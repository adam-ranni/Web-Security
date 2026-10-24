"""Bounded image/XML handling and allowlisted, DNS-pinned network diagnostics."""
import io
import ipaddress
import os
import secrets
import shutil
import socket
import ssl
import subprocess
import warnings
from http.client import HTTPSConnection
from pathlib import Path
from urllib.parse import urlsplit

from defusedxml import ElementTree
from PIL import Image, UnidentifiedImageError
from werkzeug.utils import secure_filename

MAX_IMAGE_BYTES=1000000
MAX_PREVIEW_BYTES=65536


def store_avatar(upload, directory):
    data=upload.read(MAX_IMAGE_BYTES+1)
    if len(data)>MAX_IMAGE_BYTES:
        raise ValueError('Image is too large')
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error',Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as image:
                if image.format not in {'PNG','JPEG'} or image.width>2048 or image.height>2048 or getattr(image,'is_animated',False):
                    raise ValueError('Use a static PNG or JPEG up to 2048 pixels')
                image.verify()
            with Image.open(io.BytesIO(data)) as image:
                image.thumbnail((256,256))
                clean=image.convert('RGB')
                encoded=io.BytesIO(); clean.save(encoded,format='PNG')
    except (UnidentifiedImageError,OSError,Image.DecompressionBombError,Image.DecompressionBombWarning) as exc:
        raise ValueError('Invalid image') from exc
    directory=Path(directory); directory.mkdir(parents=True,exist_ok=True,mode=0o700)
    filename=secrets.token_hex(16)+'.png'
    path=directory/filename
    descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(descriptor,'wb') as output:
        output.write(encoded.getvalue())
    return filename,secure_filename(upload.filename or 'image')[:100]


def parse_books(data):
    if not data or len(data)>1000000:
        raise ValueError('XML is empty or too large')
    root=ElementTree.fromstring(data,forbid_dtd=True,forbid_entities=True,forbid_external=True)
    if root.tag!='books' or len(root)>200:
        raise ValueError('Expected at most 200 books')
    return list(root)


def ping_host(host):
    address=str(ipaddress.ip_address(host))
    allowed={str(ipaddress.ip_address(value.strip())) for value in os.environ.get('BOOKSHOP_PING_HOSTS','127.0.0.1,::1').split(',') if value.strip()}
    if address not in allowed:
        raise ValueError('Host is not allowed')
    executable=shutil.which('ping')
    if not executable:
        raise ValueError('Ping is not installed')
    arguments=[executable,'-n','2','-w','1000',address] if os.name=='nt' else [executable,'-c','2','-W','1',address]
    try:
        result=subprocess.run(arguments,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=5,check=False,text=True,encoding='utf-8',errors='replace')
    except subprocess.TimeoutExpired as exc:
        raise ValueError('Ping timed out') from exc
    return result.stdout[:5000]


class PinnedHTTPSConnection(HTTPSConnection):
    def __init__(self,hostname,address):
        super().__init__(hostname,port=443,timeout=3,context=ssl.create_default_context())
        self.address=address

    def connect(self):
        # Connect to the validated address, while retaining certificate/hostname checks.
        connection=socket.create_connection((self.address,443),self.timeout)
        try:
            self.sock=self._context.wrap_socket(connection,server_hostname=self.host)
        except BaseException:
            connection.close()
            raise


def preview_url(value):
    if any(ord(character)<32 for character in value) or '\\' in value:
        raise ValueError('Invalid URL')
    parsed=urlsplit(value)
    host=parsed.hostname
    if parsed.scheme!='https' or not host or parsed.username or parsed.password or parsed.fragment or parsed.port not in (None,443):
        raise ValueError('Only HTTPS URLs on port 443 are supported')
    host=host.encode('idna').decode('ascii').lower()
    allowed={name.strip().lower() for name in os.environ.get('BOOKSHOP_PREVIEW_HOSTS','').split(',') if name.strip()}
    if host not in allowed:
        raise ValueError('Host is not in BOOKSHOP_PREVIEW_HOSTS')
    addresses={info[4][0] for info in socket.getaddrinfo(host,443,type=socket.SOCK_STREAM)}
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ValueError('Only public destination addresses are permitted')
    connection=PinnedHTTPSConnection(host,sorted(addresses)[0])
    try:
        target=parsed.path or '/'
        if parsed.query:
            target+='?'+parsed.query
        connection.request('GET',target,headers={'Host':host,'Accept':'text/plain,text/html','User-Agent':'DV-Bookshop-fixed-preview'})
        response=connection.getresponse()
        if response.status!=200:
            raise ValueError('Preview requires HTTP 200; redirects are not followed')
        media=response.getheader('Content-Type','').split(';')[0].strip()
        if media not in {'text/plain','text/html'}:
            raise ValueError('Only text previews are supported')
        data=response.read(MAX_PREVIEW_BYTES+1)
        if len(data)>MAX_PREVIEW_BYTES:
            raise ValueError('Preview is too large')
        return data.decode('utf-8',errors='replace')
    finally:
        connection.close()
