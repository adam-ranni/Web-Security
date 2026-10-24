"""Regression tests use disposable databases; no running service is contacted."""
import hashlib
import io
import json
import os
import secrets
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ['BOOKSHOP_SECRET_KEY']=secrets.token_urlsafe(48)
os.environ['BOOKSHOP_JWT_SECRET']=secrets.token_urlsafe(48)
import app as shop
from catalog_seed import BOOKS, COUPONS
from storage import initialize, connect, migrate


class ShopTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory=Path(self.temp.name)
        self.db=self.directory/'shop.sqlite3'
        self.password=secrets.token_urlsafe(16)
        initialize(self.db,self.password,BOOKS,COUPONS)
        shop.app.config.update(TESTING=True,DATABASE=str(self.db),UPLOAD_FOLDER=str(self.directory/'uploads'),RESET_OUTBOX=str(self.directory/'outbox'))
        self.a=shop.app.test_client();self.b=shop.app.test_client()

    def sql(self,sql,params=()):
        db=connect(self.db)
        try:
            result=[dict(x) for x in db.execute(sql,params)]
            db.commit()
            return result
        finally:
            db.close()

    def token(self,client):
        response=client.get('/api/csrf')
        self.assertEqual(response.status_code,200)
        return response.json['csrf_token']

    def post(self,client,url,data=None,**kwargs):
        token=self.token(client)
        headers=kwargs.pop('headers',{})
        headers['X-CSRFToken']=token
        return client.post(url,data=data,headers=headers,**kwargs)

    def register(self,client,name):
        response=self.post(client,'/register',dict(username=name,email=name+'@example.invalid',password=self.password,confirm_password=self.password))
        self.assertEqual(response.status_code,302)
        return self.sql('SELECT id FROM users WHERE username=?',(name,))[0]['id']

    def login(self,client,name='admin'):
        response=self.post(client,'/login',dict(username=name,password=self.password))
        self.assertEqual(response.status_code,302)

    def test_auth_csrf_and_session_revocation(self):
        self.assertEqual(self.a.post('/login',data={'username':'admin','password':self.password}).status_code,400)
        self.login(self.a)
        self.assertEqual(self.a.get('/admin').status_code,200)
        self.assertEqual(self.a.get('/logout').status_code,405)
        with self.a.session_transaction() as state: previous=state['sid']
        self.post(self.a,'/logout')
        self.assertFalse(self.sql('SELECT * FROM sessions WHERE token_hash=?',(hashlib.sha256(previous.encode()).hexdigest(),)))
        self.assertEqual(self.a.get('/admin').status_code,302)

    def test_registration_owner_and_live_roles(self):
        aid=self.register(self.a,'qa_alice');self.register(self.b,'qa_bob')
        self.assertEqual(self.b.get('/profile?user_id='+str(aid)).status_code,403)
        self.assertEqual(self.b.get('/api/user/'+str(aid)+'/card').status_code,403)
        self.assertEqual(self.post(self.a,'/api/update_role',dict(user_id=aid,role='admin')).status_code,403)
        self.assertTrue(self.sql('SELECT password FROM users WHERE id=?',(aid,))[0]['password'].startswith('scrypt:'))
        self.sql('UPDATE users SET is_active=0 WHERE id=?',(aid,))
        self.assertEqual(self.a.get('/profile').status_code,302)

    def test_reset_is_private_expiring_and_single_use(self):
        self.register(self.a,'qa_alice')
        response=self.post(self.b,'/forgot_password',dict(username='qa_alice'))
        self.assertNotIn(b'/reset_password/',response.data)
        aid=self.sql('SELECT id FROM users WHERE username=?',('qa_alice',))[0]['id']
        link=(self.directory/'outbox'/str(aid)).read_text()
        self.assertNotIn(link.rsplit('/',1)[1],json.dumps(self.sql('SELECT reset_token FROM users WHERE id=?',(aid,))))
        self.assertEqual(self.post(self.b,link,dict(password=self.password,confirm_password=self.password)).status_code,302)
        self.assertEqual(self.b.get(link).status_code,400)
        self.assertEqual(self.a.get('/profile').status_code,302)

    def test_migration_preserves_sources(self):
        source=Path(__file__).resolve().parents[1]
        files=[source/'users.db',source/'bookshop.db']
        before=[hashlib.sha256(p.read_bytes()).digest() for p in files]
        destination=self.directory/'migrated.sqlite3'
        migrate(*files,destination)
        db=connect(destination)
        try:
            self.assertGreater(db.execute('SELECT COUNT(*) FROM users').fetchone()[0],0)
            self.assertTrue(all(r[0].startswith(('scrypt:','pbkdf2:')) for r in db.execute('SELECT password FROM users')))
            self.assertFalse(db.execute('PRAGMA foreign_key_check').fetchall())
        finally: db.close()
        self.assertEqual(before,[hashlib.sha256(p.read_bytes()).digest() for p in files])
        with self.assertRaises(ValueError): migrate(*files,destination)

    def test_sql_queries_and_escaped_output(self):
        self.assertEqual(self.a.get('/book_details?id=1%20OR%201=1').status_code,400)
        response=self.post(self.a,'/login',dict(username="admin' OR '1'='1",password='unrelated-password'))
        self.assertEqual(response.status_code,200)
        self.assertEqual(self.a.get('/profile').status_code,302)
        payload='<img src=x onerror=alert(1)>'
        for path in ['/search','/books']:
            response=self.a.get(path,query_string={'q':payload} if path.startswith('/search') else {'search':payload})
            self.assertNotIn(payload.encode(),response.data)
            self.assertIn(b'&lt;img',response.data)
        self.assertFalse(self.a.get('/api/check_username',query_string={'username':"admin' OR '1'='1"}).json['exists'])
        self.assertFalse(self.a.get('/api/check_coupon',query_string={'code':"x' OR '1'='1"}).json['valid'])
        self.register(self.a,'qa_alice')
        self.post(self.a,'/review/1',dict(rating=4,comment=payload))
        response=self.a.get('/book_details?id=1')
        self.assertNotIn(payload.encode(),response.data)
        self.assertIn(b'&lt;img',response.data)

    def test_order_review_ownership_and_json_cart(self):
        aid=self.register(self.a,'qa_alice');self.register(self.b,'qa_bob')
        self.sql('INSERT INTO orders (user_id,total_cents) VALUES (?,?)',(aid,2999))
        oid=self.sql('SELECT id FROM orders')[0]['id']
        self.assertEqual(self.b.get('/order/'+str(oid)).status_code,404)
        self.assertEqual(self.b.get('/download_receipt/'+str(oid)).status_code,404)
        self.assertEqual(self.a.get('/download_receipt/'+str(oid)).status_code,200)
        self.post(self.a,'/review/1',dict(rating=4,comment='Normal review'))
        rid=self.sql('SELECT id FROM reviews')[0]['id']
        for prefix in ['/edit_review/','/delete_review/']:
            self.assertEqual(self.post(self.b,prefix+str(rid),dict(rating=1,comment='Other')).status_code,404)
        self.assertEqual(self.post(self.a,'/api/load_cart',json=[dict(book_id=1,quantity=2)]).status_code,200)
        self.assertEqual(self.sql('SELECT quantity FROM cart WHERE user_id=?',(aid,))[0]['quantity'],2)
        self.assertEqual(self.post(self.a,'/api/load_cart',dict(cart_data='gASVpickleFixture')).status_code,400)
        self.assertEqual(self.post(self.a,'/api/load_cart',json=[dict(book_id=1,quantity=-2)]).status_code,400)
        self.assertEqual(self.sql('SELECT quantity FROM cart WHERE user_id=?',(aid,))[0]['quantity'],2)

    def test_redirect_and_jwt_validation(self):
        for value in ['https://example.invalid','//example.invalid','/\\example.invalid','http://[']:
            response=self.a.get('/redirect',query_string={'url':value})
            self.assertEqual(response.status_code,302)
            self.assertEqual(response.headers['Location'],'/')
        self.register(self.a,'qa_alice')
        response=self.post(self.a,'/api/jwt/login',json=dict(username='qa_alice',password=self.password))
        self.assertEqual(response.status_code,200)
        token=response.json['token']
        headers={'Authorization':'Bearer '+token}
        self.assertEqual(self.a.get('/api/jwt/me',headers=headers).status_code,200)
        self.assertEqual(self.a.get('/api/jwt/admin',headers=headers).status_code,403)
        import jwt
        claims=jwt.decode(token,shop.app.config['JWT_SECRET'],algorithms=['HS256'],audience='dv-bookshop-api')
        unsigned=jwt.encode(claims,key='',algorithm='none')
        self.assertEqual(self.a.get('/api/jwt/me',headers={'Authorization':'Bearer '+unsigned}).status_code,401)
        claims['exp']=int(time.time())-1
        expired=jwt.encode(claims,shop.app.config['JWT_SECRET'],algorithm='HS256')
        self.assertEqual(self.a.get('/api/jwt/me',headers={'Authorization':'Bearer '+expired}).status_code,401)
        self.sql('UPDATE users SET auth_version=auth_version+1 WHERE username=?',('qa_alice',))
        self.assertEqual(self.a.get('/api/jwt/me',headers=headers).status_code,401)

    def test_avatar_content_and_private_delivery(self):
        from PIL import Image
        aid=self.register(self.a,'qa_alice');self.register(self.b,'qa_bob')
        image=io.BytesIO();Image.new('RGB',(2,2)).save(image,format='PNG');image.seek(0)
        response=self.post(self.a,'/upload_avatar',{'avatar':(image,'../../avatar.png')})
        self.assertEqual(response.status_code,302)
        filename=self.sql('SELECT profile_pic FROM users WHERE id=?',(aid,))[0]['profile_pic']
        self.assertRegex(filename,r'^[0-9a-f]{32}\.png$')
        response=self.a.get('/media/'+filename)
        self.assertEqual(response.status_code,200);response.close()
        self.assertEqual(self.b.get('/media/'+filename).status_code,404)
        self.assertEqual(self.a.get('/static/uploads/'+filename).status_code,404)
        self.assertEqual(self.post(self.a,'/upload_avatar',{'avatar':(io.BytesIO(b'not an image'),'wrong.png')}).status_code,400)
        self.assertEqual(len(self.sql('SELECT * FROM uploaded_files')),1)

    def test_xml_import_and_csv(self):
        self.login(self.a)
        xml=b'<books><book><title>Normal import</title><author>Author</author><price>12.34</price></book></books>'
        response=self.post(self.a,'/api/import_books',data=xml,content_type='application/xml')
        self.assertEqual(response.status_code,200)
        self.assertEqual(self.sql('SELECT price_cents FROM books WHERE title=?',('Normal import',))[0]['price_cents'],1234)
        entity=b'<!DOCTYPE books [<!ENTITY x SYSTEM "file:///never-read">]><books><book><title>&x;</title></book></books>'
        self.assertEqual(self.post(self.a,'/api/import_books',data=entity,content_type='application/xml').status_code,400)
        invalid=b'<books><book><title>Partial</title><author>A</author><price>1</price></book><book><price>NaN</price></book></books>'
        self.assertEqual(self.post(self.a,'/api/import_books',data=invalid,content_type='application/xml').status_code,400)
        self.assertFalse(self.sql('SELECT id FROM books WHERE title=?',('Partial',)))
        self.sql('INSERT INTO books (title,author,price_cents) VALUES (?,?,?)',('=1+1','Comma, author',100))
        response=self.a.get('/admin/export?format=csv')
        import csv
        exported=list(csv.DictReader(io.StringIO(response.get_data(as_text=True))))
        self.assertEqual(exported[-1]['title'],"'=1+1")
        self.assertEqual(exported[-1]['author'],'Comma, author')
        self.assertEqual(self.a.get('/admin/export?format=other').status_code,400)

    def test_network_boundaries_with_mocks(self):
        import file_network
        from unittest.mock import Mock
        with patch('file_network.subprocess.run') as run,patch('file_network.shutil.which',return_value='/trusted/ping'):
            run.return_value.stdout='two replies'
            with self.assertRaises(ValueError): file_network.ping_host('127.0.0.1; arbitrary')
            run.assert_not_called()
            self.assertEqual(file_network.ping_host('127.0.0.1'),'two replies')
            self.assertIsInstance(run.call_args.args[0],list)
            self.assertFalse(run.call_args.kwargs.get('shell',False))
        with patch.dict(os.environ,{'BOOKSHOP_PREVIEW_HOSTS':'allowed.example'}),patch('file_network.socket.getaddrinfo') as dns,patch('file_network.PinnedHTTPSConnection') as transport:
            dns.return_value=[(2,1,6,'',('127.0.0.1',443))]
            with self.assertRaises(ValueError): file_network.preview_url('https://allowed.example/')
            transport.assert_not_called()
            for url in ['http://allowed.example/','https://other.example/','https://user:pass@allowed.example/','https://allowed.example:444/']:
                with self.assertRaises(ValueError): file_network.preview_url(url)
            dns.return_value=[(2,1,6,'',('93.184.216.34',443))]
            response=Mock(status=200);response.getheader.return_value='text/plain';response.read.return_value=b'Normal preview'
            transport.return_value.getresponse.return_value=response
            self.assertEqual(file_network.preview_url('https://allowed.example/'),'Normal preview')
            transport.assert_called_with('allowed.example','93.184.216.34')
            response.status=302
            with self.assertRaises(ValueError): file_network.preview_url('https://allowed.example/')

    def test_purchase_uses_server_price_and_coupon(self):
        aid=self.register(self.a,'qa_alice')
        self.assertEqual(self.post(self.a,'/add_to_cart/1',dict(quantity=2)).status_code,302)
        self.assertEqual(self.post(self.a,'/apply_coupon',dict(code='HACK10')).status_code,302)
        self.assertEqual(self.a.get('/checkout').status_code,200)
        response=self.post(self.a,'/checkout',dict(total='0.01',shipping_address='Test classroom'))
        self.assertEqual(response.status_code,302)
        order=self.sql('SELECT * FROM orders')[0]
        self.assertEqual(order['total_cents'],5398)
        self.assertEqual(self.sql('SELECT balance_cents FROM users WHERE id=?',(aid,))[0]['balance_cents'],94602)
        self.assertEqual(self.sql('SELECT stock FROM books WHERE id=1')[0]['stock'],48)
        self.assertEqual(self.sql('SELECT current_uses FROM coupons WHERE code=?',('HACK10',))[0]['current_uses'],1)
        self.assertFalse(self.sql('SELECT * FROM cart'))
        receipt=self.a.get('/download_receipt/'+str(order['id']))
        self.assertIn(b'$53.98',receipt.data)
        self.assertIn(('/order/'+str(order['id'])).encode(),self.a.get('/order_history').data)
        self.assertEqual(self.post(self.a,'/checkout',dict(shipping_address='Repeat')).status_code,409)
        self.assertEqual(len(self.sql('SELECT * FROM orders')),1)

    def test_checkout_rolls_back_all_writes(self):
        aid=self.register(self.a,'qa_alice')
        self.post(self.a,'/add_to_cart/1',dict(quantity=1))
        self.sql("CREATE TRIGGER reject_order BEFORE INSERT ON orders BEGIN SELECT RAISE(ABORT,'fixture'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.post(self.a,'/checkout',dict(shipping_address='Test classroom'))
        self.assertEqual(self.sql('SELECT balance_cents FROM users WHERE id=?',(aid,))[0]['balance_cents'],100000)
        self.assertEqual(self.sql('SELECT stock FROM books WHERE id=1')[0]['stock'],50)
        self.assertEqual(len(self.sql('SELECT * FROM cart')),1)
        self.assertFalse(self.sql('SELECT * FROM orders'))

    def test_quantities_balances_and_coupon_exhaustion(self):
        aid=self.register(self.a,'qa_alice');self.register(self.b,'qa_bob')
        for value in ['-1','0','101','1.5','NaN']:
            self.assertEqual(self.post(self.a,'/add_to_cart/1',dict(quantity=value)).status_code,400)
        for value in ['NaN','inf','-1','0','1.001']:
            self.assertEqual(self.post(self.a,'/transfer',dict(recipient='qa_bob',amount=value)).status_code,409)
        self.assertEqual(self.post(self.a,'/transfer',dict(recipient='qa_bob',amount='25.01')).status_code,302)
        self.assertEqual(self.sql('SELECT balance_cents FROM users WHERE id=?',(aid,))[0]['balance_cents'],97499)
        self.assertEqual(sum(row['balance_cents'] for row in self.sql('SELECT balance_cents FROM users WHERE username IN (?,?)',('qa_alice','qa_bob'))),200000)
        self.sql('UPDATE coupons SET max_uses=1 WHERE code=?',('HACK10',))
        for client in [self.a,self.b]:
            self.post(client,'/add_to_cart/1',dict(quantity=1));self.post(client,'/apply_coupon',dict(code='HACK10'))
        self.assertEqual(self.post(self.a,'/checkout',dict(shipping_address='Test')).status_code,302)
        self.assertEqual(self.post(self.b,'/checkout',dict(shipping_address='Test')).status_code,409)
        self.assertEqual(len(self.sql('SELECT * FROM orders')),1)
        self.assertEqual(self.sql('SELECT current_uses FROM coupons WHERE code=?',('HACK10',))[0]['current_uses'],1)

    def test_parallel_checkout_creates_one_order(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier
        aid=self.register(self.a,'qa_alice')
        self.post(self.a,'/add_to_cart/1',dict(quantity=1))
        barrier=Barrier(2)
        def checkout(_):
            client=shop.app.test_client();self.login(client,'qa_alice');token=self.token(client)
            barrier.wait(timeout=10)
            return client.post('/checkout',data=dict(shipping_address='Concurrent test'),headers={'X-CSRFToken':token}).status_code
        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses=list(pool.map(checkout,range(2)))
        self.assertEqual(sorted(statuses),[302,409])
        self.assertEqual(len(self.sql('SELECT * FROM orders')),1)
        self.assertEqual(self.sql('SELECT balance_cents FROM users WHERE id=?',(aid,))[0]['balance_cents'],97001)

    def test_old_lab_paths_cannot_restore_vulnerable_transactions(self):
        self.register(self.a,'alice_hacker')
        endpoint='/api/race-lab/transfer/vulnerable'
        self.assertEqual(self.post(self.a,endpoint,json=dict(recipient='bob_secure',amount='75')).status_code,200)
        self.assertEqual(self.post(self.a,endpoint,json=dict(recipient='bob_secure',amount='75')).status_code,409)
        self.assertEqual(self.sql('SELECT balance_cents FROM race_accounts WHERE username=?',('alice_hacker',))[0]['balance_cents'],2500)
        self.assertEqual(self.post(self.a,'/lab',dict(secure='')).status_code,405)


if __name__=='__main__': unittest.main()
