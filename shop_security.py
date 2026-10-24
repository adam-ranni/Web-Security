"""Shared authentication, authorization, CSRF and input validation for the shop."""
import hashlib
import os
import re
import secrets
import time
from contextlib import closing
from datetime import timedelta
from functools import wraps
from pathlib import Path
from urllib.parse import urlsplit

import jwt
from flask import abort, current_app, g, jsonify, redirect, request, session, url_for
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash
from storage import connect, transaction

csrf=CSRFProtect()
DUMMY_PASSWORD=generate_password_hash(secrets.token_urlsafe(32))
SESSION_SECONDS=1800


def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def database():
    return connect(current_app.config['DATABASE'])


def one(sql, params=()):
    with closing(database()) as db:
        return db.execute(sql,params).fetchone()


def rows(sql, params=()):
    with closing(database()) as db:
        return db.execute(sql,params).fetchall()


def write(sql, params=()):
    with transaction(current_app.config['DATABASE']) as db:
        return db.execute(sql,params).rowcount


def secret_from_env(name):
    value=os.environ.get(name,'')
    if len(value)<32:
        raise RuntimeError(name+' must be set to an independent random secret of at least 32 characters')
    return value


def configure(app):
    directory=Path(os.environ.get('BOOKSHOP_DATA_DIR',app.instance_path)).resolve()
    https=os.environ.get('BOOKSHOP_HTTPS','0')=='1'
    app.config.update(SECRET_KEY=secret_from_env('BOOKSHOP_SECRET_KEY'),
        JWT_SECRET=secret_from_env('BOOKSHOP_JWT_SECRET'),
        DATABASE=str(directory/'shop.sqlite3'), UPLOAD_FOLDER=str(directory/'uploads'),
        RESET_OUTBOX=str(directory/'reset-outbox'),
        SESSION_COOKIE_NAME='bookshop_fixed', SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=https, SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=timedelta(seconds=SESSION_SECONDS),
        MAX_CONTENT_LENGTH=2*1024*1024, MAX_FORM_MEMORY_SIZE=256*1024,
        TRUSTED_HOSTS=os.environ.get('BOOKSHOP_TRUSTED_HOSTS','localhost,127.0.0.1').split(','))
    if secrets.compare_digest(app.secret_key,app.config['JWT_SECRET']):
        raise RuntimeError('Session and JWT secrets must be different')
    csrf.init_app(app)

    @app.before_request
    def load_identity():
        g.user=None
        if request.endpoint=='static':
            if request.path.startswith('/static/uploads/') and not request.path.endswith('/default.png'):
                abort(404)
            return
        if not Path(app.config['DATABASE']).is_file():
            abort(503,description='Initialize or migrate the fixed database using the local CLI')
        if session.get('sid'):
            user=one('SELECT users.* FROM users JOIN sessions ON users.id=sessions.user_id WHERE sessions.token_hash=? AND sessions.expires_at>? AND sessions.auth_version=users.auth_version AND users.is_active=1 AND users.password_reset_required=0',(digest(session['sid']),int(time.time())))
            if user:
                g.user=user
                session['user_id']=user['id']
                session['username']=user['username']
                session['role']=user['role']
            else:
                session.clear()
        elif session.get('user_id'):
            session.clear()

    @app.after_request
    def security_headers(response):
        response.headers['X-Content-Type-Options']='nosniff'
        response.headers['X-Frame-Options']='DENY'
        response.headers['Referrer-Policy']='no-referrer'
        response.headers['Content-Security-Policy']=("default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        response.headers['Permissions-Policy']='camera=(), microphone=(), geolocation=()'
        if request.is_secure or app.config['SESSION_COOKIE_SECURE']:
            response.headers['Strict-Transport-Security']='max-age=31536000'
        if request.endpoint!='static':
            response.headers['Cache-Control']='no-store'
        return response


def login_required(function):
    @wraps(function)
    def wrapped(*args,**kwargs):
        if not getattr(g,'user',None):
            if request.path.startswith('/api/'):
                return jsonify(error='Authentication required'),401
            return redirect(url_for('login'))
        return function(*args,**kwargs)
    return wrapped


def admin_required(function):
    @wraps(function)
    @login_required
    def wrapped(*args,**kwargs):
        if g.user['role']!='admin':
            abort(403)
        return function(*args,**kwargs)
    return wrapped


def text(value, maximum, required=True):
    if not isinstance(value,str) or len(value)>maximum or (required and not value.strip()):
        abort(400,description='Invalid text field')
    return value.strip()


def valid_password(value):
    if not isinstance(value,str) or not 12<=len(value)<=128:
        abort(400,description='Password must contain 12 to 128 characters')
    return value


def email(value):
    value=text(value,254).lower()
    if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',value):
        abort(400,description='Invalid email address')
    return value


def positive_int(value, maximum=100):
    try:
        if isinstance(value,bool) or not re.fullmatch(r'[0-9]+',str(value)):
            raise ValueError
        result=int(value)
        if not 1<=result<=maximum:
            raise ValueError
        return result
    except (ValueError,TypeError):
        abort(400,description='Invalid positive integer')


def safe_redirect(value, default='/'):
    if not isinstance(value,str) or any(ord(c)<32 for c in value) or '\\' in value:
        return default
    try:
        parsed=urlsplit(value)
    except ValueError:
        return default
    if parsed.scheme or parsed.netloc or not value.startswith('/') or value.startswith('//'):
        return default
    return value


def password_matches(user, password):
    stored=user['password'] if user else DUMMY_PASSWORD
    if not stored.startswith(('scrypt:','pbkdf2:')):
        check_password_hash(DUMMY_PASSWORD,password)
        return False
    try:
        matches=check_password_hash(stored,password)
    except ValueError:
        return False
    return matches and bool(user and user['is_active'] and not user['password_reset_required'])


def throttle_key(identity, purpose):
    return digest(purpose+':'+request.remote_addr+':'+str(identity).casefold()[:254])


def authenticate(username,password):
    if not isinstance(username,str) or not isinstance(password,str) or len(username)>64 or len(password)>128:
        abort(400)
    limit_action('login-ip',60)
    key=throttle_key(username,'login'); now=int(time.time())
    with transaction(current_app.config['DATABASE']) as db:
        info=db.execute('SELECT * FROM rate_limits WHERE key=?',(key,)).fetchone()
        if info and info['locked_until']>now:
            abort(429,description='Too many attempts')
        user=db.execute('SELECT * FROM users WHERE username=?',(username,)).fetchone()
        if password_matches(user,password):
            db.execute('DELETE FROM rate_limits WHERE key=?',(key,))
            return user
        count=info['failures']+1 if info and now-info['first_at']<300 else 1
        first=info['first_at'] if info and now-info['first_at']<300 else now
        db.execute('DELETE FROM rate_limits WHERE first_at<?',(now-600,))
        db.execute('INSERT INTO rate_limits (key,failures,first_at,locked_until) VALUES (?,?,?,?) ON CONFLICT(key) DO UPDATE SET failures=excluded.failures,first_at=excluded.first_at,locked_until=excluded.locked_until',(key,count,first,now+120 if count>=5 else 0))
    return None


def start_session(user):
    sid=secrets.token_urlsafe(32)
    session.clear()
    session.permanent=True
    session.update(sid=sid,user_id=user['id'],username=user['username'],role=user['role'])
    write('DELETE FROM sessions WHERE expires_at<=?',(int(time.time()),))
    write('INSERT INTO sessions (token_hash,user_id,auth_version,expires_at) VALUES (?,?,?,?)',(digest(sid),user['id'],user['auth_version'],int(time.time())+SESSION_SECONDS))


def end_session():
    if session.get('sid'):
        write('DELETE FROM sessions WHERE token_hash=?',(digest(session['sid']),))
    session.clear()


def current_password():
    if not password_matches(g.user,request.form.get('current_password','')):
        abort(403,description='Current password required')


def token_identity():
    auth=request.headers.get('Authorization','')
    if not auth.startswith('Bearer '):
        abort(401)
    try:
        claims=jwt.decode(auth[7:],current_app.config['JWT_SECRET'],algorithms=['HS256'],issuer='dv-bookshop-fixed',audience='dv-bookshop-api',options={'require':['exp','iat','sub','ver','iss','aud']})
        user=one('SELECT * FROM users WHERE id=? AND is_active=1 AND password_reset_required=0',(positive_int(claims['sub'],2**31-1),))
        if not user or claims['ver']!=user['auth_version']:
            abort(401)
        return user
    except jwt.InvalidTokenError:
        abort(401)


def limit_action(purpose, limit=5):
    key=throttle_key('',purpose); now=int(time.time())
    with transaction(current_app.config['DATABASE']) as db:
        info=db.execute('SELECT * FROM rate_limits WHERE key=?',(key,)).fetchone()
        count=info['failures']+1 if info and now-info['first_at']<300 else 1
        first=info['first_at'] if info and now-info['first_at']<300 else now
        if count>limit:
            abort(429)
        db.execute('INSERT INTO rate_limits (key,failures,first_at) VALUES (?,?,?) ON CONFLICT(key) DO UPDATE SET failures=excluded.failures,first_at=excluded.first_at',(key,count,first))
