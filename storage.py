"""Explicit initialization and copy-only migration to a transactional shop database."""
import sqlite3
import os
import secrets
from contextlib import closing, contextmanager
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path
from werkzeug.security import generate_password_hash

SCHEMA = """
CREATE TABLE users (
 id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, email TEXT NOT NULL UNIQUE,
 password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','moderator','admin')),
 credit_card_number TEXT DEFAULT '', credit_card_expiry TEXT DEFAULT '',
 balance_cents INTEGER NOT NULL DEFAULT 100000 CHECK(balance_cents>=0),
 balance REAL GENERATED ALWAYS AS (balance_cents/100.0) VIRTUAL,
 secret_note TEXT DEFAULT '', profile_pic TEXT NOT NULL DEFAULT 'default.png', bio TEXT DEFAULT '',
 reset_token TEXT UNIQUE, reset_token_expiry INTEGER, auth_version INTEGER NOT NULL DEFAULT 0,
 password_reset_required INTEGER NOT NULL DEFAULT 0 CHECK(password_reset_required IN (0,1)),
 is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1)), created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE books (
 id INTEGER PRIMARY KEY, title TEXT NOT NULL, author TEXT NOT NULL,
 price_cents INTEGER NOT NULL CHECK(price_cents>=0), price REAL GENERATED ALWAYS AS (price_cents/100.0) VIRTUAL,
 image TEXT DEFAULT 'book1.jpg', description TEXT DEFAULT '', category TEXT DEFAULT 'General', stock INTEGER NOT NULL DEFAULT 100 CHECK(stock>=0));
CREATE TABLE cart (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), book_id INTEGER NOT NULL REFERENCES books(id), quantity INTEGER NOT NULL CHECK(quantity BETWEEN 1 AND 100), UNIQUE(user_id,book_id));
CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), total_cents INTEGER NOT NULL CHECK(total_cents>=0), total REAL GENERATED ALWAYS AS (total_cents/100.0) VIRTUAL, status TEXT DEFAULT 'confirmed', shipping_address TEXT DEFAULT '', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE order_items (id INTEGER PRIMARY KEY, order_id INTEGER NOT NULL REFERENCES orders(id), book_id INTEGER NOT NULL REFERENCES books(id), quantity INTEGER NOT NULL CHECK(quantity BETWEEN 1 AND 100), price_cents INTEGER NOT NULL CHECK(price_cents>=0), price REAL GENERATED ALWAYS AS (price_cents/100.0) VIRTUAL);
CREATE TABLE reviews (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), book_id INTEGER NOT NULL REFERENCES books(id), rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5), comment TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE coupons (id INTEGER PRIMARY KEY, code TEXT UNIQUE NOT NULL, discount_percent REAL NOT NULL CHECK(discount_percent BETWEEN 0 AND 100), is_active INTEGER DEFAULT 1, max_uses INTEGER NOT NULL CHECK(max_uses>=0), current_uses INTEGER NOT NULL DEFAULT 0 CHECK(current_uses>=0 AND current_uses<=max_uses));
CREATE TABLE support_tickets (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), subject TEXT NOT NULL, message TEXT NOT NULL, status TEXT DEFAULT 'open', admin_reply TEXT DEFAULT '', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE uploaded_files (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), filename TEXT NOT NULL, original_filename TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE admin_logs (id INTEGER PRIMARY KEY, admin_id INTEGER NOT NULL REFERENCES users(id), action TEXT NOT NULL, target_user_id INTEGER, details TEXT DEFAULT '', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE sessions (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), auth_version INTEGER NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE rate_limits (key TEXT PRIMARY KEY, failures INTEGER NOT NULL, first_at INTEGER NOT NULL, locked_until INTEGER NOT NULL DEFAULT 0);
CREATE TABLE race_accounts (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, balance_cents INTEGER NOT NULL CHECK(balance_cents>=0), balance REAL GENERATED ALWAYS AS (balance_cents/100.0) VIRTUAL);
CREATE TABLE race_transfers (id INTEGER PRIMARY KEY, sender TEXT NOT NULL, recipient TEXT NOT NULL, amount_cents INTEGER NOT NULL CHECK(amount_cents>0), amount REAL GENERATED ALWAYS AS (amount_cents/100.0) VIRTUAL, mode TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
PRAGMA user_version=1;
"""

def cents(value):
    try:
        amount=Decimal(str(value))
        if not amount.is_finite() or amount<0 or amount>Decimal('10000000'):
            raise ValueError('Amount out of range')
        return int((amount*100).quantize(Decimal('1'), rounding=ROUND_HALF_UP))
    except (InvalidOperation, TypeError) as exc:
        raise ValueError('Invalid amount') from exc


def connect(path):
    db=sqlite3.connect(Path(path).resolve().as_uri()+'?mode=rw',uri=True,timeout=10)
    db.row_factory=sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    return db


@contextmanager
def transaction(path):
    with closing(connect(path)) as db:
        try:
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise


def mask_card(number):
    digits=''.join(c for c in str(number or '') if c.isdigit())
    return '****'+digits[-4:] if len(digits)>=4 else ''


def initialize(path, admin_password, books, coupons):
    target=Path(path).resolve()
    if target.exists():
        raise ValueError('Database already exists; use a new output path')
    if not 12<=len(admin_password)<=128:
        raise ValueError('Admin password must contain 12 to 128 characters')
    target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    descriptor=os.open(target,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    os.close(descriptor)
    with closing(sqlite3.connect(target)) as db:
        db.executescript(SCHEMA)
        db.execute('INSERT INTO users (username,email,password,role) VALUES (?,?,?,?)',('admin','admin@example.invalid',generate_password_hash(admin_password),'admin'))
        db.executemany('INSERT INTO books (title,author,price_cents,image,description,category,stock) VALUES (?,?,?,?,?,?,?)',[(b[0],b[1],cents(b[2]),*b[3:]) for b in books])
        db.executemany('INSERT INTO coupons (code,discount_percent,is_active,max_uses,current_uses) VALUES (?,?,?,?,?)',coupons)
        db.executemany('INSERT INTO race_accounts (username,balance_cents) VALUES (?,?)',[('alice_hacker',10000),('bob_secure',0)])
        db.commit()


def migrate(users_path, shop_path, output):
    """Read legacy DBs only; never update an input or overwrite an output."""
    output=Path(output).resolve()
    sources=[Path(p).resolve(strict=True) for p in (users_path,shop_path)]
    if output in sources or output.exists():
        raise ValueError('Output must be a new database, separate from both inputs')
    temporary=output.with_name(output.name+'.migrating-'+secrets.token_hex(8))
    output.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    descriptor=os.open(temporary,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    os.close(descriptor)
    try:
        with closing(sqlite3.connect(temporary)) as dest:
            dest.executescript(SCHEMA)
            dest.execute('PRAGMA foreign_keys=ON')
            with closing(sqlite3.connect(sources[0].as_uri()+'?mode=ro',uri=True)) as source:
                source.row_factory=sqlite3.Row
                for row in source.execute('SELECT * FROM users'):
                    d=dict(row); stored=d['password']
                    password=stored if stored.startswith(('scrypt:','pbkdf2:')) else generate_password_hash(stored)
                    dest.execute('INSERT INTO users (id,username,email,password,role,credit_card_number,credit_card_expiry,balance_cents,secret_note,bio,is_active,created_at,password_reset_required) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1)',(d['id'],d['username'],d['email'].lower(),password,d['role'],mask_card(d['credit_card_number']),d['credit_card_expiry'],cents(d['balance']),d['secret_note'],d['bio'],d['is_active'],d['created_at']))
            with closing(sqlite3.connect(sources[1].as_uri()+'?mode=ro',uri=True)) as source:
                source.row_factory=sqlite3.Row
                for table in ('books','cart','orders','order_items','reviews','coupons','support_tickets','uploaded_files','admin_logs'):
                    rows=[dict(r) for r in source.execute('SELECT * FROM '+table)]
                    for d in rows:
                        if table in ('books','order_items'): d['price_cents']=cents(d.pop('price'))
                        if table=='orders': d['total_cents']=cents(d.pop('total'))
                        if table=='uploaded_files':
                            # Legacy files are not trusted or served in the fixed app.
                            continue
                        columns=list(d)
                        sql='INSERT INTO '+table+' ('+','.join(columns)+') VALUES ('+','.join('?' for _ in columns)+')'
                        dest.execute(sql,list(d.values()))
            dest.executemany('INSERT INTO race_accounts (username,balance_cents) VALUES (?,?)',[('alice_hacker',10000),('bob_secure',0)])
            if dest.execute('PRAGMA foreign_key_check').fetchone():
                raise ValueError('Legacy data contains orphan references')
            dest.commit()
        os.link(temporary,output)
        temporary.unlink()
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
