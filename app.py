"""Fixed DV Bookshop. Initialize or migrate data explicitly before serving."""
import csv
import io
import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import closing
from pathlib import Path

import click
import jwt
from flask import send_from_directory, Flask, abort, flash, g, jsonify, make_response, redirect, render_template, request, session, url_for
from flask_wtf.csrf import CSRFError, generate_csrf
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash

from catalog_seed import BOOKS, COUPONS
from commerce import purchase, quote_cart, transfer, transfer_cents
from file_network import parse_books, ping_host, preview_url, store_avatar
from defusedxml.common import DefusedXmlException
from xml.etree.ElementTree import ParseError
from storage import cents, initialize, mask_card, migrate, transaction
from shop_security import (admin_required, authenticate, configure, current_password,
    database, digest, email, end_session, login_required, one, positive_int,
    rows, limit_action, safe_redirect, start_session, text, token_identity, valid_password, write)

app=Flask(__name__)
configure(app)


def get_user_db():
    return database()


def get_shop_db():
    return database()


def get_race_db():
    return database()


def is_secure(_identifier):
    return True


def get_cart_count():
    if not getattr(g,'user',None):
        return 0
    return one('SELECT COALESCE(SUM(quantity),0) AS n FROM cart WHERE user_id=?',(g.user['id'],))['n']


@app.context_processor
def inject_cart_count():
    return dict(cart_count=get_cart_count(),is_secure=is_secure)


def log_admin_action(admin_id,action,target_user_id=None,details=''):
    write('INSERT INTO admin_logs (admin_id,action,target_user_id,details) VALUES (?,?,?,?)',(admin_id,action,target_user_id,details))


def owned_order(order_id):
    order=one('SELECT * FROM orders WHERE id=?',(order_id,))
    if not order or (order['user_id']!=g.user['id'] and g.user['role']!='admin'):
        abort(404)
    return order


def owned_review(review_id):
    review=one('SELECT * FROM reviews WHERE id=?',(review_id,))
    if not review or (review['user_id']!=g.user['id'] and g.user['role']!='admin'):
        abort(404)
    return review


@app.cli.command('init-db')
@click.password_option(confirmation_prompt=True)
def init_db_command(password):
    """Create a NEW fixed database with a user-supplied administrator password."""
    initialize(app.config['DATABASE'],password,BOOKS,COUPONS)
    click.echo('Initialized fixed database')


@app.cli.command('migrate-data')
@click.option('--users',required=True,type=click.Path(exists=True,dir_okay=False))
@click.option('--shop',required=True,type=click.Path(exists=True,dir_okay=False))
@click.option('--output',required=True,type=click.Path(dir_okay=False))
def migrate_command(users,shop,output):
    """Copy legacy data into a NEW fixed database; inputs remain unchanged."""
    migrate(users,shop,output)
    click.echo('Migration complete. Review the new database before selecting its data directory.')


@app.cli.command('reset-link')
@click.argument('username')
def reset_link_command(username):
    """Read a pending link locally, for handoff to its verified owner only."""
    user=one('SELECT id FROM users WHERE username=?',(username,))
    if not user:
        raise click.ClickException('No pending reset')
    path=Path(app.config['RESET_OUTBOX'])/str(user['id'])
    if not path.is_file():
        raise click.ClickException('No pending reset')
    click.echo(path.read_text(encoding='utf-8'))


@app.cli.command('set-password')
@click.argument('username')
@click.password_option(confirmation_prompt=True)
def set_password_command(username,password):
    """Locally verify the owner, then activate a migrated account with a NEW password."""
    valid_password_value=password
    if not 12<=len(valid_password_value)<=128:
        raise click.ClickException('Password must contain 12 to 128 characters')
    with transaction(app.config['DATABASE']) as db:
        user=db.execute('SELECT id FROM users WHERE username=?',(username,)).fetchone()
        if not user:
            raise click.ClickException('Account not found')
        db.execute('UPDATE users SET password=?,password_reset_required=0,reset_token=NULL,reset_token_expiry=NULL,auth_version=auth_version+1 WHERE id=?',(generate_password_hash(valid_password_value),user['id']))
        db.execute('DELETE FROM sessions WHERE user_id=?',(user['id'],))
    (Path(app.config['RESET_OUTBOX'])/str(user['id'])).unlink(missing_ok=True)
    click.echo('Password changed; existing sessions and tokens revoked')


@app.get('/api/csrf')
def csrf_token_api():
    return jsonify(csrf_token=generate_csrf())


@app.errorhandler(HTTPException)
def http_error(error):
    message=error.description if error.code in (400,409,413,429,503) else error.name
    if request.path.startswith('/api/'):
        return jsonify(error=message),error.code
    return render_template('error.html',error_code=error.code,error_message=message),error.code


@app.errorhandler(CSRFError)
def csrf_error(_error):
    return jsonify(error='CSRF token missing, expired or invalid'),400


@app.errorhandler(500)
def server_error(_error):
    return render_template('error.html',error_code=500,error_message='Internal server error'),500


@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        user=authenticate(request.form.get('username',''),request.form.get('password',''))
        if user:
            start_session(user)
            return redirect(safe_redirect(request.form.get('next') or request.args.get('next','/')))
        flash('Invalid username or password.','danger')
    return render_template('login.html',attempt_info=None)


@app.post('/logout')
@login_required
def logout():
    end_session()
    return redirect(url_for('index'))


@app.route('/register',methods=['GET','POST'])
def register():
    if request.method=='POST':
        limit_action('registration',10)
        username=text(request.form.get('username',''),32)
        if not re.fullmatch(r'[A-Za-z0-9_]{3,32}',username):
            abort(400,description='Username must contain 3 to 32 letters, digits or underscores')
        address=email(request.form.get('email',''))
        password=valid_password(request.form.get('password',''))
        if password!=request.form.get('confirm_password'):
            abort(400,description='Passwords do not match')
        card=text(request.form.get('credit_card_number',''),4,required=False)
        if card and not re.fullmatch(r'[0-9]{4}',card):
            abort(400,description='Provide only four demo card digits')
        expiry=text(request.form.get('credit_card_expiry',''),5,required=False)
        if expiry and not re.fullmatch(r'(0[1-9]|1[0-2])/[0-9]{2}',expiry):
            abort(400,description='Invalid expiry')
        try:
            write('INSERT INTO users (username,email,password,credit_card_number,credit_card_expiry) VALUES (?,?,?,?,?)',(username,address,generate_password_hash(password),mask_card(card),expiry))
        except sqlite3.IntegrityError:
            flash('Registration could not be completed with those details.','danger')
            return render_template('register.html'),400
        start_session(one('SELECT * FROM users WHERE username=?',(username,)))
        return redirect(url_for('index'))
    return render_template('register.html')


@app.route('/forgot_password',methods=['GET','POST'])
def forgot_password():
    if request.method=='POST':
        limit_action('reset',3)
        username=text(request.form.get('username',''),64)
        now=int(time.time())
        user=one('SELECT * FROM users WHERE username=? AND is_active=1',(username,))
        # Only one live reset per account every fifteen minutes, with a generic response.
        if user and (not user['reset_token_expiry'] or int(user['reset_token_expiry'])<now):
            token=secrets.token_urlsafe(32)
            write('UPDATE users SET reset_token=?,reset_token_expiry=? WHERE id=?',(digest(token),now+900,user['id']))
            outbox=Path(app.config['RESET_OUTBOX']); outbox.mkdir(parents=True,exist_ok=True,mode=0o700)
            path=outbox/str(user['id'])
            descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
            with os.fdopen(descriptor,'w',encoding='utf-8') as delivery:
                delivery.write('/reset_password/'+token)
        flash('If the account is eligible, a reset request has been recorded. Contact the local operator.','info')
    return render_template('forgot_password.html')


@app.route('/reset_password/<token>',methods=['GET','POST'])
def reset_password(token):
    now=int(time.time()); hashed=digest(token)
    user=one('SELECT id FROM users WHERE reset_token=? AND reset_token_expiry>? AND is_active=1',(hashed,now))
    if not user:
        abort(400,description='Invalid or expired reset link')
    if request.method=='POST':
        password=valid_password(request.form.get('password',''))
        if password!=request.form.get('confirm_password'):
            abort(400,description='Passwords do not match')
        with transaction(app.config['DATABASE']) as db:
            changed=db.execute('UPDATE users SET password=?,reset_token=NULL,reset_token_expiry=NULL,password_reset_required=0,auth_version=auth_version+1 WHERE reset_token=? AND reset_token_expiry>? AND is_active=1',(generate_password_hash(password),hashed,now)).rowcount
            if changed!=1:
                abort(400)
            db.execute('DELETE FROM sessions WHERE user_id=?',(user['id'],))
        (Path(app.config['RESET_OUTBOX'])/str(user['id'])).unlink(missing_ok=True)
        end_session()
        return redirect(url_for('login'))
    return render_template('reset_password.html',token=token)


@app.get('/')
def index():
    return render_template('index.html',books=rows('SELECT * FROM books ORDER BY id'))


@app.get('/books')
def books():
    query=text(request.args.get('search',''),200,required=False)
    results=rows('SELECT * FROM books WHERE title LIKE ? OR author LIKE ? ORDER BY id',(f'%{query}%',f'%{query}%'))
    return render_template('books.html',books=results,search=query)


@app.get('/book_details')
def book_details():
    book_id=positive_int(request.args.get('id'),2**31-1)
    book=one('SELECT * FROM books WHERE id=?',(book_id,))
    if not book:
        abort(404)
    reviews=rows('SELECT reviews.*,users.username FROM reviews LEFT JOIN users ON users.id=reviews.user_id WHERE book_id=? ORDER BY reviews.created_at DESC',(book_id,))
    return render_template('book_details.html',book=book,reviews=reviews)


@app.get('/profile')
@login_required
def profile():
    if request.args.get('user_id') and positive_int(request.args['user_id'],2**31-1)!=g.user['id']:
        abort(403)
    orders=rows('SELECT * FROM orders WHERE user_id=? ORDER BY created_at DESC LIMIT 5',(g.user['id'],))
    return render_template('profile.html',user=g.user,orders=orders)


@app.route('/edit_profile',methods=['GET','POST'])
@login_required
def edit_profile():
    if request.method=='POST':
        address=email(request.form.get('email',''))
        if address!=g.user['email']:
            current_password()
        bio=text(request.form.get('bio',''),2000,required=False)
        try:
            write('UPDATE users SET bio=?,email=? WHERE id=?',(bio,address,g.user['id']))
        except sqlite3.IntegrityError:
            abort(400,description='Profile could not be updated')
        return redirect(url_for('profile'))
    return render_template('edit_profile.html',user=g.user)


@app.post('/change_password')
@login_required
def change_password():
    current_password()
    password=valid_password(request.form.get('new_password',''))
    with transaction(app.config['DATABASE']) as db:
        db.execute('UPDATE users SET password=?,password_reset_required=0,auth_version=auth_version+1 WHERE id=?',(generate_password_hash(password),g.user['id']))
        db.execute('DELETE FROM sessions WHERE user_id=?',(g.user['id'],))
    end_session()
    return redirect(url_for('login'))


@app.post('/change_email')
@login_required
def change_email():
    current_password()
    try:
        write('UPDATE users SET email=? WHERE id=?',(email(request.form.get('new_email','')),g.user['id']))
    except sqlite3.IntegrityError:
        abort(400,description='Email could not be updated')
    return redirect(url_for('profile'))


@app.post('/delete_account')
@login_required
def delete_account():
    current_password()
    if g.user['role']=='admin' and one("SELECT COUNT(*) AS n FROM users WHERE role='admin' AND is_active=1")['n']<=1:
        abort(409,description='Create another administrator before deactivating this account')
    with transaction(app.config['DATABASE']) as db:
        db.execute('UPDATE users SET is_active=0,auth_version=auth_version+1 WHERE id=?',(g.user['id'],))
        db.execute('DELETE FROM sessions WHERE user_id=?',(g.user['id'],))
    end_session()
    return redirect(url_for('index'))


@app.post('/upload_avatar')
@login_required
def upload_avatar():
    upload=request.files.get('avatar')
    if not upload or not upload.filename:
        abort(400,description='Select an image')
    try:
        filename,original=store_avatar(upload,app.config['UPLOAD_FOLDER'])
    except ValueError as error:
        abort(400,description=str(error))
    try:
        with transaction(app.config['DATABASE']) as db:
            db.execute('UPDATE users SET profile_pic=? WHERE id=?',(filename,g.user['id']))
            db.execute('INSERT INTO uploaded_files (user_id,filename,original_filename) VALUES (?,?,?)',(g.user['id'],filename,original))
    except BaseException:
        (Path(app.config['UPLOAD_FOLDER'])/filename).unlink(missing_ok=True)
        raise
    return redirect(url_for('profile'))


@app.post('/add_to_cart/<int:book_id>')
@login_required
def add_to_cart(book_id):
    quantity=positive_int(request.form.get('quantity','1'))
    with transaction(app.config['DATABASE']) as db:
        book=db.execute('SELECT stock FROM books WHERE id=?',(book_id,)).fetchone()
        if not book:
            abort(404)
        old=db.execute('SELECT quantity FROM cart WHERE user_id=? AND book_id=?',(g.user['id'],book_id)).fetchone()
        combined=quantity+(old['quantity'] if old else 0)
        if combined>100 or combined>book['stock']:
            abort(409,description='Quantity exceeds available stock')
        db.execute('INSERT INTO cart (user_id,book_id,quantity) VALUES (?,?,?) ON CONFLICT(user_id,book_id) DO UPDATE SET quantity=excluded.quantity',(g.user['id'],book_id,combined))
    return redirect(url_for('view_cart'))


@app.get('/cart')
@login_required
def view_cart():
    items=rows('SELECT books.*,cart.quantity,cart.id AS cart_id FROM cart JOIN books ON books.id=cart.book_id WHERE cart.user_id=? ORDER BY books.id',(g.user['id'],))
    total=sum(item['price_cents']*item['quantity'] for item in items)/100
    return render_template('cart.html',cart_items=items,total=total)


@app.post('/remove_from_cart/<int:book_id>')
@login_required
def remove_from_cart(book_id):
    write('DELETE FROM cart WHERE user_id=? AND book_id=?',(g.user['id'],book_id))
    return redirect(url_for('view_cart'))


@app.route('/checkout',methods=['GET','POST'])
@login_required
def checkout():
    try:
        if request.method=='POST':
            address=text(request.form.get('shipping_address',''),500)
            order_id=purchase(app.config['DATABASE'],g.user['id'],session.get('coupon_code'),address)
            session.pop('coupon_code',None);session.pop('coupon_discount',None)
            return redirect(url_for('order_detail',order_id=order_id))
        with closing(database()) as db:
            items,subtotal,total,coupon=quote_cart(db,g.user['id'],session.get('coupon_code'))
        if coupon:
            session['coupon_discount']=coupon['discount_percent']
        return render_template('checkout.html',cart_items=items,total=total/100,subtotal=subtotal/100,user=g.user)
    except ValueError as error:
        if request.method=='GET' and not one('SELECT id FROM cart WHERE user_id=?',(g.user['id'],)):
            return redirect(url_for('view_cart'))
        abort(409,description=str(error))


@app.post('/apply_coupon')
@login_required
def apply_coupon():
    code=text(request.form.get('code',''),64)
    coupon=one('SELECT * FROM coupons WHERE code=? AND is_active=1 AND current_uses<max_uses',(code,))
    if not coupon:
        session.pop('coupon_code',None);session.pop('coupon_discount',None)
        abort(400,description='Invalid or exhausted coupon')
    session['coupon_code']=coupon['code']
    session['coupon_discount']=coupon['discount_percent']
    return redirect(url_for('checkout'))


@app.get('/order_history')
@login_required
def order_history():
    orders=rows('SELECT * FROM orders WHERE user_id=? ORDER BY created_at DESC,id DESC',(g.user['id'],))
    return render_template('order_history.html',orders=orders)


@app.get('/order/<int:order_id>')
@login_required
def order_detail(order_id):
    order=owned_order(order_id)
    items=rows('SELECT order_items.*,books.title,books.author,books.image FROM order_items JOIN books ON books.id=order_items.book_id WHERE order_id=?',(order_id,))
    return render_template('order_detail.html',order=order,items=items)


@app.get('/download_receipt/<int:order_id>')
@login_required
def download_receipt(order_id):
    order=owned_order(order_id)
    items=rows('SELECT order_items.*,books.title FROM order_items JOIN books ON books.id=order_items.book_id WHERE order_id=?',(order_id,))
    lines=[f"Receipt - Order #{order_id}",f"Date: {order['created_at']}",f"Status: {order['status']}",f"Shipping: {order['shipping_address']}",'Items:']
    lines.extend(f"  {item['title']} x{item['quantity']} @ ${item['price']:.2f}" for item in items)
    lines.append(f"Total: ${order['total']:.2f}")
    response=make_response('\n'.join(lines))
    response.mimetype='text/plain'
    response.headers['Content-Disposition']=f'attachment; filename=receipt_{order_id}.txt'
    return response


@app.post('/review/<int:book_id>')
@login_required
def add_review(book_id):
    if not one('SELECT id FROM books WHERE id=?',(book_id,)):
        abort(404)
    rating=positive_int(request.form.get('rating'),5)
    comment=text(request.form.get('comment',''),4000)
    write('INSERT INTO reviews (user_id,book_id,rating,comment) VALUES (?,?,?,?)',(g.user['id'],book_id,rating,comment))
    return redirect(url_for('book_details',id=book_id))


@app.post('/edit_review/<int:review_id>')
@login_required
def edit_review(review_id):
    review=owned_review(review_id)
    write('UPDATE reviews SET comment=?,rating=? WHERE id=?',(text(request.form.get('comment',''),4000),positive_int(request.form.get('rating'),5),review_id))
    return redirect(url_for('book_details',id=review['book_id']))


@app.post('/delete_review/<int:review_id>')
@login_required
def delete_review(review_id):
    review=owned_review(review_id)
    write('DELETE FROM reviews WHERE id=?',(review_id,))
    return redirect(url_for('book_details',id=review['book_id']))


@app.route('/transfer',methods=['GET','POST'])
@login_required
def transfer_balance():
    if request.method=='POST':
        try:
            amount=transfer_cents(request.form.get('amount',''))
            recipient=text(request.form.get('recipient',''),32)
            transfer(app.config['DATABASE'],g.user['id'],recipient,amount)
        except ValueError as error:
            abort(409,description=str(error))
        return redirect(url_for('profile'))
    return render_template('transfer.html',user=g.user)


@app.get('/support')
@login_required
def support_tickets():
    tickets=rows('SELECT * FROM support_tickets WHERE user_id=? ORDER BY created_at DESC,id DESC',(g.user['id'],))
    return render_template('support_tickets.html',tickets=tickets)


@app.route('/support/new',methods=['GET','POST'])
@login_required
def new_ticket():
    if request.method=='POST':
        limit_action('support',20)
        write('INSERT INTO support_tickets (user_id,subject,message) VALUES (?,?,?)',(g.user['id'],text(request.form.get('subject',''),200),text(request.form.get('message',''),4000)))
        return redirect(url_for('support_tickets'))
    return render_template('new_ticket.html')


@app.get('/api/check_username')
def api_check_username():
    limit_action('username-availability',120)
    username=text(request.args.get('username',''),64)
    exists=one('SELECT id FROM users WHERE username=?',(username,)) is not None
    return jsonify(exists=exists,message='Username is taken' if exists else 'Username is available')


@app.get('/api/check_coupon')
def api_check_coupon():
    limit_action('coupon-availability',120)
    code=text(request.args.get('code',''),64)
    coupon=one('SELECT discount_percent FROM coupons WHERE code=? AND is_active=1 AND current_uses<max_uses',(code,))
    return jsonify(valid=True,discount=coupon['discount_percent']) if coupon else jsonify(valid=False)


@app.get('/api/user/<int:user_id>/card')
@login_required
def api_user_card(user_id):
    if user_id!=g.user['id']:
        abort(403)
    return jsonify(username=g.user['username'],card_number=g.user['credit_card_number'],card_expiry=g.user['credit_card_expiry'])


@app.post('/api/update_role')
@admin_required
def api_update_role():
    user_id=positive_int(request.form.get('user_id'),2**31-1)
    role=request.form.get('role','')
    if role not in {'user','moderator','admin'} or user_id==g.user['id']:
        abort(400)
    if write('UPDATE users SET role=?,auth_version=auth_version+1 WHERE id=?',(role,user_id))!=1:
        abort(404)
    log_admin_action(g.user['id'],'change_role',user_id)
    return jsonify(success=True)


@app.post('/api/import_books')
@admin_required
def api_import_books():
    data=request.files['xml_file'].read(1000001) if 'xml_file' in request.files else request.get_data()
    try:
        elements=parse_books(data)
        values=[]
        for element in elements:
            if element.tag!='book':
                abort(400)
            values.append((text(element.findtext('title',''),200),text(element.findtext('author',''),200),cents(element.findtext('price','')),text(element.findtext('description',''),4000,required=False),text(element.findtext('category','General'),100)))
        with transaction(app.config['DATABASE']) as db:
            db.executemany('INSERT INTO books (title,author,price_cents,description,category) VALUES (?,?,?,?,?)',values)
        return jsonify(success=True,books_added=len(values))
    except (DefusedXmlException,ParseError,ValueError):
        abort(400,description='Invalid book XML')


@app.post('/api/load_cart')
@login_required
def api_load_cart():
    try:
        data=request.get_json(silent=True)
        if data is None:
            data=json.loads(request.form.get('cart_data',''))
        if not isinstance(data,list) or len(data)>50:
            abort(400,description='Send a JSON list of at most 50 cart items')
        items={}
        for item in data:
            if not isinstance(item,dict) or set(item)!={'book_id','quantity'}:
                abort(400)
            book_id=positive_int(item['book_id'],2**31-1)
            quantity=positive_int(item['quantity'])
            if book_id in items:
                abort(400)
            items[book_id]=quantity
        with transaction(app.config['DATABASE']) as db:
            for book_id,quantity in items.items():
                book=db.execute('SELECT stock FROM books WHERE id=?',(book_id,)).fetchone()
                if not book or book['stock']<quantity:
                    abort(409)
            db.execute('DELETE FROM cart WHERE user_id=?',(g.user['id'],))
            db.executemany('INSERT INTO cart (user_id,book_id,quantity) VALUES (?,?,?)',[(g.user['id'],book_id,quantity) for book_id,quantity in items.items()])
        return jsonify(success=True,items=len(items))
    except (ValueError,TypeError):
        abort(400,description='Invalid JSON cart')


@app.get('/admin')
@admin_required
def admin_dashboard():
    stats=dict(total_users=one('SELECT COUNT(*) AS n FROM users')['n'],total_books=one('SELECT COUNT(*) AS n FROM books')['n'],total_orders=one('SELECT COUNT(*) AS n FROM orders')['n'],total_revenue=one('SELECT COALESCE(SUM(total_cents),0) AS n FROM orders')['n']/100,open_tickets=one("SELECT COUNT(*) AS n FROM support_tickets WHERE status='open'")['n'])
    recent_users=rows('SELECT id,username,email,role,created_at FROM users ORDER BY id DESC LIMIT 5')
    recent_orders=rows('SELECT * FROM orders ORDER BY id DESC LIMIT 5')
    return render_template('admin_dashboard.html',stats=stats,recent_users=recent_users,recent_orders=recent_orders)


@app.get('/admin/users')
@admin_required
def admin_users():
    users=rows('SELECT id,username,email,role,balance,credit_card_number,is_active FROM users ORDER BY id')
    return render_template('admin_users.html',users=users)


@app.get('/admin/logs')
@admin_required
def admin_logs():
    logs=rows('SELECT admin_logs.*,users.username AS admin_username FROM admin_logs LEFT JOIN users ON users.id=admin_logs.admin_id ORDER BY admin_logs.id DESC LIMIT 100')
    return render_template('admin_logs.html',logs=logs)


@app.get('/admin/tickets')
@admin_required
def admin_tickets():
    tickets=rows('SELECT support_tickets.*,users.username FROM support_tickets JOIN users ON users.id=support_tickets.user_id ORDER BY support_tickets.id DESC')
    return render_template('admin_tickets.html',tickets=tickets)


@app.post('/admin/ticket/<int:ticket_id>/reply')
@admin_required
def admin_reply_ticket(ticket_id):
    reply=text(request.form.get('reply',''),4000)
    if write("UPDATE support_tickets SET admin_reply=?,status='closed' WHERE id=?",(reply,ticket_id))!=1:
        abort(404)
    log_admin_action(g.user['id'],'reply_ticket',details=f'Ticket #{ticket_id}')
    return redirect(url_for('admin_tickets'))


@app.route('/admin/ping',methods=['GET','POST'])
@admin_required
def admin_ping():
    result=None
    if request.method=='POST':
        try:
            result=ping_host(text(request.form.get('host',''),64))
        except (ValueError,OSError,TimeoutError):
            result='Ping rejected or unavailable'
        log_admin_action(g.user['id'],'ping')
    return render_template('admin_ping.html',result=result)


@app.route('/admin/preview_url',methods=['GET','POST'])
@admin_required
def admin_preview_url():
    content=None
    if request.method=='POST':
        try:
            content=preview_url(text(request.form.get('url',''),2000))
        except (ValueError,OSError,TimeoutError):
            content='Preview rejected or unavailable'
        log_admin_action(g.user['id'],'preview_url')
    return render_template('admin_preview.html',content=content)


@app.get('/admin/export')
@admin_required
def admin_export():
    if request.args.get('format','csv')!='csv':
        abort(400,description='Only CSV export is supported')
    output=io.StringIO(newline=''); writer=csv.writer(output)
    writer.writerow(['id','title','author','price','category','stock'])
    for book in rows('SELECT * FROM books ORDER BY id'):
        values=[book['id'],book['title'],book['author'],f"{book['price']:.2f}",book['category'],book['stock']]
        writer.writerow(["'"+v if isinstance(v,str) and v.lstrip().startswith(('=','+','-','@','\t','\r')) else v for v in values])
    response=make_response(output.getvalue()); response.mimetype='text/csv'
    response.headers['Content-Disposition']='attachment; filename=books.csv'
    return response


@app.post('/admin/reset_data')
@admin_required
def admin_reset_data():
    abort(405)


@app.get('/redirect')
def open_redirect():
    return redirect(safe_redirect(request.args.get('url','/')))


@app.post('/set_language')
def set_language():
    lang=request.form.get('lang','en')
    if lang not in {'en','ru','my'}:
        abort(400)
    response=make_response(redirect(url_for('index')))
    response.set_cookie('language',lang,httponly=True,secure=app.config['SESSION_COOKIE_SECURE'],samesite='Lax')
    return response


@app.get('/debug_db')
def debug_db():
    abort(404)


@app.get('/robots.txt')
def robots():
    response=make_response('User-agent: *\nDisallow: /admin\n')
    response.mimetype='text/plain'
    return response


@app.get('/uploads')
@login_required
def list_uploads():
    files=rows('SELECT filename,original_filename FROM uploaded_files WHERE user_id=? ORDER BY id',(g.user['id'],))
    return render_template('uploads.html',files=files)


@app.get('/app.py.bak')
def backup_file():
    abort(404)


@app.get('/search')
def search_page():
    query=text(request.args.get('q',''),200,required=False)
    results=rows('SELECT * FROM books WHERE title LIKE ? OR author LIKE ? ORDER BY id',(f'%{query}%',f'%{query}%'))
    return render_template('search.html',query=query,results=results)


@app.post('/lab/reset')
@admin_required
def lab_reset():
    abort(405)


@app.get('/lab')
@admin_required
def lab_panel():
    return render_template('lab_panel.html')


@app.post('/api/jwt/login')
def jwt_login():
    data=request.get_json(silent=True) or request.form
    if not isinstance(data,dict) and not hasattr(data,'get'):
        abort(400)
    user=authenticate(data.get('username',''),data.get('password',''))
    if not user:
        return jsonify(error='Invalid credentials'),401
    now=int(time.time())
    token=jwt.encode(dict(sub=str(user['id']),ver=user['auth_version'],iat=now,exp=now+900,iss='dv-bookshop-fixed',aud='dv-bookshop-api'),app.config['JWT_SECRET'],algorithm='HS256')
    return jsonify(token=token,token_type='Bearer',expires_in=900)


@app.get('/api/jwt/me')
def jwt_me():
    user=token_identity()
    return jsonify(identity=dict(sub=str(user['id']),username=user['username'],role=user['role']))


@app.get('/api/jwt/admin')
def jwt_admin():
    user=token_identity()
    if user['role']!='admin':
        abort(403)
    return jsonify(message='Welcome, admin.')


@app.get('/api/race-lab/status')
@login_required
def race_lab_status():
    if g.user['username'] not in {'alice_hacker','bob_secure'} and g.user['role']!='admin':
        abort(403)
    accounts=[dict(row) for row in rows('SELECT username,balance FROM race_accounts ORDER BY id')]
    transfers=[dict(row) for row in rows('SELECT sender,recipient,amount,mode,created_at FROM race_transfers ORDER BY id DESC LIMIT 20')]
    return jsonify(accounts=accounts,recent_transfers=transfers)


@app.post('/api/race-lab/transfer/vulnerable')
@login_required
def race_lab_vulnerable_transfer():
    # Retain the URL contract, but never expose a vulnerable transaction.
    return race_lab_safe_transfer()


@app.post('/api/race-lab/transfer/safe')
@login_required
def race_lab_safe_transfer():
    sender=g.user['username']
    if sender not in {'alice_hacker','bob_secure'}:
        abort(403)
    data=request.get_json(silent=True) or request.form
    if not hasattr(data,'get'):
        abort(400)
    try:
        amount=transfer_cents(data.get('amount',''))
        recipient=text(data.get('recipient',''),32)
        with transaction(app.config['DATABASE']) as db:
            if recipient not in {'alice_hacker','bob_secure'} or recipient==sender:
                abort(400)
            if db.execute('UPDATE race_accounts SET balance_cents=balance_cents-? WHERE username=? AND balance_cents>=?',(amount,sender,amount)).rowcount!=1:
                abort(409)
            if db.execute('UPDATE race_accounts SET balance_cents=balance_cents+? WHERE username=? AND balance_cents<=?',(amount,recipient,1000000000-amount)).rowcount!=1:
                abort(409)
            db.execute('INSERT INTO race_transfers (sender,recipient,amount_cents,mode) VALUES (?,?,?,?)',(sender,recipient,amount,'safe'))
            balance=db.execute('SELECT balance FROM race_accounts WHERE username=?',(sender,)).fetchone()['balance']
        return jsonify(status='accepted',mode='safe',sender_balance=balance)
    except ValueError:
        abort(400,description='Invalid transfer amount')


@app.post('/api/race-lab/reset')
@admin_required
def race_lab_reset():
    abort(405)




@app.get('/media/<filename>')
@login_required
def avatar(filename):
    if not re.fullmatch(r'[0-9a-f]{32}\.png',filename):
        abort(404)
    uploaded=one('SELECT user_id FROM uploaded_files WHERE filename=?',(filename,))
    if not uploaded or (uploaded['user_id']!=g.user['id'] and g.user['role']!='admin'):
        abort(404)
    return send_from_directory(app.config['UPLOAD_FOLDER'],filename,mimetype='image/png')


def avatar_url(user):
    if user['profile_pic']=='default.png':
        return url_for('static',filename='uploads/default.png')
    return url_for('avatar',filename=user['profile_pic'])


@app.context_processor
def avatar_context():
    return dict(avatar_url=avatar_url)

if __name__=='__main__':
    app.run(host='127.0.0.1',port=int(os.environ.get('BOOKSHOP_PORT','5006')),debug=False)
