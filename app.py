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
from flask import Flask, abort, flash, g, jsonify, make_response, redirect, render_template, request, session, url_for
from flask_wtf.csrf import CSRFError, generate_csrf
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash

from catalog_seed import BOOKS, COUPONS
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


@app.get('/api/csrf')
def csrf_token_api():
    return jsonify(csrf_token=generate_csrf())


@app.errorhandler(HTTPException)
def http_error(error):
    message=error.description if error.code in (400,413,429,503) else error.name
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
        username=text(request.form.get('username',''),32)
        if not re.fullmatch(r'[A-Za-z0-9_]{3,32}',username):
            abort(400,description='Username must contain 3 to 32 letters, digits or underscores')
        address=email(request.form.get('email',''))
        password=valid_password(request.form.get('password',''))
        if password!=request.form.get('confirm_password'):
            abort(400,description='Passwords do not match')
        expiry=text(request.form.get('credit_card_expiry',''),5,required=False)
        if expiry and not re.fullmatch(r'(0[1-9]|1[0-2])/[0-9]{2}',expiry):
            abort(400,description='Invalid expiry')
        try:
            write('INSERT INTO users (username,email,password,credit_card_number,credit_card_expiry) VALUES (?,?,?,?,?)',(username,address,generate_password_hash(password),mask_card(request.form.get('credit_card_number','')),expiry))
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
            changed=db.execute('UPDATE users SET password=?,reset_token=NULL,reset_token_expiry=NULL,auth_version=auth_version+1 WHERE reset_token=? AND reset_token_expiry>? AND is_active=1',(generate_password_hash(password),hashed,now)).rowcount
            if changed!=1:
                abort(400)
            db.execute('DELETE FROM sessions WHERE user_id=?',(user['id'],))
        (Path(app.config['RESET_OUTBOX'])/str(user['id'])).unlink(missing_ok=True)
        end_session()
        return redirect(url_for('login'))
    return render_template('reset_password.html',token=token)


@app.route('/')
def index():
    conn = get_shop_db()
    c = conn.cursor()
    c.execute('SELECT * FROM books')
    books = c.fetchall()
    conn.close()
    return render_template('index.html', books=books)


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
        db.execute('UPDATE users SET password=?,auth_version=auth_version+1 WHERE id=?',(generate_password_hash(password),g.user['id']))
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
    with transaction(app.config['DATABASE']) as db:
        db.execute('UPDATE users SET is_active=0,auth_version=auth_version+1 WHERE id=?',(g.user['id'],))
        db.execute('DELETE FROM sessions WHERE user_id=?',(g.user['id'],))
    end_session()
    return redirect(url_for('index'))


@app.route('/upload_avatar', methods=['POST'])
@login_required
def upload_avatar():
    if 'avatar' not in request.files:
        flash('No file selected.', 'danger')
        return redirect(url_for('edit_profile'))

    file = request.files['avatar']
    if file.filename == '':
        flash('No file selected.', 'danger')
        return redirect(url_for('edit_profile'))

    # G1 вЂ” Unrestricted file upload: no extension/type validation
    # G2 вЂ” Path traversal: filename used directly
    # G3 вЂ” No MIME type validation
    filename = file.filename  # No secure_filename!
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    # B5 вЂ” XSS via filename: original filename stored and rendered
    conn = get_user_db()
    c = conn.cursor()
    c.execute('UPDATE users SET profile_pic = ? WHERE id = ?', (filename, session['user_id']))
    conn.commit()

    # Log uploaded file
    sconn = get_shop_db()
    sc = sconn.cursor()
    sc.execute('INSERT INTO uploaded_files (user_id, filename, original_filename) VALUES (?, ?, ?)',
              (session['user_id'], filename, file.filename))
    sconn.commit()
    sconn.close()

    conn.close()
    flash('Avatar uploaded successfully!', 'success')
    return redirect(url_for('profile'))


@app.route('/add_to_cart/<int:book_id>', methods=['POST'])
@login_required
def add_to_cart(book_id):
    # C3 вЂ” CSRF: No token validation
    # K1 вЂ” Negative quantity: accepts any quantity value
    quantity = request.form.get('quantity', 1, type=int)

    conn = get_shop_db()
    c = conn.cursor()

    c.execute('SELECT * FROM books WHERE id = ?', (book_id,))
    book = c.fetchone()
    if not book:
        conn.close()
        flash('Book not found.', 'danger')
        return redirect(url_for('index'))

    c.execute('SELECT * FROM cart WHERE user_id = ? AND book_id = ?',
              (session['user_id'], book_id))
    cart_item = c.fetchone()

    if cart_item:
        c.execute('UPDATE cart SET quantity = quantity + ? WHERE user_id = ? AND book_id = ?',
                 (quantity, session['user_id'], book_id))
    else:
        c.execute('INSERT INTO cart (user_id, book_id, quantity) VALUES (?, ?, ?)',
                 (session['user_id'], book_id, quantity))

    conn.commit()
    conn.close()

    flash('Book added to cart!', 'success')
    return redirect(request.referrer or url_for('index'))


@app.route('/cart')
@login_required
def view_cart():
    conn = get_shop_db()
    c = conn.cursor()
    c.execute('''SELECT books.*, cart.quantity, cart.id as cart_id
                 FROM cart
                 JOIN books ON cart.book_id = books.id
                 WHERE cart.user_id = ?''', (session['user_id'],))
    cart_items = c.fetchall()
    total = sum(item['price'] * item['quantity'] for item in cart_items)
    conn.close()
    return render_template('cart.html', cart_items=cart_items, total=total)


@app.route('/remove_from_cart/<int:book_id>', methods=['POST'])
@login_required
def remove_from_cart(book_id):
    conn = get_shop_db()
    c = conn.cursor()
    c.execute('DELETE FROM cart WHERE user_id = ? AND book_id = ?',
              (session['user_id'], book_id))
    conn.commit()
    conn.close()
    flash('Item removed from cart.', 'success')
    return redirect(url_for('view_cart'))


@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    conn = get_shop_db()
    c = conn.cursor()
    c.execute('''SELECT books.*, cart.quantity
                 FROM cart
                 JOIN books ON cart.book_id = books.id
                 WHERE cart.user_id = ?''', (session['user_id'],))
    cart_items = c.fetchall()

    if not cart_items:
        conn.close()
        flash('Your cart is empty.', 'danger')
        return redirect(url_for('view_cart'))

    total = sum(item['price'] * item['quantity'] for item in cart_items)

    if request.method == 'POST':
        shipping_address = request.form.get('shipping_address', '')
        # K3 вЂ” Price manipulation: uses client-submitted total instead of server-calculated
        submitted_total = request.form.get('total', total, type=float)

        uconn = get_user_db()
        uc = uconn.cursor()
        uc.execute('SELECT balance FROM users WHERE id = ?', (session['user_id'],))
        user = uc.fetchone()

        # K5 вЂ” Insufficient balance bypass: uses submitted_total
        if user['balance'] < submitted_total:
            uconn.close()
            conn.close()
            flash('Insufficient balance!', 'danger')
            return redirect(url_for('checkout'))

        # Deduct balance
        uc.execute('UPDATE users SET balance = balance - ? WHERE id = ?',
                  (submitted_total, session['user_id']))
        uconn.commit()
        uconn.close()

        # Create order
        c.execute('''INSERT INTO orders (user_id, total, status, shipping_address)
                     VALUES (?, ?, 'confirmed', ?)''',
                 (session['user_id'], submitted_total, shipping_address))
        order_id = c.lastrowid

        # Create order items
        for item in cart_items:
            c.execute('''INSERT INTO order_items (order_id, book_id, quantity, price)
                        VALUES (?, ?, ?, ?)''',
                     (order_id, item['id'], item['quantity'], item['price']))

        # Clear cart
        c.execute('DELETE FROM cart WHERE user_id = ?', (session['user_id'],))
        conn.commit()
        conn.close()

        flash(f'Order #{order_id} placed successfully!', 'success')
        return redirect(url_for('order_detail', order_id=order_id))

    conn.close()

    # Get user balance
    uconn = get_user_db()
    uc = uconn.cursor()
    uc.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
    user = uc.fetchone()
    uconn.close()

    return render_template('checkout.html', cart_items=cart_items, total=total, user=user)


@app.route('/apply_coupon', methods=['POST'])
@login_required
def apply_coupon():
    code = request.form.get('code', '')

    conn = get_shop_db()
    c = conn.cursor()
    c.execute('SELECT * FROM coupons WHERE code = ? AND is_active = 1', (code,))
    coupon = c.fetchone()

    if coupon:
        # K4 вЂ” Coupon reuse: max_uses not properly enforced
        session['coupon_discount'] = coupon['discount_percent']
        session['coupon_code'] = code
        flash(f'Coupon applied! {coupon["discount_percent"]}% discount.', 'success')
    else:
        flash('Invalid or expired coupon code.', 'danger')

    conn.close()
    return redirect(url_for('checkout'))


@app.route('/order_history')
@login_required
def order_history():
    conn = get_shop_db()
    c = conn.cursor()
    c.execute('SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC',
              (session['user_id'],))
    orders = c.fetchall()
    conn.close()
    return render_template('order_history.html', orders=orders)


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


@app.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer_balance():
    if request.method == 'POST':
        # C4 вЂ” CSRF: No token validation for money transfer
        recipient_username = request.form.get('recipient', '')
        amount = request.form.get('amount', 0, type=float)

        if amount <= 0:
            flash('Invalid amount.', 'danger')
            return redirect(url_for('transfer_balance'))

        conn = get_user_db()
        c = conn.cursor()

        # Check sender balance
        c.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
        sender = c.fetchone()

        if sender['balance'] < amount:
            flash('Insufficient balance.', 'danger')
            conn.close()
            return redirect(url_for('transfer_balance'))

        # Find recipient
        c.execute('SELECT * FROM users WHERE username = ?', (recipient_username,))
        recipient = c.fetchone()

        if not recipient:
            flash('Recipient not found.', 'danger')
            conn.close()
            return redirect(url_for('transfer_balance'))

        if recipient['id'] == session['user_id']:
            flash('Cannot transfer to yourself.', 'danger')
            conn.close()
            return redirect(url_for('transfer_balance'))

        # K2 вЂ” Race condition: no locking, vulnerable to double-spend
        c.execute('UPDATE users SET balance = balance - ? WHERE id = ?',
                 (amount, session['user_id']))
        c.execute('UPDATE users SET balance = balance + ? WHERE id = ?',
                 (amount, recipient['id']))
        conn.commit()
        conn.close()

        flash(f'${amount:.2f} transferred to {recipient_username}!', 'success')
        return redirect(url_for('profile'))

    # GET вЂ” show transfer form
    conn = get_user_db()
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
    user = c.fetchone()
    conn.close()

    return render_template('transfer.html', user=user)


@app.route('/support')
@login_required
def support_tickets():
    conn = get_shop_db()
    c = conn.cursor()
    c.execute('SELECT * FROM support_tickets WHERE user_id = ? ORDER BY created_at DESC',
              (session['user_id'],))
    tickets = c.fetchall()
    conn.close()
    return render_template('support_tickets.html', tickets=tickets)


@app.route('/support/new', methods=['GET', 'POST'])
@login_required
def new_ticket():
    if request.method == 'POST':
        subject = request.form.get('subject', '')
        message = request.form.get('message', '')

        conn = get_shop_db()
        c = conn.cursor()
        c.execute('''INSERT INTO support_tickets (user_id, subject, message)
                    VALUES (?, ?, ?)''',
                 (session['user_id'], subject, message))
        conn.commit()
        conn.close()

        flash('Support ticket submitted!', 'success')
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


@app.route('/api/import_books', methods=['POST'])
def api_import_books():
    """L3 вЂ” XXE: XML External Entity injection via book import."""
    if 'xml_file' not in request.files:
        xml_data = request.data
    else:
        xml_data = request.files['xml_file'].read()

    if not xml_data:
        return jsonify({'error': 'No XML data provided'}), 400

    try:
        # L3 вЂ” XXE vulnerable: parsing XML without disabling external
        # entities. NOTE: stdlib xml.etree.ElementTree (expat) does NOT
        # resolve external SYSTEM/PUBLIC entities, so this route was not
        # actually exploitable for classic XXE (file read / SSRF) on any
        # modern Python. We use lxml with resolve_entities=True instead,
        # which DOES resolve <!ENTITY x SYSTEM "file://..."> references.
        xxe_parser = etree.XMLParser(resolve_entities=True, no_network=False,
                                      load_dtd=True, huge_tree=True)
        root = etree.fromstring(xml_data, parser=xxe_parser)
        books_added = 0

        conn = get_shop_db()
        c = conn.cursor()

        for book_elem in root.findall('book'):
            title = book_elem.findtext('title', '')
            author = book_elem.findtext('author', '')
            price = float(book_elem.findtext('price', '0'))
            description = book_elem.findtext('description', '')
            category = book_elem.findtext('category', 'General')

            c.execute('''INSERT INTO books (title, author, price, description, category)
                        VALUES (?, ?, ?, ?, ?)''',
                     (title, author, price, description, category))
            books_added += 1

        conn.commit()
        conn.close()

        return jsonify({'success': True, 'books_added': books_added})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


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


@app.route('/admin')
@admin_required
def admin_dashboard():
    # Get stats
    uconn = get_user_db()
    uc = uconn.cursor()
    uc.execute('SELECT COUNT(*) as cnt FROM users')
    total_users = uc.fetchone()['cnt']
    uc.execute('SELECT * FROM users ORDER BY created_at DESC LIMIT 5')
    recent_users = uc.fetchall()
    uconn.close()

    sconn = get_shop_db()
    sc = sconn.cursor()
    sc.execute('SELECT COUNT(*) as cnt FROM books')
    total_books = sc.fetchone()['cnt']
    sc.execute('SELECT COUNT(*) as cnt FROM orders')
    total_orders = sc.fetchone()['cnt']
    sc.execute('SELECT COALESCE(SUM(total), 0) as rev FROM orders')
    total_revenue = sc.fetchone()['rev']
    sc.execute('SELECT * FROM orders ORDER BY created_at DESC LIMIT 5')
    recent_orders = sc.fetchall()

    # Get open tickets count
    sc.execute("SELECT COUNT(*) as cnt FROM support_tickets WHERE status = 'open'")
    open_tickets = sc.fetchone()['cnt']
    sconn.close()

    stats = {
        'total_users': total_users,
        'total_books': total_books,
        'total_orders': total_orders,
        'total_revenue': total_revenue,
        'open_tickets': open_tickets,
    }

    return render_template('admin_dashboard.html', stats=stats,
                          recent_orders=recent_orders, recent_users=recent_users)


@app.route('/admin/users')
@admin_required
def admin_users():
    """F6 вЂ” Forced browsing: URL directly accessible if role check bypassed."""
    conn = get_user_db()
    c = conn.cursor()
    c.execute('SELECT * FROM users ORDER BY id')
    users = c.fetchall()
    conn.close()
    return render_template('admin_users.html', users=users)


@app.route('/admin/logs')
@admin_required
def admin_logs():
    conn = get_shop_db()
    c = conn.cursor()
    c.execute('SELECT * FROM admin_logs ORDER BY created_at DESC LIMIT 100')
    logs = c.fetchall()
    conn.close()

    # Enrich with usernames
    uconn = get_user_db()
    uc = uconn.cursor()
    enriched_logs = []
    for log in logs:
        uc.execute('SELECT username FROM users WHERE id = ?', (log['admin_id'],))
        admin = uc.fetchone()
        enriched_logs.append({
            'id': log['id'],
            'admin_username': admin['username'] if admin else 'Unknown',
            'action': log['action'],
            'details': log['details'],
            'created_at': log['created_at'],
        })
    uconn.close()

    return render_template('admin_logs.html', logs=enriched_logs)


@app.route('/admin/tickets')
@admin_required
def admin_tickets():
    conn = get_shop_db()
    c = conn.cursor()
    c.execute('SELECT * FROM support_tickets ORDER BY created_at DESC')
    tickets = c.fetchall()
    conn.close()

    # Enrich with usernames
    uconn = get_user_db()
    uc = uconn.cursor()
    enriched = []
    for t in tickets:
        uc.execute('SELECT username FROM users WHERE id = ?', (t['user_id'],))
        u = uc.fetchone()
        enriched.append({**dict(t), 'username': u['username'] if u else 'Unknown'})
    uconn.close()

    return render_template('admin_tickets.html', tickets=enriched)


@app.route('/admin/ticket/<int:ticket_id>/reply', methods=['POST'])
@admin_required
def admin_reply_ticket(ticket_id):
    reply = request.form.get('reply', '')
    conn = get_shop_db()
    c = conn.cursor()
    # A6 вЂ” Second-order SQLi potential: admin_reply stored, could be reflected elsewhere
    c.execute("UPDATE support_tickets SET admin_reply = ?, status = 'closed' WHERE id = ?",
              (reply, ticket_id))
    conn.commit()
    conn.close()

    log_admin_action(session['user_id'], 'reply_ticket', details=f'Ticket #{ticket_id}')
    flash('Reply sent.', 'success')
    return redirect(url_for('admin_tickets'))


@app.route('/admin/ping', methods=['GET', 'POST'])
@admin_required
def admin_ping():
    result = None
    if request.method == 'POST':
        host = request.form.get('host', '')

        # H1 вЂ” OS Command Injection
        try:
            output = subprocess.check_output(
                f"ping -c 2 {host}",
                shell=True,
                stderr=subprocess.STDOUT,
                timeout=10
            )
            result = output.decode('utf-8', errors='replace')
        except subprocess.TimeoutExpired:
            result = "Command timed out"
        except subprocess.CalledProcessError as e:
            result = e.output.decode('utf-8', errors='replace')
        except Exception as e:
            result = f"Error: {str(e)}"

        log_admin_action(session['user_id'], 'ping', details=f'Host: {host}')

    return render_template('admin_ping.html', result=result)


@app.route('/admin/preview_url', methods=['GET', 'POST'])
@admin_required
def admin_preview_url():
    content = None
    if request.method == 'POST':
        url = request.form.get('url', '')

        # I1 вЂ” SSRF: No URL validation, fetches arbitrary URLs
        try:
            response = urlopen(url, timeout=5)
            content = response.read().decode('utf-8', errors='replace')[:5000]
        except Exception as e:
            content = f"Error fetching URL: {str(e)}"

        log_admin_action(session['user_id'], 'preview_url', details=f'URL: {url}')

    return render_template('admin_preview.html', content=content)


@app.route('/admin/export')
@admin_required
def admin_export():
    fmt = request.args.get('format', 'csv')

    # H2 вЂ” Command injection in export
    try:
        conn = get_shop_db()
        c = conn.cursor()
        c.execute('SELECT * FROM books')
        books = c.fetchall()
        conn.close()

        if fmt == 'csv':
            output = "id,title,author,price,category,stock\n"
            for b in books:
                output += f"{b['id']},{b['title']},{b['author']},{b['price']},{b['category']},{b['stock']}\n"

            response = make_response(output)
            response.headers['Content-Type'] = 'text/csv'
            response.headers['Content-Disposition'] = 'attachment; filename=books.csv'
            return response
        else:
            # Vulnerable: format parameter injected into shell command
            cmd = f"echo 'Export format: {fmt}' && date"
            result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=5)
            return result.decode('utf-8', errors='replace')
    except Exception as e:
        return f"Export error: {str(e)}", 500


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


@app.route('/uploads')
def list_uploads():
    """J6 вЂ” Directory listing of uploaded files."""
    try:
        files = os.listdir(UPLOAD_FOLDER)
        output = "<h2>Uploaded Files</h2><ul>"
        for f in files:
            output += f'<li><a href="/static/uploads/{f}">{f}</a></li>'
        output += "</ul>"
        return output
    except Exception as e:
        return f"Error: {str(e)}", 500


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


@app.route('/api/race-lab/status')
@login_required
def race_lab_status():
    """Show balances and transfer records from the isolated race lab."""
    if not _race_lab_user():
        return jsonify({'error': 'Use alice_hacker or bob_secure for the race lab'}), 403

    conn = get_race_db()
    accounts = [dict(row) for row in conn.execute(
        'SELECT username, balance FROM race_accounts ORDER BY id'
    ).fetchall()]
    transfers = [dict(row) for row in conn.execute(
        'SELECT sender, recipient, amount, mode, created_at '
        'FROM race_transfers ORDER BY id DESC LIMIT 20'
    ).fetchall()]
    conn.close()
    return jsonify({'accounts': accounts, 'recent_transfers': transfers})


@app.route('/api/race-lab/transfer/vulnerable', methods=['POST'])
@login_required
def race_lab_vulnerable_transfer():
    """Intentionally expose a check-then-act race in an isolated database."""
    sender = _race_lab_user()
    values = _race_transfer_input()
    if not sender:
        return jsonify({'error': 'Use alice_hacker or bob_secure for the race lab'}), 403
    if not values:
        return jsonify({'error': 'Send a positive amount and recipient'}), 400

    amount, recipient = values
    conn = get_race_db()
    c = conn.cursor()
    c.execute('SELECT balance FROM race_accounts WHERE username = ?', (sender,))
    sender_row = c.fetchone()
    c.execute('SELECT username FROM race_accounts WHERE username = ?', (recipient,))
    recipient_row = c.fetchone()

    if not sender_row or not recipient_row:
        conn.close()
        return jsonify({'error': 'Race-lab account not found'}), 404
    if sender == recipient:
        conn.close()
        return jsonify({'error': 'Sender and recipient must be different'}), 400
    if sender_row['balance'] < amount:
        conn.close()
        return jsonify({'error': 'Insufficient balance', 'balance': sender_row['balance']}), 409

    # The deliberate pause makes two requests pass the same balance check.
    time.sleep(0.1)
    c.execute(
        'UPDATE race_accounts SET balance = balance - ? WHERE username = ?',
        (amount, sender),
    )
    c.execute(
        'UPDATE race_accounts SET balance = balance + ? WHERE username = ?',
        (amount, recipient),
    )
    c.execute(
        'INSERT INTO race_transfers (sender, recipient, amount, mode) VALUES (?, ?, ?, ?)',
        (sender, recipient, amount, 'vulnerable'),
    )
    conn.commit()
    c.execute('SELECT balance FROM race_accounts WHERE username = ?', (sender,))
    balance = c.fetchone()['balance']
    conn.close()
    return jsonify({
        'status': 'accepted',
        'mode': 'vulnerable',
        'sender': sender,
        'recipient': recipient,
        'amount': amount,
        'sender_balance': balance,
    }), 200


@app.route('/api/race-lab/transfer/safe', methods=['POST'])
@login_required
def race_lab_safe_transfer():
    """Use one SQLite transaction to close the race-condition window."""
    sender = _race_lab_user()
    values = _race_transfer_input()
    if not sender:
        return jsonify({'error': 'Use alice_hacker or bob_secure for the race lab'}), 403
    if not values:
        return jsonify({'error': 'Send a positive amount and recipient'}), 400

    amount, recipient = values
    conn = get_race_db()
    c = conn.cursor()
    try:
        # Serialize the check and both balance updates for this SQLite database.
        c.execute('BEGIN IMMEDIATE')
        c.execute(
            'UPDATE race_accounts SET balance = balance - ? '
            'WHERE username = ? AND balance >= ?',
            (amount, sender, amount),
        )
        if c.rowcount != 1:
            conn.rollback()
            return jsonify({'error': 'Insufficient balance or transfer rejected'}), 409

        c.execute('SELECT username FROM race_accounts WHERE username = ?', (recipient,))
        if not c.fetchone() or sender == recipient:
            conn.rollback()
            return jsonify({'error': 'Invalid recipient'}), 400

        c.execute(
            'UPDATE race_accounts SET balance = balance + ? WHERE username = ?',
            (amount, recipient),
        )
        c.execute(
            'INSERT INTO race_transfers (sender, recipient, amount, mode) VALUES (?, ?, ?, ?)',
            (sender, recipient, amount, 'safe'),
        )
        conn.commit()
        c.execute('SELECT balance FROM race_accounts WHERE username = ?', (sender,))
        balance = c.fetchone()['balance']
        return jsonify({
            'status': 'accepted',
            'mode': 'safe',
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
            'sender_balance': balance,
        }), 200
    finally:
        conn.close()


@app.post('/api/race-lab/reset')
@admin_required
def race_lab_reset():
    abort(405)


if __name__=='__main__':
    app.run(host='127.0.0.1',port=int(os.environ.get('BOOKSHOP_PORT','5006')),debug=False)
