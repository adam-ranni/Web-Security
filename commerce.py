"""Server-authoritative prices and serializable purchases/transfers in integer cents."""
from decimal import Decimal, ROUND_HALF_UP
from storage import cents, transaction


def transfer_cents(value):
    result=cents(value)
    if result<=0 or Decimal(str(value))!=Decimal(result)/100:
        raise ValueError('Use a positive amount with at most two decimal places')
    return result


def quote_cart(db,user_id,code=None):
    items=db.execute('SELECT books.*,cart.quantity FROM cart JOIN books ON books.id=cart.book_id WHERE cart.user_id=? ORDER BY books.id',(user_id,)).fetchall()
    if not items or len(items)>50:
        raise ValueError('Cart is empty or too large')
    if any(not 1<=item['quantity']<=100 or item['quantity']>item['stock'] for item in items):
        raise ValueError('Quantity exceeds available stock')
    subtotal=sum(item['price_cents']*item['quantity'] for item in items)
    coupon=None
    if code:
        coupon=db.execute('SELECT * FROM coupons WHERE code=? AND is_active=1 AND current_uses<max_uses',(code,)).fetchone()
        if not coupon:
            raise ValueError('Coupon is invalid or exhausted')
    discount=Decimal(str(coupon['discount_percent'])) if coupon else Decimal(0)
    total=int((Decimal(subtotal)*(100-discount)/100).quantize(Decimal('1'),rounding=ROUND_HALF_UP))
    return items,subtotal,total,coupon


def purchase(path,user_id,code,address):
    with transaction(path) as db:
        items,_,total,coupon=quote_cart(db,user_id,code)
        if db.execute('UPDATE users SET balance_cents=balance_cents-? WHERE id=? AND is_active=1 AND balance_cents>=?',(total,user_id,total)).rowcount!=1:
            raise ValueError('Insufficient balance')
        order_id=db.execute('INSERT INTO orders (user_id,total_cents,shipping_address) VALUES (?,?,?)',(user_id,total,address)).lastrowid
        for item in items:
            if db.execute('UPDATE books SET stock=stock-? WHERE id=? AND stock>=?',(item['quantity'],item['id'],item['quantity'])).rowcount!=1:
                raise ValueError('Stock changed')
            db.execute('INSERT INTO order_items (order_id,book_id,quantity,price_cents) VALUES (?,?,?,?)',(order_id,item['id'],item['quantity'],item['price_cents']))
        if coupon and db.execute('UPDATE coupons SET current_uses=current_uses+1 WHERE id=? AND current_uses<max_uses AND is_active=1',(coupon['id'],)).rowcount!=1:
            raise ValueError('Coupon is exhausted')
        db.execute('DELETE FROM cart WHERE user_id=?',(user_id,))
        return order_id


def transfer(path,sender_id,recipient_name,amount):
    with transaction(path) as db:
        recipient=db.execute('SELECT id FROM users WHERE username=? AND is_active=1',(recipient_name,)).fetchone()
        if not recipient or recipient['id']==sender_id:
            raise ValueError('Invalid recipient')
        if db.execute('UPDATE users SET balance_cents=balance_cents-? WHERE id=? AND is_active=1 AND balance_cents>=?',(amount,sender_id,amount)).rowcount!=1:
            raise ValueError('Insufficient balance')
        if db.execute('UPDATE users SET balance_cents=balance_cents+? WHERE id=? AND balance_cents<=?',(amount,recipient['id'],1000000000-amount)).rowcount!=1:
            raise ValueError('Recipient balance limit exceeded')
