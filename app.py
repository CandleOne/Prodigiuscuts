from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import sqlite3
import os
import json
import jwt
import bcrypt
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from functools import wraps

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB = os.environ.get('PRODIGIOUS_DB_PATH', os.path.join(BASE_DIR, 'prodigious.db'))
ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@prodigiouscuts.com')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD','admin123')
SECRET = os.environ.get('JWT_SECRET','secret-key')
GOOGLE_PLACES_API_KEY = os.environ.get('GOOGLE_PLACES_API_KEY', '')
GOOGLE_PLACE_ID = os.environ.get('GOOGLE_PLACE_ID', '')

app = Flask(__name__)
CORS(app)

VALID_APPOINTMENT_STATUSES = {'pending', 'confirmed', 'completed', 'cancelled'}
COUPON_CODES = {
    'PCUTS5': 5
}

def get_conn():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS services(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, price INTEGER, description TEXT)''')
    cur.execute('''CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT UNIQUE, phone TEXT, password TEXT, joined TEXT)''')
    cur.execute('''CREATE TABLE IF NOT EXISTS appointments(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT, service TEXT, date TEXT, time TEXT, notes TEXT, status TEXT, created TEXT)''')

    cur.execute('PRAGMA table_info(users)')
    user_columns = {row['name'] for row in cur.fetchall()}
    if 'is_admin' not in user_columns:
        cur.execute('ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0')

    # Lightweight migration for coupon-aware pricing fields.
    cur.execute('PRAGMA table_info(appointments)')
    appointment_columns = {row['name'] for row in cur.fetchall()}
    if 'coupon_code' not in appointment_columns:
        cur.execute('ALTER TABLE appointments ADD COLUMN coupon_code TEXT DEFAULT ""')
    if 'discount_amount' not in appointment_columns:
        cur.execute('ALTER TABLE appointments ADD COLUMN discount_amount INTEGER DEFAULT 0')
    if 'final_price' not in appointment_columns:
        cur.execute('ALTER TABLE appointments ADD COLUMN final_price INTEGER')

    conn.commit()
    # seed services if empty
    cur.execute('SELECT COUNT(*) FROM services')
    if cur.fetchone()[0] == 0:
        services = [
            ('Men\'s Haircut',30,'Precision cut'),
            ('Men\'s Beard & Taper',20,'Beard trim'),
            ('Women\'s Haircut',20,'Haircut'),
            ('Women\'s Cut + Design',25,'Design'),
            ('Kids Cut',15,'Kids under 12'),
            ('Teen Cut',20,'13-18')
        ]
        cur.executemany('INSERT INTO services(name,price,description) VALUES(?,?,?)', services)
        conn.commit()

    admin_password_hash = bcrypt.hashpw(ADMIN_PASSWORD.encode(), bcrypt.gensalt()).decode()
    cur.execute('SELECT id FROM users WHERE email=?', (ADMIN_EMAIL,))
    admin_row = cur.fetchone()
    if admin_row:
        cur.execute('UPDATE users SET name=?, password=?, is_admin=1 WHERE email=?', ('Admin', admin_password_hash, ADMIN_EMAIL))
    else:
        cur.execute(
            'INSERT INTO users(name,email,phone,password,joined,is_admin) VALUES(?,?,?,?,?,?)',
            ('Admin', ADMIN_EMAIL, '', admin_password_hash, datetime.utcnow().isoformat(), 1)
        )
    conn.commit()
    conn.close()

def startup():
    db_dir = os.path.dirname(DB)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
    if not os.path.exists(DB):
        open(DB,'w').close()
    init_db()

startup()

def token_required(f):
    @wraps(f)
    def wrapper(*args,**kwargs):
        auth_header = request.headers.get('Authorization', '')
        token = auth_header.split(' ')[-1] if auth_header else ''
        if not token:
            return jsonify({'error':'Token required'}),401
        try:
            payload = jwt.decode(token, SECRET, algorithms=['HS256'])
            request.user = payload
        except Exception:
            return jsonify({'error':'Invalid token'}),401
        return f(*args,**kwargs)
    return wrapper

@app.route('/')
def serve_home():
    return send_from_directory(BASE_DIR, 'index.html')

@app.route('/<path:path>')
def serve_static_files(path):
    if path.startswith('api/'):
        return jsonify({'error': 'Not found'}), 404
    return send_from_directory(BASE_DIR, path)

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    name = data.get('name'); email = data.get('email'); phone = data.get('phone'); pwd = data.get('password')
    if not all([name,email,pwd]):
        return jsonify({'error':'Missing fields'}),400
    hashed = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt())
    conn = get_conn(); cur = conn.cursor()
    try:
        cur.execute('INSERT INTO users(name,email,phone,password,joined) VALUES(?,?,?,?,?)', (name,email,phone,hashed.decode(), datetime.utcnow().isoformat()))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close(); return jsonify({'error':'Email exists'}),400
    conn.close(); return jsonify({'ok':True}),200

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email'); pwd = data.get('password')
    conn = get_conn(); cur = conn.cursor()
    cur.execute('SELECT id,name,email,password FROM users WHERE email=?', (email,))
    row = cur.fetchone()
    conn.close()
    if not row: return jsonify({'error':'Invalid credentials'}),401
    if not bcrypt.checkpw(pwd.encode(), row['password'].encode()):
        return jsonify({'error':'Invalid credentials'}),401
    token = jwt.encode({'user_id': row['id'], 'exp': datetime.utcnow()+timedelta(hours=12)}, SECRET, algorithm='HS256')
    return jsonify({'token': token, 'user': {'id': row['id'], 'name': row['name'], 'email': row['email']}})

@app.route('/api/services', methods=['GET'])
def services():
    conn = get_conn(); cur = conn.cursor(); cur.execute('SELECT id,name,price,description FROM services'); rows = [dict(r) for r in cur.fetchall()]; conn.close(); return jsonify(rows)

def fetch_google_reviews():
    if not GOOGLE_PLACES_API_KEY or not GOOGLE_PLACE_ID:
        return None, 'Google review verification is not configured.'

    params = urllib.parse.urlencode({
        'place_id': GOOGLE_PLACE_ID,
        'fields': 'reviews',
        'key': GOOGLE_PLACES_API_KEY
    })
    url = 'https://maps.googleapis.com/maps/api/place/details/json?' + params

    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            payload = json.loads(response.read().decode('utf-8'))
    except Exception:
        return None, 'Could not reach Google reviews right now.'

    if payload.get('status') != 'OK':
        return None, 'Google review verification is temporarily unavailable.'

    return payload.get('result', {}).get('reviews', []), None

def calculate_coupon_discount(raw_code, service_price):
    code = (raw_code or '').strip().upper()
    if not code:
        return '', 0
    amount = COUPON_CODES.get(code, 0)
    amount = max(0, min(int(amount), int(service_price)))
    if amount <= 0:
        return '', 0
    return code, amount

@app.route('/api/coupons/validate', methods=['POST'])
def validate_coupon():
    data = request.json or {}
    code = (data.get('code') or '').strip()
    service_name = (data.get('service') or '').strip()

    if not code:
        return jsonify({'valid': False, 'error': 'Enter a coupon code.'}), 400
    if not service_name:
        return jsonify({'valid': False, 'error': 'Select a service first.'}), 400

    conn = get_conn(); cur = conn.cursor()
    cur.execute('SELECT price FROM services WHERE name=?', (service_name,))
    service_row = cur.fetchone()
    conn.close()
    if not service_row:
        return jsonify({'valid': False, 'error': 'Service not found.'}), 404

    normalized_code, discount_amount = calculate_coupon_discount(code, service_row['price'])
    if not normalized_code:
        return jsonify({'valid': False, 'error': 'Invalid coupon code.'}), 400

    final_price = max(0, int(service_row['price']) - discount_amount)
    return jsonify({
        'valid': True,
        'code': normalized_code,
        'discount_amount': discount_amount,
        'service_price': int(service_row['price']),
        'final_price': final_price
    })

@app.route('/api/reviews/verify', methods=['POST'])
@token_required
def verify_review_for_coupon():
    data = request.json or {}
    reviewer_name = (data.get('reviewer_name') or '').strip().lower()
    text_hint = (data.get('text_hint') or '').strip().lower()

    if not reviewer_name:
        return jsonify({'verified': False, 'error': 'Enter the name used on your Google review.'}), 400

    reviews, fetch_error = fetch_google_reviews()
    if fetch_error:
        return jsonify({'verified': False, 'error': fetch_error}), 503

    for review in reviews:
        author_name = (review.get('author_name') or '').strip().lower()
        review_text = (review.get('text') or '').strip().lower()
        name_match = reviewer_name in author_name or author_name in reviewer_name
        text_match = True if not text_hint else text_hint in review_text
        if name_match and text_match:
            code, amount = calculate_coupon_discount('PCUTS5', 9999)
            return jsonify({'verified': True, 'coupon_code': code, 'discount_amount': amount})

    return jsonify({
        'verified': False,
        'error': 'We could not verify that review yet. Google reviews can take a few minutes to appear. Try again shortly.'
    })

@app.route('/api/book', methods=['POST'])
@token_required
def book():
    data = request.json or {}
    user_id = data.get('user_id') or request.user.get('user_id')
    name = data.get('name'); service = data.get('service'); date = data.get('date'); time = data.get('time'); notes = data.get('notes','')
    if not all([name, service, date, time]): return jsonify({'error':'Missing fields'}),400

    conn = get_conn(); cur = conn.cursor()
    cur.execute('SELECT price FROM services WHERE name=?', (service,))
    service_row = cur.fetchone()
    if not service_row:
        conn.close()
        return jsonify({'error': 'Invalid service selected.'}), 400

    base_price = int(service_row['price'])
    coupon_code, discount_amount = calculate_coupon_discount(data.get('coupon_code'), base_price)
    final_price = max(0, base_price - discount_amount)

    cur.execute('''
        INSERT INTO appointments(user_id,name,service,date,time,notes,status,created,coupon_code,discount_amount,final_price)
        VALUES(?,?,?,?,?,?,?,?,?,?,?)
    ''', (user_id,name,service,date,time,notes,'pending', datetime.utcnow().isoformat(),coupon_code,discount_amount,final_price))
    conn.commit(); conn.close()
    return jsonify({'ok':True, 'price': final_price, 'discount_amount': discount_amount, 'coupon_code': coupon_code})

@app.route('/api/appointments', methods=['GET'])
@token_required
def my_appointments():
    user_id = request.user.get('user_id')
    conn = get_conn(); cur = conn.cursor(); cur.execute('''
        SELECT appointments.*, COALESCE(appointments.final_price, services.price) AS price, services.price AS base_price
        FROM appointments
        LEFT JOIN services ON services.name = appointments.service
        WHERE appointments.user_id=?
        ORDER BY appointments.date DESC, appointments.time DESC
    ''', (user_id,)); rows = [dict(r) for r in cur.fetchall()]; conn.close(); return jsonify(rows)

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization', '').split(' ')[-1]
        if not token:
            return jsonify({'error': 'Admin token required'}), 401
        try:
            payload = jwt.decode(token, SECRET, algorithms=['HS256'])
            if not payload.get('is_admin'):
                raise Exception('Not admin')
            request.admin = payload
        except Exception:
            return jsonify({'error': 'Invalid or expired admin token'}), 401
        return f(*args, **kwargs)
    return wrapper

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    data = request.json or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    conn = get_conn(); cur = conn.cursor()
    cur.execute('SELECT id,name,email,password,is_admin FROM users WHERE email=?', (email,))
    row = cur.fetchone()
    conn.close()
    if not row or not row['is_admin']:
        return jsonify({'error': 'Admin account not found'}), 401
    if not bcrypt.checkpw(password.encode(), row['password'].encode()):
        return jsonify({'error': 'Wrong password'}), 401

    token = jwt.encode({'is_admin': True, 'admin_user_id': row['id'], 'admin_email': row['email'], 'exp': datetime.utcnow() + timedelta(hours=12)}, SECRET, algorithm='HS256')
    return jsonify({'token': token, 'admin': {'id': row['id'], 'name': row['name'], 'email': row['email']}})

@app.route('/api/admin/appointments', methods=['GET'])
@admin_required
def admin_appointments():
    conn = get_conn(); cur = conn.cursor(); cur.execute('''
        SELECT appointments.*, COALESCE(appointments.final_price, services.price) AS price, services.price AS base_price, users.phone AS phone, users.email AS email
        FROM appointments
        LEFT JOIN services ON services.name = appointments.service
        LEFT JOIN users ON users.id = appointments.user_id
        ORDER BY appointments.date DESC, appointments.time DESC
    '''); rows=[dict(r) for r in cur.fetchall()]; conn.close(); return jsonify(rows)

@app.route('/api/admin/stats', methods=['GET'])
@admin_required
def admin_stats():
    today = datetime.utcnow().strftime('%Y-%m-%d')
    conn = get_conn(); cur = conn.cursor()
    cur.execute('SELECT COUNT(*) AS total FROM appointments')
    total = cur.fetchone()['total']
    cur.execute('SELECT COUNT(*) AS pending FROM appointments WHERE status=?', ('pending',))
    pending = cur.fetchone()['pending']
    cur.execute('SELECT COUNT(*) AS today_count FROM appointments WHERE date=?', (today,))
    today_count = cur.fetchone()['today_count']
    cur.execute('SELECT COUNT(*) AS clients FROM users')
    clients = cur.fetchone()['clients']
    conn.close()
    return jsonify({
        'total_bookings': total,
        'pending_bookings': pending,
        'today_bookings': today_count,
        'clients': clients
    })

@app.route('/api/admin/reviews/status', methods=['GET'])
@admin_required
def admin_reviews_status():
    configured = bool(GOOGLE_PLACES_API_KEY and GOOGLE_PLACE_ID)
    if not configured:
        return jsonify({
            'configured': False,
            'api_reachable': False,
            'message': 'Missing GOOGLE_PLACES_API_KEY or GOOGLE_PLACE_ID.'
        })

    reviews, error = fetch_google_reviews()
    if error:
        return jsonify({
            'configured': True,
            'api_reachable': False,
            'message': error
        })

    return jsonify({
        'configured': True,
        'api_reachable': True,
        'message': 'Google review verification is connected.',
        'review_count_sample': len(reviews)
    })

@app.route('/api/admin/services', methods=['GET', 'POST'])
@admin_required
def admin_services():
    conn = get_conn(); cur = conn.cursor()
    if request.method == 'GET':
        cur.execute('SELECT id,name,price,description FROM services ORDER BY name ASC')
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return jsonify(rows)

    data = request.json or {}
    name = (data.get('name') or '').strip()
    description = (data.get('description') or '').strip()
    try:
        price = int(data.get('price'))
    except Exception:
        conn.close()
        return jsonify({'error': 'Price must be a number'}), 400

    if not name:
        conn.close()
        return jsonify({'error': 'Service name is required'}), 400

    cur.execute('INSERT INTO services(name,price,description) VALUES(?,?,?)', (name, price, description))
    conn.commit()
    service_id = cur.lastrowid
    conn.close()
    return jsonify({'ok': True, 'id': service_id}), 201

@app.route('/api/admin/services/<int:sid>', methods=['PUT', 'DELETE'])
@admin_required
def admin_service_update(sid):
    conn = get_conn(); cur = conn.cursor()
    if request.method == 'DELETE':
        cur.execute('DELETE FROM services WHERE id=?', (sid,))
        conn.commit()
        deleted = cur.rowcount
        conn.close()
        if not deleted:
            return jsonify({'error': 'Service not found'}), 404
        return jsonify({'ok': True})

    data = request.json or {}
    name = (data.get('name') or '').strip()
    description = (data.get('description') or '').strip()
    try:
        price = int(data.get('price'))
    except Exception:
        conn.close()
        return jsonify({'error': 'Price must be a number'}), 400

    if not name:
        conn.close()
        return jsonify({'error': 'Service name is required'}), 400

    cur.execute('UPDATE services SET name=?, price=?, description=? WHERE id=?', (name, price, description, sid))
    conn.commit()
    updated = cur.rowcount
    conn.close()
    if not updated:
        return jsonify({'error': 'Service not found'}), 404
    return jsonify({'ok': True})

@app.route('/api/admin/clients', methods=['GET'])
@admin_required
def admin_clients():
    conn = get_conn(); cur = conn.cursor(); cur.execute('SELECT id,name,email,phone,joined FROM users ORDER BY joined DESC'); rows=[dict(r) for r in cur.fetchall()]; conn.close(); return jsonify(rows)

@app.route('/api/admin/appointments/<int:aid>', methods=['PUT','DELETE'])
@admin_required
def admin_update(aid):
    if request.method=='PUT':
        status = (request.json or {}).get('status', '').strip().lower()
        if status not in VALID_APPOINTMENT_STATUSES:
            return jsonify({'error': 'Invalid status'}), 400
        conn = get_conn(); cur=conn.cursor(); cur.execute('UPDATE appointments SET status=? WHERE id=?',(status,aid)); conn.commit(); updated = cur.rowcount; conn.close()
        if not updated:
            return jsonify({'error': 'Appointment not found'}), 404
        return jsonify({'ok':True})
    else:
        conn = get_conn(); cur=conn.cursor(); cur.execute('DELETE FROM appointments WHERE id=?',(aid,)); conn.commit(); deleted = cur.rowcount; conn.close()
        if not deleted:
            return jsonify({'error': 'Appointment not found'}), 404
        return jsonify({'ok':True})

@app.route('/api/appointments/<int:aid>/cancel', methods=['PUT'])
@token_required
def cancel_appointment(aid):
    user_id = request.user.get('user_id')
    conn = get_conn(); cur = conn.cursor()
    cur.execute('SELECT id FROM appointments WHERE id=? AND user_id=?', (aid, user_id))
    if not cur.fetchone():
        conn.close(); return jsonify({'error': 'Not found'}), 404
    cur.execute('UPDATE appointments SET status=? WHERE id=?', ('cancelled', aid))
    conn.commit(); conn.close()
    return jsonify({'ok': True})

@app.route('/api/profile', methods=['PUT'])
@token_required
def update_profile():
    user_id = request.user.get('user_id')
    data = request.json or {}
    name = data.get('name', ''); phone = data.get('phone', '')
    conn = get_conn(); cur = conn.cursor()
    cur.execute('UPDATE users SET name=?, phone=? WHERE id=?', (name, phone, user_id))
    conn.commit(); conn.close()
    return jsonify({'ok': True})

if __name__=='__main__':
    app.run(host='0.0.0.0', debug=True, port=5000)
