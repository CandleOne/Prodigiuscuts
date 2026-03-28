from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import sqlite3
import os
import jwt
import bcrypt
from datetime import datetime, timedelta
from functools import wraps

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB = os.environ.get('PRODIGIOUS_DB_PATH', os.path.join(BASE_DIR, 'prodigious.db'))
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD','admin123')
SECRET = os.environ.get('JWT_SECRET','secret-key')

app = Flask(__name__)
CORS(app)

VALID_APPOINTMENT_STATUSES = {'pending', 'confirmed', 'completed', 'cancelled'}

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

@app.route('/api/book', methods=['POST'])
@token_required
def book():
    data = request.json
    user_id = data.get('user_id') or request.user.get('user_id')
    name = data.get('name'); service = data.get('service'); date = data.get('date'); time = data.get('time'); notes = data.get('notes','')
    if not all([name, service, date, time]): return jsonify({'error':'Missing fields'}),400
    conn = get_conn(); cur = conn.cursor()
    cur.execute('INSERT INTO appointments(user_id,name,service,date,time,notes,status,created) VALUES(?,?,?,?,?,?,?,?)', (user_id,name,service,date,time,notes,'pending', datetime.utcnow().isoformat()))
    conn.commit(); conn.close()
    return jsonify({'ok':True})

@app.route('/api/appointments', methods=['GET'])
@token_required
def my_appointments():
    user_id = request.user.get('user_id')
    conn = get_conn(); cur = conn.cursor(); cur.execute('''
        SELECT appointments.*, services.price AS price
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
    if data.get('password') != ADMIN_PASSWORD:
        return jsonify({'error': 'Wrong password'}), 401
    token = jwt.encode({'is_admin': True, 'exp': datetime.utcnow() + timedelta(hours=12)}, SECRET, algorithm='HS256')
    return jsonify({'token': token})

@app.route('/api/admin/appointments', methods=['GET'])
@admin_required
def admin_appointments():
    conn = get_conn(); cur = conn.cursor(); cur.execute('''
        SELECT appointments.*, services.price AS price, users.phone AS phone, users.email AS email
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
