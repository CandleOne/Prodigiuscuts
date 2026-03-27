from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import os
import jwt
import bcrypt
from datetime import datetime, timedelta

DB = '/home/john/.openclaw/workspace/OurPage/websitepreviews/ProdigiousCuts/prodigious.db'
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD','admin123')
SECRET = os.environ.get('JWT_SECRET','secret-key')

app = Flask(__name__)
CORS(app)

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

@app.before_first_request
def startup():
    if not os.path.exists(DB):
        open(DB,'w').close()
    init_db()

def token_required(f):
    def wrapper(*args,**kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error':'Token required'}),401
        try:
            payload = jwt.decode(token.split(' ')[-1], SECRET, algorithms=['HS256'])
            request.user = payload
        except Exception as e:
            return jsonify({'error':'Invalid token'}),401
        return f(*args,**kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

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
    conn = get_conn(); cur = conn.cursor(); cur.execute('SELECT * FROM appointments WHERE user_id=?', (user_id,)); rows = [dict(r) for r in cur.fetchall()]; conn.close(); return jsonify(rows)

def admin_required(f):
    from functools import wraps
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
    conn = get_conn(); cur = conn.cursor(); cur.execute('SELECT * FROM appointments ORDER BY date DESC, time DESC'); rows=[dict(r) for r in cur.fetchall()]; conn.close(); return jsonify(rows)

@app.route('/api/admin/clients', methods=['GET'])
@admin_required
def admin_clients():
    conn = get_conn(); cur = conn.cursor(); cur.execute('SELECT id,name,email,phone,joined FROM users ORDER BY joined DESC'); rows=[dict(r) for r in cur.fetchall()]; conn.close(); return jsonify(rows)

@app.route('/api/admin/appointments/<int:aid>', methods=['PUT','DELETE'])
@admin_required
def admin_update(aid):
    if request.method=='PUT':
        status = request.json.get('status','')
        conn = get_conn(); cur=conn.cursor(); cur.execute('UPDATE appointments SET status=? WHERE id=?',(status,aid)); conn.commit(); conn.close(); return jsonify({'ok':True})
    else:
        conn = get_conn(); cur=conn.cursor(); cur.execute('DELETE FROM appointments WHERE id=?',(aid,)); conn.commit(); conn.close(); return jsonify({'ok':True})

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
    app.run(debug=True, port=5000)
