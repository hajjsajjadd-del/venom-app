import os, re, time, sqlite3, secrets, hashlib, hmac
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_from_directory, g
import requests

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get('VENOM_DB_PATH', os.path.join(BASE, 'venom.sqlite3'))
app = Flask(__name__, static_folder=None)
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024
OTP_TTL = int(os.environ.get('OTP_TTL_SECONDS', '300'))
SMS_API_KEY = os.environ.get('KAVENEGAR_API_KEY', '').strip()
SMS_SENDER = os.environ.get('KAVENEGAR_SENDER', '').strip()
DEV_MODE = os.environ.get('VENOM_DEV_OTP', '0') == '1'

def db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_=None):
    conn = g.pop('db', None)
    if conn is not None:
        conn.close()

def init_db():
    with sqlite3.connect(DB_PATH) as con:
        con.executescript('''
        CREATE TABLE IF NOT EXISTS otp_codes(phone TEXT PRIMARY KEY, code_hash TEXT NOT NULL, expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, last_sent INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, phone TEXT UNIQUE NOT NULL, created_at INTEGER NOT NULL, accepted_terms INTEGER NOT NULL DEFAULT 1, status TEXT NOT NULL DEFAULT 'active', suspended_until INTEGER, suspension_reason TEXT, role TEXT NOT NULL DEFAULT 'user');
        CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY AUTOINCREMENT, sender_id INTEGER NOT NULL, recipient_id INTEGER NOT NULL, body TEXT NOT NULL, created_at INTEGER NOT NULL, edited_at INTEGER, deleted_for_all INTEGER NOT NULL DEFAULT 0, read_at INTEGER, FOREIGN KEY(sender_id) REFERENCES users(id), FOREIGN KEY(recipient_id) REFERENCES users(id));
        CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY AUTOINCREMENT, reporter_id INTEGER NOT NULL, target_user_id INTEGER NOT NULL, reason TEXT NOT NULL, created_at INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'open');
        CREATE TABLE IF NOT EXISTS admin_audit(id INTEGER PRIMARY KEY AUTOINCREMENT, admin_phone TEXT NOT NULL, action TEXT NOT NULL, target_user_id INTEGER, details TEXT, created_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id));
        CREATE TABLE IF NOT EXISTS rate_limits(key TEXT PRIMARY KEY, hits INTEGER NOT NULL, window_start INTEGER NOT NULL);
        ''')
        cols = {r[1] for r in con.execute('PRAGMA table_info(users)').fetchall()}
        for name, decl in [('status', "TEXT NOT NULL DEFAULT 'active'"), ('suspended_until', 'INTEGER'), ('suspension_reason', 'TEXT'), ('role', "TEXT NOT NULL DEFAULT 'user'")]:
            if name not in cols:
                con.execute(f'ALTER TABLE users ADD COLUMN {name} {decl}')
        creator_phone = normalize_phone(os.environ.get('VENOM_CREATOR_PHONE', '')) if 'normalize_phone' in globals() else None
        if creator_phone:
            con.execute("UPDATE users SET role='creator' WHERE phone=?", (creator_phone,))

def json_error(message, status=400):
    return jsonify({'ok': False, 'error': message}), status

def normalize_phone(raw):
    value = re.sub(r'[\s()\-]', '', str(raw or ''))
    if value.startswith('00'):
        value = '+' + value[2:]
    if value.startswith('09') and len(value) == 11 and value.isdigit():
        value = '+98' + value[1:]
    if value.startswith('9') and len(value) == 10 and value.isdigit():
        value = '+98' + value
    if not re.fullmatch(r'\+[1-9]\d{7,14}', value):
        return None
    return value

def rate_ok(key, max_hits, seconds):
    now = int(time.time())
    row = db().execute('SELECT hits, window_start FROM rate_limits WHERE key=?', (key,)).fetchone()
    if not row or now - row['window_start'] >= seconds:
        db().execute('INSERT OR REPLACE INTO rate_limits(key,hits,window_start) VALUES(?,?,?)', (key, 1, now)); db().commit(); return True
    if row['hits'] >= max_hits:
        return False
    db().execute('UPDATE rate_limits SET hits=hits+1 WHERE key=?', (key,)); db().commit(); return True

def send_sms(phone, code):
    if not SMS_API_KEY:
        return False, 'سرویس پیامک پیکربندی نشده است.'
    text = f'کد ورود ونوم: {code}'
    url = f'https://api.kavenegar.com/v1/{SMS_API_KEY}/sms/send.json'
    payload = {'receptor': phone.lstrip('+'), 'message': text}
    if SMS_SENDER:
        payload['sender'] = SMS_SENDER
    try:
        res = requests.post(url, data=payload, timeout=12)
        data = res.json()
        if res.ok and data.get('return', {}).get('status') == 200:
            return True, None
        return False, 'ارسال پیامک تأیید نشد.'
    except (requests.RequestException, ValueError):
        return False, 'ارتباط با سرویس پیامک برقرار نشد.'

def current_user():
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return None
    token = auth[7:].strip()
    digest = hashlib.sha256(token.encode()).hexdigest()
    row = db().execute('SELECT users.id, users.phone, users.status, users.suspended_until, users.suspension_reason, users.role FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash=? AND sessions.expires_at>?', (digest, int(time.time()))).fetchone()
    if row and row['status'] == 'suspended' and (row['suspended_until'] is None or row['suspended_until'] > int(time.time())):
        return None
    return row

def require_admin():
    expected = os.environ.get('VENOM_ADMIN_KEY', '').strip()
    supplied = request.headers.get('X-Venom-Admin-Key', '').strip()
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        return None
    return True

def audit(action, target_id=None, details=''):
    db().execute('INSERT INTO admin_audit(admin_phone,action,target_user_id,details,created_at) VALUES(?,?,?,?,?)', ('admin-key', action, target_id, details[:500], int(time.time())))
    db().commit()

@app.get('/')
def index():
    return send_from_directory(BASE, 'index.html')

@app.get('/admin')
def admin_page():
    return send_from_directory(BASE, 'admin.html')

@app.get('/api/health')
def health():
    return jsonify({'ok': True, 'service': 'Venom Auth API', 'sms_configured': bool(SMS_API_KEY), 'mode': 'development' if DEV_MODE else 'production'})

@app.post('/api/auth/request-code')
def request_code():
    payload = request.get_json(silent=True) or {}
    phone = normalize_phone(payload.get('phone'))
    if not phone:
        return json_error('شماره موبایل معتبر وارد کن.')
    ip = request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown').split(',')[0].strip()
    if not rate_ok('ip:' + ip, 10, 3600) or not rate_ok('phone:' + phone, 3, 600):
        return json_error('تعداد درخواست‌ها زیاد است. کمی بعد دوباره تلاش کن.', 429)
    pepper = os.environ.get('OTP_PEPPER', '').strip()
    if not pepper and not DEV_MODE:
        return json_error('تنظیم امنیتی OTP_PEPPER روی سرور تنظیم نشده است.', 503)
    code = f'{secrets.randbelow(1_000_000):06d}'
    now = int(time.time())
    digest = hashlib.sha256((phone + ':' + code + pepper).encode()).hexdigest()
    db().execute('INSERT OR REPLACE INTO otp_codes(phone,code_hash,expires_at,attempts,last_sent) VALUES(?,?,?,?,?)', (phone, digest, now + OTP_TTL, 0, now)); db().commit()
    
    sent, error = send_sms(phone, code)
    if not sent:
        if DEV_MODE and not SMS_API_KEY:
            app.logger.warning('DEV OTP for %s: %s', phone, code)
            return jsonify({'ok': True, 'message': f'کد تایید شما: {code}', 'development': True, 'expires_in': OTP_TTL})
        db().execute('DELETE FROM otp_codes WHERE phone=?', (phone,)); db().commit()
        return json_error(error, 503)
    return jsonify({'ok': True, 'message': 'اگر شماره معتبر باشد، کد تأیید ارسال شد.', 'expires_in': OTP_TTL})

@app.post('/api/auth/verify-code')
def verify_code():
    payload = request.get_json(silent=True) or {}
    phone = normalize_phone(payload.get('phone'))
    code = str(payload.get('code') or '').strip()
    accepted = payload.get('accepted_terms') is True
    if not phone or not re.fullmatch(r'\d{6}', code):
        return json_error('شماره یا کد تأیید معتبر نیست.')
    if not accepted:
        return json_error('برای ادامه باید قوانین را بپذیری.')
    if not rate_ok('verify:' + phone, 8, 900):
        return json_error('تلاش‌های زیادی انجام شده؛ بعداً دوباره امتحان کن.', 429)
    row = db().execute('SELECT * FROM otp_codes WHERE phone=?', (phone,)).fetchone()
    if not row or row['expires_at'] < int(time.time()) or row['attempts'] >= 6:
        return json_error('کد منقضی شده یا دیگر معتبر نیست. کد تازه بگیر.', 400)
    pepper = os.environ.get('OTP_PEPPER', '').strip()
    if not pepper and not DEV_MODE:
        return json_error('تنظیم امنیتی OTP_PEPPER روی سرور تنظیم نشده است.', 503)
    digest = hashlib.sha256((phone + ':' + code + pepper).encode()).hexdigest()
    if not hmac.compare_digest(digest, row['code_hash']):
        db().execute('UPDATE otp_codes SET attempts=attempts+1 WHERE phone=?', (phone,)); db().commit()
        return json_error('کد تأیید اشتباه است.')
    now = int(time.time())
    db().execute('INSERT OR IGNORE INTO users(phone,created_at,accepted_terms) VALUES(?,?,1)', (phone, now))
    user = db().execute('SELECT id,phone FROM users WHERE phone=?', (phone,)).fetchone()
    token = secrets.token_urlsafe(40)
    db().execute('INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)', (hashlib.sha256(token.encode()).hexdigest(), user['id'], now + 60*60*24*30, now))
    db().execute('DELETE FROM otp_codes WHERE phone=?', (phone,)); db().commit()
    return jsonify({'ok': True, 'token': token, 'user': {'id': user['id'], 'phone': user['phone']}, 'expires_in': 60*60*24*30})

@app.get('/api/auth/me')
def me():
    user = current_user()
    if not user:
        return json_error('نشست معتبر نیست؛ دوباره وارد شو.', 401)
    return jsonify({'ok': True, 'user': {'id': user['id'], 'phone': user['phone'], 'role': user['role']}})

@app.post('/api/auth/logout')
def logout():
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        digest = hashlib.sha256(auth[7:].strip().encode()).hexdigest()
        db().execute('DELETE FROM sessions WHERE token_hash=?', (digest,)); db().commit()
    return jsonify({'ok': True})

@app.get('/api/admin/stats')
def admin_stats():
    if not require_admin(): return json_error('کلید مدیریت معتبر نیست.', 401)
    con=db()
    return jsonify({'ok':True,'stats':{
        'users':con.execute('SELECT COUNT(*) FROM users').fetchone()[0],
        'active':con.execute("SELECT COUNT(*) FROM users WHERE status='active'").fetchone()[0],
        'suspended':con.execute("SELECT COUNT(*) FROM users WHERE status='suspended'").fetchone()[0],
        'messages':con.execute('SELECT COUNT(*) FROM messages WHERE deleted_for_all=0').fetchone()[0],
        'open_reports':con.execute("SELECT COUNT(*) FROM reports WHERE status='open'").fetchone()[0]}})

@app.get('/api/admin/users')
def admin_users():
    if not require_admin(): return json_error('کلید مدیریت معتبر نیست.', 401)
    q=(request.args.get('q') or '').strip()[:80]
    rows=db().execute("SELECT id,phone,created_at,status,suspended_until,suspension_reason,role FROM users WHERE phone LIKE ? ORDER BY id DESC LIMIT 200", ('%'+q+'%',)).fetchall()
    return jsonify({'ok':True,'users':[dict(r) for r in rows]})

@app.post('/api/admin/users/<int:user_id>/suspend')
def admin_suspend(user_id):
    if not require_admin(): return json_error('کلید مدیریت معتبر نیست.', 401)
    data=request.get_json(silent=True) or {}
    reason=str(data.get('reason') or '').strip()[:300]
    hours=data.get('hours',24)
    try: hours=int(hours)
    except (TypeError,ValueError): return json_error('مدت تعلیق معتبر نیست.')
    if not reason or hours < 1 or hours > 8760: return json_error('دلیل و مدت تعلیق بین ۱ ساعت تا ۳۶۵ روز لازم است.')
    row=db().execute('SELECT id,role FROM users WHERE id=?',(user_id,)).fetchone()
    if not row: return json_error('کاربر پیدا نشد.',404)
    if row['role']=='creator': return json_error('حساب سازنده قابل تعلیق از این مسیر نیست.',403)
    until=int(time.time())+hours*3600
    db().execute("UPDATE users SET status='suspended',suspended_until=?,suspension_reason=? WHERE id=?",(until,reason,user_id))
    db().execute('DELETE FROM sessions WHERE user_id=?',(user_id,)); audit('suspend',user_id,f'{hours}h: {reason}')
    return jsonify({'ok':True,'message':'حساب تعلیق شد.','suspended_until':until})

@app.post('/api/admin/users/<int:user_id>/unsuspend')
def admin_unsuspend(user_id):
    if not require_admin(): return json_error('کلید مدیریت معتبر نیست.', 401)
    cur=db().execute("UPDATE users SET status='active',suspended_until=NULL,suspension_reason=NULL WHERE id=? AND role!='creator'",(user_id,)); db().commit()
    if cur.rowcount==0: return json_error('حساب پیدا نشد یا قابل تغییر نیست.',404)
    audit('unsuspend',user_id,'manual unsuspend')
    return jsonify({'ok':True,'message':'تعلیق برداشته شد.'})

@app.delete('/api/admin/users/<int:user_id>')
def admin_delete_user(user_id):
    if not require_admin(): return json_error('کلید مدیریت معتبر نیست.', 401)
    row=db().execute('SELECT role FROM users WHERE id=?',(user_id,)).fetchone()
    if not row: return json_error('کاربر پیدا نشد.',404)
    if row['role']=='creator': return json_error('حساب سازنده قابل حذف نیست.',403)
    con=db(); con.execute('DELETE FROM sessions WHERE user_id=?',(user_id,)); con.execute('DELETE FROM otp_codes WHERE phone=(SELECT phone FROM users WHERE id=?)',(user_id,)); con.execute('DELETE FROM messages WHERE sender_id=? OR recipient_id=?',(user_id,user_id)); con.execute('DELETE FROM reports WHERE reporter_id=? OR target_user_id=?',(user_id,user_id)); con.execute('DELETE FROM users WHERE id=?',(user_id,)); audit('delete_user',user_id,'account and related data deleted')
    return jsonify({'ok':True,'message':'حساب و داده‌های وابسته حذف شد.'})

@app.post('/api/reports')
def create_report():
    user=current_user()
    if not user: return json_error('برای گزارش باید وارد شوی.',401)
    data=request.get_json(silent=True) or {}
    try: target=int(data.get('target_user_id'))
    except (TypeError,ValueError): return json_error('شناسه کاربر نامعتبر است.')
    reason=str(data.get('reason') or '').strip()[:500]
    if not reason or target==user['id'] or not db().execute('SELECT 1 FROM users WHERE id=?',(target,)).fetchone(): return json_error('اطلاعات گزارش معتبر نیست.')
    db().execute('INSERT INTO reports(reporter_id,target_user_id,reason,created_at) VALUES(?,?,?,?)',(user['id'],target,reason,int(time.time()))); db().commit()
    return jsonify({'ok':True,'message':'گزارش ثبت شد.'}),201

@app.get('/api/messages')
def get_messages():
    user=current_user()
    if not user: return json_error('نشست معتبر نیست؛ دوباره وارد شو.',401)
    try: other=int(request.args.get('with_user_id',''))
    except ValueError: return json_error('شناسه مخاطب معتبر نیست.')
    rows=db().execute('SELECT id,sender_id,recipient_id,body,created_at,edited_at,read_at FROM messages WHERE ((sender_id=? AND recipient_id=?) OR (sender_id=? AND recipient_id=?)) AND deleted_for_all=0 ORDER BY id DESC LIMIT 200',(user['id'],other,other,user['id'])).fetchall()
    return jsonify({'ok':True,'messages':[dict(r) for r in reversed(rows)]})

@app.post('/api/messages')
def send_message():
    user=current_user()
    if not user: return json_error('نشست معتبر نیست؛ دوباره وارد شو.',401)
    data=request.get_json(silent=True) or {}
    try: recipient=int(data.get('recipient_id'))
    except (TypeError,ValueError): return json_error('شناسه گیرنده معتبر نیست.')
    body=str(data.get('body') or '').strip()
    if not body or len(body)>4000: return json_error('متن پیام باید بین ۱ تا ۴۰۰۰ نویسه باشد.')
    target=db().execute('SELECT id,status,suspended_until FROM users WHERE id=?',(recipient,)).fetchone()
    if not target: return json_error('گیرنده پیدا نشد.',404)
    if target['status']=='suspended' and (target['suspended_until'] is None or target['suspended_until']>int(time.time())): return json_error('ارسال پیام به این حساب ممکن نیست.',403)
    now=int(time.time()); cur=db().execute('INSERT INTO messages(sender_id,recipient_id,body,created_at) VALUES(?,?,?,?)',(user['id'],recipient,body,now)); db().commit()
    return jsonify({'ok':True,'message':{'id':cur.lastrowid,'sender_id':user['id'],'recipient_id':recipient,'body':body,'created_at':now}}),201

@app.post('/api/messages/<int:message_id>/read')
def mark_message_read(message_id):
    user=current_user()
    if not user: return json_error('نشست معتبر نیست.',401)
    db().execute('UPDATE messages SET read_at=? WHERE id=? AND recipient_id=?',(int(time.time()),message_id,user['id'])); db().commit()
    return jsonify({'ok':True})

init_db()

if __name__ == '__main__':
    app.run(host=os.environ.get('HOST', '127.0.0.1'), port=int(os.environ.get('PORT', '5000')), debug=False)
