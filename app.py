import os, re, time, sqlite3, secrets, hashlib, hmac
from pathlib import Path
from flask import Flask, request, jsonify, send_from_directory, g
import requests

BASE = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get('VENOM_DB_PATH', str(BASE / 'data' / 'venom.sqlite3')))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
app = Flask(__name__, static_folder=None)
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024
OTP_TTL = max(60, min(int(os.environ.get('OTP_TTL_SECONDS', '300')), 900))
SMS_API_KEY = os.environ.get('KAVENEGAR_API_KEY', '').strip()
SMS_SENDER = os.environ.get('KAVENEGAR_SENDER', '').strip()
DEV_MODE = os.environ.get('VENOM_DEV_OTP', '0') == '1'


def db():
    if 'db' not in g:
        con = sqlite3.connect(str(DB_PATH), timeout=20)
        con.row_factory = sqlite3.Row
        con.execute('PRAGMA foreign_keys=ON')
        g.db = con
    return g.db

@app.teardown_appcontext
def close_db(_=None):
    con = g.pop('db', None)
    if con is not None: con.close()


def normalize_phone(raw):
    value = re.sub(r'[\s()\-]', '', str(raw or ''))
    if value.startswith('00'): value = '+' + value[2:]
    if value.startswith('09') and len(value) == 11 and value.isdigit(): value = '+98' + value[1:]
    if value.startswith('9') and len(value) == 10 and value.isdigit(): value = '+98' + value
    return value if re.fullmatch(r'\+[1-9]\d{7,14}', value) else None


def init_db():
    with sqlite3.connect(str(DB_PATH), timeout=20) as con:
        con.execute('PRAGMA journal_mode=WAL')
        con.execute('PRAGMA foreign_keys=ON')
        con.executescript('''
        CREATE TABLE IF NOT EXISTS otp_codes(phone TEXT PRIMARY KEY, code_hash TEXT NOT NULL, expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, last_sent INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, phone TEXT UNIQUE NOT NULL, created_at INTEGER NOT NULL, accepted_terms INTEGER NOT NULL DEFAULT 1, status TEXT NOT NULL DEFAULT 'active', suspended_until INTEGER, suspension_reason TEXT, role TEXT NOT NULL DEFAULT 'user', display_name TEXT NOT NULL DEFAULT '');
        CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY AUTOINCREMENT, sender_id INTEGER NOT NULL, recipient_id INTEGER NOT NULL, body TEXT NOT NULL, created_at INTEGER NOT NULL, edited_at INTEGER, deleted_for_all INTEGER NOT NULL DEFAULT 0, read_at INTEGER, FOREIGN KEY(sender_id) REFERENCES users(id), FOREIGN KEY(recipient_id) REFERENCES users(id));
        CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY AUTOINCREMENT, reporter_id INTEGER NOT NULL, target_user_id INTEGER NOT NULL, reason TEXT NOT NULL, created_at INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'open');
        CREATE TABLE IF NOT EXISTS admin_audit(id INTEGER PRIMARY KEY AUTOINCREMENT, admin_phone TEXT NOT NULL, action TEXT NOT NULL, target_user_id INTEGER, details TEXT, created_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS rate_limits(key TEXT PRIMARY KEY, hits INTEGER NOT NULL, window_start INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_messages_pair ON messages(sender_id,recipient_id,id);
        CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
        ''')
        cols = {r[1] for r in con.execute('PRAGMA table_info(users)')}
        if 'display_name' not in cols: con.execute("ALTER TABLE users ADD COLUMN display_name TEXT NOT NULL DEFAULT ''")
        creator = normalize_phone(os.environ.get('VENOM_CREATOR_PHONE', ''))
        if creator: con.execute("UPDATE users SET role='creator' WHERE phone=?", (creator,))
        # Expired suspensions are restored on startup; the request middleware also handles them lazily.
        con.execute("UPDATE users SET status='active', suspended_until=NULL, suspension_reason=NULL WHERE status='suspended' AND suspended_until IS NOT NULL AND suspended_until<=?", (int(time.time()),))


def error(message, status=400): return jsonify({'ok': False, 'error': message}), status

def rate_ok(key, max_hits, seconds):
    now = int(time.time()); con = db()
    row = con.execute('SELECT hits,window_start FROM rate_limits WHERE key=?', (key,)).fetchone()
    if not row or now-row['window_start'] >= seconds:
        con.execute('INSERT OR REPLACE INTO rate_limits(key,hits,window_start) VALUES(?,?,?)', (key,1,now)); con.commit(); return True
    if row['hits'] >= max_hits: return False
    con.execute('UPDATE rate_limits SET hits=hits+1 WHERE key=?', (key,)); con.commit(); return True


def send_sms(phone, code):
    if not SMS_API_KEY: return False, 'سرویس پیامک تنظیم نشده است؛ KAVENEGAR_API_KEY را در تنظیمات امن هاست وارد کن.'
    payload = {'receptor': phone.lstrip('+'), 'message': f'کد ورود ونوم: {code}\nاین کد را در اختیار هیچ‌کس قرار نده.'}
    if SMS_SENDER: payload['sender'] = SMS_SENDER
    try:
        res = requests.post(f'https://api.kavenegar.com/v1/{SMS_API_KEY}/sms/send.json', data=payload, timeout=12)
        data = res.json()
        if res.ok and data.get('return', {}).get('status') == 200: return True, None
        app.logger.warning('SMS provider rejected request: HTTP %s', res.status_code)
        return False, 'سرویس پیامک ارسال را تأیید نکرد؛ کلید، اعتبار و دسترسی ارسال را بررسی کن.'
    except (requests.RequestException, ValueError): return False, 'ارتباط با سرویس پیامک برقرار نشد؛ دوباره تلاش کن.'


def current_user():
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '): return None
    token = auth[7:].strip()
    if len(token) < 32: return None
    digest = hashlib.sha256(token.encode()).hexdigest(); now = int(time.time())
    row = db().execute('''SELECT u.id,u.phone,u.status,u.suspended_until,u.suspension_reason,u.role,u.display_name,s.token_hash
        FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?''', (digest,now)).fetchone()
    if not row: return None
    if row['status']=='suspended':
        if row['suspended_until'] is None or row['suspended_until'] > now: return None
        db().execute("UPDATE users SET status='active',suspended_until=NULL,suspension_reason=NULL WHERE id=?", (row['id'],)); db().commit()
    return row


def require_admin():
    expected = os.environ.get('VENOM_ADMIN_KEY', '').strip()
    supplied = request.headers.get('X-Venom-Admin-Key', '').strip()
    return bool(expected and len(expected) >= 32 and supplied and hmac.compare_digest(expected, supplied))

def audit(action, target_id=None, details=''):
    db().execute('INSERT INTO admin_audit(admin_phone,action,target_user_id,details,created_at) VALUES(?,?,?,?,?)', ('admin-key',action,target_id,details[:500],int(time.time())))
    db().commit()

@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['Referrer-Policy']='strict-origin-when-cross-origin'
    response.headers['X-Frame-Options']='DENY'
    response.headers['Permissions-Policy']='camera=(), microphone=(), geolocation=()'
    if request.path.startswith('/api/'): response.headers['Cache-Control']='no-store'
    return response

@app.get('/')
def index(): return send_from_directory(str(BASE), 'index.html')
@app.get('/admin')
def admin_page(): return send_from_directory(str(BASE), 'admin.html')
@app.get('/api/health')
def health(): return jsonify({'ok':True,'service':'Venom','sms_configured':bool(SMS_API_KEY),'dev_mode':DEV_MODE})

@app.post('/api/auth/request-code')
def request_code():
    data=request.get_json(silent=True) or {}; phone=normalize_phone(data.get('phone'))
    if not phone: return error('شماره موبایل معتبر وارد کن.')
    ip=request.remote_addr or 'unknown'
    if not rate_ok('ip:'+ip, 10, 3600) or not rate_ok('phone:'+phone, 3, 600): return error('تعداد درخواست‌ها زیاد است؛ کمی بعد دوباره تلاش کن.',429)
    pepper=os.environ.get('OTP_PEPPER','').strip()
    if not pepper and not DEV_MODE: return error('تنظیم امنیتی OTP_PEPPER روی سرور تنظیم نشده است.',503)
    code=f'{secrets.randbelow(1000000):06d}'; now=int(time.time())
    digest=hashlib.sha256((phone+':'+code+pepper).encode()).hexdigest()
  db().execute('INSERT OR REPLACE INTO otp_codes(phone, code_hash, expires_at, attempts, last_sent) VALUES(?, ?, ?, ?, ?)', (phone, digest, now + OTP_TTL, 0, now))
db().commit()

sent, error = send_sms(phone, code)
if not sent:
    if DEV_MODE and not SMS_API_KEY:
        app.logger.warning('DEV OTP for %s: %s', phone, code)
        return jsonify({'ok': True, 'message': f'کد تایید شما: {code}', 'development': True, 'expires_in': OTP_TTL})
    db().execute('DELETE FROM otp_codes WHERE phone=?', (phone,))
    db().commit()
    return json_error(error, 503)

return jsonify({'ok': True, 'message': 'اگر شماره معتبر باشد، کد تأیید ارسال شد.', 'expires_in': OTP_TTL})
@app.post('/api/auth/verify-code')
def verify_code():
    data=request.get_json(silent=True) or {}; phone=normalize_phone(data.get('phone')); code=str(data.get('code') or '').strip()
    if not phone or not re.fullmatch(r'\d{6}',code): return error('شماره یا کد معتبر نیست.')
    if data.get('accepted_terms') is not True: return error('برای ادامه باید قوانین را بپذیری.')
    if not rate_ok('verify:'+phone,8,900): return error('تلاش‌های زیادی انجام شده؛ بعداً دوباره امتحان کن.',429)
    row=db().execute('SELECT * FROM otp_codes WHERE phone=?',(phone,)).fetchone(); now=int(time.time())
    if not row or row['expires_at'] < now or row['attempts'] >= 6: return error('کد منقضی شده یا دیگر معتبر نیست؛ کد تازه بگیر.')
    pepper=os.environ.get('OTP_PEPPER','').strip()
    if not pepper and not DEV_MODE: return error('تنظیم امنیتی OTP_PEPPER روی سرور تنظیم نشده است.',503)
    digest=hashlib.sha256((phone+':'+code+pepper).encode()).hexdigest()
    if not hmac.compare_digest(digest,row['code_hash']):
        db().execute('UPDATE otp_codes SET attempts=attempts+1 WHERE phone=?',(phone,)); db().commit(); return error('کد تأیید اشتباه است.')
    creator=normalize_phone(os.environ.get('VENOM_CREATOR_PHONE',''))
    db().execute('INSERT OR IGNORE INTO users(phone,created_at,accepted_terms,role,display_name) VALUES(?,?,1,?,?)',(phone,now,'creator' if creator and phone==creator else 'user',''))
    user=db().execute('SELECT id,phone,status,role,display_name FROM users WHERE phone=?',(phone,)).fetchone()
    if user['status']=='suspended' and (user['suspended_until'] is None or user['suspended_until']>now): return error('این حساب موقتاً تعلیق شده است.',403)
    if user['status']=='suspended': db().execute("UPDATE users SET status='active',suspended_until=NULL,suspension_reason=NULL WHERE id=?",(user['id'],))
    token=secrets.token_urlsafe(48)
    db().execute('INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),user['id'],now+60*60*24*30,now))
    db().execute('DELETE FROM otp_codes WHERE phone=?',(phone,)); db().commit()
    return jsonify({'ok':True,'token':token,'user':{'id':user['id'],'phone':user['phone'],'role':user['role'],'display_name':user['display_name']},'expires_in':2592000})

@app.get('/api/auth/me')
def me():
    u=current_user()
    if not u:return error('نشست معتبر نیست؛ دوباره وارد شو.',401)
    return jsonify({'ok':True,'user':{'id':u['id'],'phone':u['phone'],'role':u['role'],'display_name':u['display_name']}})

@app.post('/api/auth/logout')
def logout():
    auth=request.headers.get('Authorization','')
    if auth.startswith('Bearer '): db().execute('DELETE FROM sessions WHERE token_hash=?',(hashlib.sha256(auth[7:].strip().encode()).hexdigest(),)); db().commit()
    return jsonify({'ok':True})

@app.patch('/api/profile')
def update_profile():
    u=current_user()
    if not u:return error('برای ادامه وارد شو.',401)
    data=request.get_json(silent=True) or {}; name=str(data.get('display_name') or '').strip()
    if len(name)>40:return error('نام نمایشی حداکثر ۴۰ نویسه باشد.')
    db().execute('UPDATE users SET display_name=? WHERE id=?',(name,u['id'])); db().commit()
    return jsonify({'ok':True,'display_name':name})

@app.get('/api/users')
def users_search():
    u=current_user()
    if not u:return error('برای جست‌وجو وارد شو.',401)
    q=(request.args.get('q') or '').strip()[:80]
    if len(q)<3:return jsonify({'ok':True,'users':[]})
    phone=normalize_phone(q)
    if phone: rows=db().execute("SELECT id,phone,display_name,role FROM users WHERE id!=? AND phone=? AND status='active' LIMIT 30",(u['id'],phone)).fetchall()
    else: rows=db().execute("SELECT id,phone,display_name,role FROM users WHERE id!=? AND phone LIKE ? AND status='active' ORDER BY id DESC LIMIT 30",(u['id'],'%'+q+'%')).fetchall()
    return jsonify({'ok':True,'users':[dict(x) for x in rows]})

@app.get('/api/chats')
def chats():
    u=current_user()
    if not u:return error('برای ادامه وارد شو.',401)
    rows=db().execute('''SELECT other.id,other.phone,other.display_name,other.role,
      (SELECT body FROM messages m WHERE ((m.sender_id=? AND m.recipient_id=other.id) OR (m.sender_id=other.id AND m.recipient_id=?)) AND m.deleted_for_all=0 ORDER BY m.id DESC LIMIT 1) last_message,
      (SELECT created_at FROM messages m WHERE ((m.sender_id=? AND m.recipient_id=other.id) OR (m.sender_id=other.id AND m.recipient_id=?)) AND m.deleted_for_all=0 ORDER BY m.id DESC LIMIT 1) last_at,
      (SELECT COUNT(*) FROM messages m WHERE m.sender_id=other.id AND m.recipient_id=? AND m.read_at IS NULL AND m.deleted_for_all=0) unread
      FROM users other WHERE other.id!=? AND other.status='active' AND EXISTS(SELECT 1 FROM messages m WHERE (m.sender_id=? AND m.recipient_id=other.id) OR (m.sender_id=other.id AND m.recipient_id=?))
      ORDER BY last_at DESC''',(u['id'],u['id'],u['id'],u['id'],u['id'],u['id'],u['id'],u['id'])).fetchall()
    return jsonify({'ok':True,'chats':[dict(x) for x in rows]})

@app.get('/api/messages')
def get_messages():
    u=current_user()
    if not u:return error('نشست معتبر نیست؛ دوباره وارد شو.',401)
    try: other=int(request.args.get('with_user_id',''))
    except ValueError:return error('شناسه مخاطب معتبر نیست.')
    if other==u['id'] or not db().execute("SELECT 1 FROM users WHERE id=? AND status='active'",(other,)).fetchone():return error('مخاطب در دسترس نیست.',404)
    try: after=max(0,int(request.args.get('after','0')))
    except ValueError: after=0
    rows=db().execute('''SELECT id,sender_id,recipient_id,body,created_at,edited_at,read_at FROM messages
      WHERE ((sender_id=? AND recipient_id=?) OR (sender_id=? AND recipient_id=?)) AND deleted_for_all=0 AND id>?
      ORDER BY id ASC LIMIT 200''',(u['id'],other,other,u['id'],after)).fetchall()
    db().execute('UPDATE messages SET read_at=? WHERE sender_id=? AND recipient_id=? AND read_at IS NULL',(int(time.time()),other,u['id'])); db().commit()
    return jsonify({'ok':True,'messages':[dict(x) for x in rows]})

@app.post('/api/messages')
def send_message():
    u=current_user()
    if not u:return error('نشست معتبر نیست؛ دوباره وارد شو.',401)
    data=request.get_json(silent=True) or {}
    try: recipient=int(data.get('recipient_id'))
    except (TypeError,ValueError):return error('شناسه گیرنده معتبر نیست.')
    body=str(data.get('body') or '').strip()
    if not body or len(body)>4000:return error('متن پیام باید بین ۱ تا ۴۰۰۰ نویسه باشد.')
    if recipient==u['id']:return error('نمی‌توانی به خودت پیام بدهی.')
    target=db().execute('SELECT id,status,suspended_until FROM users WHERE id=?',(recipient,)).fetchone()
    if not target:return error('گیرنده پیدا نشد.',404)
    now=int(time.time())
    if target['status']=='suspended' and (target['suspended_until'] is None or target['suspended_until']>now):return error('ارسال پیام به این حساب ممکن نیست.',403)
    cur=db().execute('INSERT INTO messages(sender_id,recipient_id,body,created_at) VALUES(?,?,?,?)',(u['id'],recipient,body,now));db().commit()
    return jsonify({'ok':True,'message':{'id':cur.lastrowid,'sender_id':u['id'],'recipient_id':recipient,'body':body,'created_at':now,'read_at':None}}),201

@app.patch('/api/messages/<int:message_id>')
def edit_message(message_id):
    u=current_user()
    if not u:return error('برای ادامه وارد شو.',401)
    data=request.get_json(silent=True) or {}; body=str(data.get('body') or '').strip()
    if not body or len(body)>4000:return error('متن پیام معتبر نیست.')
    row=db().execute('SELECT id,created_at FROM messages WHERE id=? AND sender_id=? AND deleted_for_all=0',(message_id,u['id'])).fetchone()
    if not row:return error('پیام پیدا نشد یا متعلق به تو نیست.',404)
    if int(time.time())-row['created_at']>86400:return error('ویرایش پیام پس از ۲۴ ساعت مجاز نیست.',403)
    db().execute('UPDATE messages SET body=?,edited_at=? WHERE id=?',(body,int(time.time()),message_id));db().commit()
    return jsonify({'ok':True})

@app.delete('/api/messages/<int:message_id>')
def delete_message(message_id):
    u=current_user()
    if not u:return error('برای ادامه وارد شو.',401)
    cur=db().execute('UPDATE messages SET deleted_for_all=1,body=? WHERE id=? AND sender_id=? AND deleted_for_all=0',('[پیام حذف شد]',message_id,u['id']));db().commit()
    if not cur.rowcount:return error('پیام پیدا نشد یا متعلق به تو نیست.',404)
    return jsonify({'ok':True})

@app.post('/api/reports')
def create_report():
    u=current_user()
    if not u:return error('برای گزارش وارد شو.',401)
    data=request.get_json(silent=True) or {}
    try: target=int(data.get('target_user_id'))
    except (TypeError,ValueError):return error('شناسه کاربر نامعتبر است.')
    reason=str(data.get('reason') or '').strip()[:500]
    if not reason or target==u['id'] or not db().execute('SELECT 1 FROM users WHERE id=?',(target,)).fetchone():return error('اطلاعات گزارش معتبر نیست.')
    db().execute('INSERT INTO reports(reporter_id,target_user_id,reason,created_at) VALUES(?,?,?,?)',(u['id'],target,reason,int(time.time())));db().commit()
    return jsonify({'ok':True,'message':'گزارش ثبت شد.'}),201

@app.get('/api/admin/stats')
def admin_stats():
    if not require_admin():return error('کلید مدیریت معتبر نیست.',401)
    c=db();return jsonify({'ok':True,'stats':{'users':c.execute('SELECT COUNT(*) FROM users').fetchone()[0],'active':c.execute("SELECT COUNT(*) FROM users WHERE status='active'").fetchone()[0],'suspended':c.execute("SELECT COUNT(*) FROM users WHERE status='suspended'").fetchone()[0],'messages':c.execute('SELECT COUNT(*) FROM messages WHERE deleted_for_all=0').fetchone()[0],'open_reports':c.execute("SELECT COUNT(*) FROM reports WHERE status='open'").fetchone()[0]}})

@app.get('/api/admin/users')
def admin_users():
    if not require_admin():return error('کلید مدیریت معتبر نیست.',401)
    q=(request.args.get('q') or '').strip()[:80]
    rows=db().execute('SELECT id,phone,created_at,status,suspended_until,suspension_reason,role,display_name FROM users WHERE phone LIKE ? ORDER BY id DESC LIMIT 200',('%'+q+'%',)).fetchall()
    return jsonify({'ok':True,'users':[dict(r) for r in rows]})

@app.post('/api/admin/users/<int:user_id>/suspend')
def admin_suspend(user_id):
    if not require_admin():return error('کلید مدیریت معتبر نیست.',401)
    data=request.get_json(silent=True) or {};reason=str(data.get('reason') or '').strip()[:300]
    try: hours=int(data.get('hours',24))
    except (TypeError,ValueError):return error('مدت تعلیق معتبر نیست.')
    if not reason or hours<1 or hours>8760:return error('دلیل و مدت تعلیق بین ۱ ساعت تا ۳۶۵ روز لازم است.')
    row=db().execute('SELECT id,role FROM users WHERE id=?',(user_id,)).fetchone()
    if not row:return error('کاربر پیدا نشد.',404)
    if row['role'] in ('creator','admin'):return error('حساب سازنده یا مدیر قابل تعلیق نیست.',403)
    until=int(time.time())+hours*3600
    db().execute("UPDATE users SET status='suspended',suspended_until=?,suspension_reason=? WHERE id=?",(until,reason,user_id));db().execute('DELETE FROM sessions WHERE user_id=?',(user_id,));audit('suspend',user_id,f'{hours}h: {reason}')
    return jsonify({'ok':True,'message':'حساب تعلیق شد.','suspended_until':until})

@app.post('/api/admin/users/<int:user_id>/unsuspend')
def admin_unsuspend(user_id):
    if not require_admin():return error('کلید مدیریت معتبر نیست.',401)
    cur=db().execute("UPDATE users SET status='active',suspended_until=NULL,suspension_reason=NULL WHERE id=? AND role NOT IN ('creator','admin')",(user_id,));db().commit()
    if not cur.rowcount:return error('حساب پیدا نشد یا قابل تغییر نیست.',404)
    audit('unsuspend',user_id,'manual unsuspend');return jsonify({'ok':True,'message':'تعلیق برداشته شد.'})

@app.delete('/api/admin/users/<int:user_id>')
def admin_delete_user(user_id):
    if not require_admin():return error('کلید مدیریت معتبر نیست.',401)
    row=db().execute('SELECT role,phone FROM users WHERE id=?',(user_id,)).fetchone()
    if not row:return error('کاربر پیدا نشد.',404)
    if row['role'] in ('creator','admin'):return error('حساب سازنده یا مدیر قابل حذف نیست.',403)
    con=db();con.execute('DELETE FROM sessions WHERE user_id=?',(user_id,));con.execute('DELETE FROM otp_codes WHERE phone=?',(row['phone'],));con.execute('DELETE FROM messages WHERE sender_id=? OR recipient_id=?',(user_id,user_id));con.execute('DELETE FROM reports WHERE reporter_id=? OR target_user_id=?',(user_id,user_id));con.execute('DELETE FROM users WHERE id=?',(user_id,));audit('delete_user',user_id,'account and related data deleted')
    return jsonify({'ok':True,'message':'حساب و داده‌های وابسته حذف شد.'})

@app.get('/api/admin/reports')
def admin_reports():
    if not require_admin():return error('کلید مدیریت معتبر نیست.',401)
    rows=db().execute('''SELECT r.id,r.reason,r.created_at,r.status,u.phone target_phone,rep.phone reporter_phone FROM reports r JOIN users u ON u.id=r.target_user_id JOIN users rep ON rep.id=r.reporter_id ORDER BY r.id DESC LIMIT 200''').fetchall()
    return jsonify({'ok':True,'reports':[dict(r) for r in rows]})

@app.post('/api/admin/reports/<int:report_id>/close')
def admin_close_report(report_id):
    if not require_admin():return error('کلید مدیریت معتبر نیست.',401)
    cur=db().execute("UPDATE reports SET status='closed' WHERE id=? AND status='open'",(report_id,));db().commit()
    if not cur.rowcount:return error('گزارش باز پیدا نشد.',404)
    audit('close_report',None,f'report_id={report_id}');return jsonify({'ok':True})

init_db()
if __name__=='__main__':
    app.run(host=os.environ.get('HOST','0.0.0.0'),port=int(os.environ.get('PORT','5000')),debug=False)
