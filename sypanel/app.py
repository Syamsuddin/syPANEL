import os, time, json, secrets, base64, hashlib, hmac, struct, io, sqlite3, ipaddress
from datetime import timedelta
from functools import wraps
from flask import Flask, request, jsonify, session, g, render_template, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import HTTPException
from .core import *


def totp_counter(secret_value, code, now=None):
    if not str(code).isdigit() or len(str(code))!=6: return -1
    key=base64.b32decode(secret_value); current=int((now or time.time())//30)
    for counter in (current-1,current,current+1):
        digest=hmac.new(key,struct.pack('>Q',counter),hashlib.sha1).digest(); offset=digest[-1]&15
        expected=str((struct.unpack('>I',digest[offset:offset+4])[0]&0x7fffffff)%1000000).zfill(6)
        if hmac.compare_digest(expected,str(code)): return counter
    return -1

def client_key(ip):
    """Login throttling key. An IPv6 /64 is normally one client, so rotating addresses inside it does not reset the count."""
    try:
        if ipaddress.ip_address(ip).version==6: return 'ip:'+str(ipaddress.ip_network(ip+'/64',strict=False))
    except ValueError: pass
    return 'ip:'+str(ip)

def create_app():
    init(); app=Flask(__name__)
    if MODE=='live':
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app=ProxyFix(app.wsgi_app,x_for=1,x_proto=1)
    app.config.update(SECRET_KEY=SESSION_KEY,MAX_CONTENT_LENGTH=24*1024*1024,
        SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Strict',
        SESSION_COOKIE_SECURE=MODE=='live',PERMANENT_SESSION_LIFETIME=timedelta(hours=8))
    def audit(action,detail=''):
        with db() as c: c.execute('INSERT INTO audit(actor,action,detail,ip) VALUES(?,?,?,?)',
            (g.user['username'] if getattr(g,'user',None) else 'anonymous',action,detail[:500],request.remote_addr))
    def auth(roles=None):
        def wrap(fn):
            @wraps(fn)
            def inner(*args,**kwargs):
                if not g.user: return jsonify(error='Silakan masuk.'),401
                if roles and g.user['role'] not in roles: return jsonify(error='Hak akses tidak mencukupi.'),403
                return fn(*args,**kwargs)
            return inner
        return wrap
    @app.before_request
    def guard():
        g.user=None
        token=session.get('sid')
        if token:
            with db() as c:
                row=c.execute('SELECT users.* FROM users JOIN sessions ON sessions.user_id=users.id WHERE sessions.token=? AND sessions.expires>?',(token,time.time())).fetchone()
                if row: g.user=dict(row)
        if 'csrf' not in session: session['csrf']=secrets.token_urlsafe(32)
        if request.path.startswith('/api/') and request.method not in ('GET','HEAD','OPTIONS'):
            value=request.headers.get('X-CSRF-Token','')
            if not hmac.compare_digest(value,session['csrf']): return jsonify(error='Token sesi tidak valid. Muat ulang halaman.'),403
    @app.after_request
    def headers(response):
        response.headers['X-Content-Type-Options']='nosniff'
        response.headers['X-Frame-Options']='DENY'
        response.headers['Referrer-Policy']='same-origin'
        response.headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        if request.path.startswith('/api/'): response.headers['Cache-Control']='no-store'
        if MODE=='live': response.headers['Strict-Transport-Security']='max-age=31536000'
        return response
    @app.errorhandler(Exception)
    def errors(e):
        if isinstance(e,HTTPException): return jsonify(error=e.description),e.code
        if isinstance(e,(ValueError,KeyError,TypeError)): return jsonify(error=str(e)),400
        if isinstance(e,sqlite3.IntegrityError): return jsonify(error='Data sudah ada atau masih digunakan.'),409
        app.logger.exception('Request failed')
        return jsonify(error='Operasi gagal. Periksa log syPanel.'),500
    @app.get('/')
    def index(): return render_template('index.html')
    @app.get('/api/me')
    def me():
        return jsonify(user={k:g.user[k] for k in ('id','username','role')} if g.user else None,
            csrf=session['csrf'],mode=MODE,totp=bool(g.user and g.user['totp']))
    @app.post('/api/login')
    def login():
        d=request.get_json(); ip=request.remote_addr; username=str(d.get('username',''))[:64]; now=time.time()
        # Per client only: a per-username counter would let anyone lock the admin out.
        keys=[client_key(ip)]
        with db() as c:
            for key in keys:
                row=c.execute('SELECT * FROM attempts WHERE ip=?',(key,)).fetchone()
                if row and row['count']>=5 and row['until']>now: return jsonify(error='Terlalu banyak percobaan. Coba kembali dalam 5 menit.'),429
            user=c.execute('SELECT * FROM users WHERE username=?',(username,)).fetchone()
            valid=user and check_password_hash(user['password'],str(d.get('password','')))
            counter=-1
            if valid and user['totp']:
                counter=totp_counter(decrypt(user['totp']),str(d.get('code','')))
                valid=counter>user['last_totp']
            if not valid:
                for key in keys:
                    c.execute('INSERT INTO attempts(ip,count,until) VALUES(?,1,?) ON CONFLICT(ip) DO UPDATE SET count=CASE WHEN until<? THEN 1 ELSE count+1 END,until=?',(key,now+300,now,now+300))
                c.commit()
                audit('login.failed',username)
                return jsonify(error='Nama pengguna, password, atau kode autentikator tidak sesuai.'),401
            if counter>=0:
                changed=c.execute('UPDATE users SET last_totp=? WHERE id=? AND last_totp<?',(counter,user['id'],counter)).rowcount
                if not changed: return jsonify(error='Kode autentikator telah digunakan.'),401
            for key in keys: c.execute('DELETE FROM attempts WHERE ip=?',(key,))
            token=secrets.token_urlsafe(40); c.execute('DELETE FROM sessions WHERE expires<?',(now,))
            c.execute('INSERT INTO sessions VALUES(?,?,?)',(token,user['id'],now+28800))
        session.clear(); session['sid']=token; session['csrf']=secrets.token_urlsafe(32); session.permanent=True
        g.user=dict(user); audit('login.success'); return jsonify(ok=True,csrf=session['csrf'])
    @app.post('/api/logout')
    @auth()
    def logout():
        audit('logout')
        with db() as c: c.execute('DELETE FROM sessions WHERE token=?',(session.get('sid'),))
        session.clear(); return jsonify(ok=True)
    @app.get('/api/overview')
    @auth()
    def overview():
        metrics_error=None
        try: metrics=agent('metrics')
        except Exception as e: metrics={}; metrics_error=str(e)
        with db() as c:
            counts={r['kind']:r['n'] for r in c.execute('SELECT kind,count(*) n FROM resources GROUP BY kind')}
            jobs=[dict(x) for x in c.execute('SELECT id,action,status,message,created,finished FROM jobs ORDER BY id DESC LIMIT 8')]
        return jsonify(metrics=metrics,metrics_error=metrics_error,counts=counts,jobs=jobs)
    @app.get('/api/resources/<kind>')
    @auth()
    def resources(kind):
        if kind not in KINDS: raise ValueError('Modul tidak dikenal.')
        with db() as c:
            result=[dict(row) for row in c.execute('SELECT * FROM resources WHERE kind=? ORDER BY id DESC',(kind,))]
        for row in result: row['data']=json.loads(row['data'])
        return jsonify(result)
    def enqueue(c,action,payload,rid=None):
        return c.execute('INSERT INTO jobs(action,payload,resource_id) VALUES(?,?,?)',(action,encrypt(payload),rid)).lastrowid
    def claimed(c,kind,name,rid=None):
        # A queued rename is not in resources yet: its new name exists only inside the encrypted job payload.
        return any(job['resource_id']!=rid and decrypt(job['payload']).get('name')==name for job in
            c.execute("SELECT resource_id,payload FROM jobs WHERE action=? AND status IN ('queued','running')",(kind+'.update',)))
    def taken(c,kind,name,rid):
        return c.execute('SELECT 1 FROM resources WHERE kind=? AND name=? AND id!=?',(kind,name,rid)).fetchone() or claimed(c,kind,name,rid)
    @app.post('/api/resources/<kind>')
    @auth(('admin','operator'))
    def create(kind):
        d=validate(kind,request.get_json())
        with db() as c:
            c.execute('BEGIN IMMEDIATE')
            if kind!='sites':
                site=c.execute("SELECT data FROM resources WHERE kind='sites' AND name=? AND status='active'",(d['domain'],)).fetchone()
                if not site: raise ValueError('Pilih situs aktif terlebih dahulu.')
                if kind=='cron' and json.loads(site['data']).get('php')=='static': raise ValueError('Cron hanya untuk situs PHP.')
            if claimed(c,kind,d['name']): raise ValueError('Nama objek sedang dipakai oleh perubahan yang belum selesai.')
            rid=c.execute('INSERT INTO resources(kind,name,data) VALUES(?,?,?)',(kind,d['name'],json.dumps(public(d)))).lastrowid
            jid=enqueue(c,kind+'.create',d,rid)
        audit('resource.create',kind+':'+d['name']); return jsonify(id=rid,job=jid),202
    @app.patch('/api/resources/<int:rid>')
    @auth(('admin','operator'))
    def update_resource(rid):
        with db() as c:
            c.execute('BEGIN IMMEDIATE')
            row=c.execute('SELECT * FROM resources WHERE id=?',(rid,)).fetchone()
            if not row or row['kind']=='backups': raise ValueError('Objek tidak dapat diubah.')
            if row['status'] in ('pending','deleting'): raise ValueError('Pekerjaan sebelumnya belum selesai.')
            old=json.loads(row['data']); raw=dict(old); raw.update(request.get_json())
            d=validate(row['kind'],raw)
            if d['domain']!=old['domain']: raise ValueError('Perpindahan domain tidak didukung.')
            if taken(c,row['kind'],d['name'],rid): raise ValueError('Nama objek telah digunakan.')
            if row['kind']=='sites' and d['php']=='static' and any(json.loads(x['data'])['domain']==d['domain'] for x in c.execute("SELECT data FROM resources WHERE kind='cron'")): raise ValueError('Hapus cron situs ini sebelum beralih ke static.')
            d['_old_name']=row['name']
            jid=enqueue(c,row['kind']+'.update',d,rid)
            c.execute("UPDATE resources SET status='pending' WHERE id=?",(rid,))
        audit('resource.update',row['name']); return jsonify(job=jid),202
    @app.delete('/api/resources/<int:rid>')
    @auth(('admin','operator'))
    def remove(rid):
        with db() as c:
            row=c.execute('SELECT * FROM resources WHERE id=?',(rid,)).fetchone()
            if not row: return jsonify(error='Objek tidak ditemukan.'),404
            if row['status'] in ('pending','deleting'): raise ValueError('Pekerjaan sebelumnya belum selesai.')
            if request.get_json().get('confirm')!=row['name']: raise ValueError('Konfirmasi nama tidak sesuai.')
            if row['kind']=='sites':
                for other in c.execute('SELECT data FROM resources WHERE id!=?',(rid,)):
                    if json.loads(other['data']).get('domain')==row['name']: raise ValueError('Hapus objek terkait situs terlebih dahulu.')
            jid=enqueue(c,row['kind']+'.delete',json.loads(row['data']),rid)
            c.execute("UPDATE resources SET status='deleting' WHERE id=?",(rid,))
        audit('resource.delete',row['name']); return jsonify(job=jid),202
    @app.get('/api/jobs')
    @auth()
    def jobs():
        with db() as c: return jsonify([dict(x) for x in c.execute('SELECT id,action,status,message,created,finished,resource_id FROM jobs ORDER BY id DESC LIMIT 150')])
    @app.post('/api/jobs/<int:jid>/retry')
    @auth(('admin',))
    def retry(jid):
        with db() as c:
            c.execute('BEGIN IMMEDIATE')
            row=c.execute('SELECT * FROM jobs WHERE id=?',(jid,)).fetchone()
            if not row or row['status']!='failed' or not row['payload']: raise ValueError('Pekerjaan ini tidak dapat diulang.')
            if row['resource_id'] and c.execute("SELECT 1 FROM jobs WHERE resource_id=? AND status IN ('queued','running')",(row['resource_id'],)).fetchone(): raise ValueError('Masih ada pekerjaan aktif.')
            # Replaying an old payload would overwrite whatever a later job already applied.
            if row['resource_id'] and c.execute('SELECT 1 FROM jobs WHERE resource_id=? AND id>?',(row['resource_id'],jid)).fetchone(): raise ValueError('Objek ini sudah memiliki pekerjaan yang lebih baru. Ulangi ditolak agar perubahan terbaru tidak tertimpa.')
            if row['action'].endswith('.update') and taken(c,row['action'].split('.')[0],decrypt(row['payload'])['name'],row['resource_id']): raise ValueError('Nama objek telah digunakan.')
            c.execute("UPDATE jobs SET status='queued',message='',finished=NULL WHERE id=?",(jid,))
            if row['resource_id']: c.execute("UPDATE resources SET status=? WHERE id=?",('deleting' if row['action'].endswith('.delete') else 'pending',row['resource_id']))
        audit('job.retry',str(jid)); return jsonify(ok=True)
    @app.post('/api/ssl')
    @auth(('admin','operator'))
    def ssl():
        d=request.get_json(); d['domain']=domain(d['domain'])
        with db() as c: jid=enqueue(c,'ssl',d)
        audit('ssl.issue',d['domain']); return jsonify(job=jid),202
    @app.post('/api/service')
    @auth(('admin',))
    def service():
        d=request.get_json()
        with db() as c: jid=enqueue(c,'service',d)
        audit('service',str(d.get('service'))+':'+str(d.get('op'))); return jsonify(job=jid),202
    @app.get('/api/logs')
    @auth(('admin','operator'))
    def logs(): return jsonify(agent('logs',dict(request.args)))
    @app.get('/api/files')
    @auth(('admin','operator'))
    def files(): return jsonify(agent('file',{'domain':request.args.get('domain'),'path':request.args.get('path','.'),'op':'list'}))
    @app.get('/api/file')
    @auth(('admin','operator'))
    def readfile():
        d={'domain':request.args.get('domain'),'path':request.args.get('path'),'op':'read'}
        return jsonify(agent('file',d))
    @app.post('/api/file')
    @auth(('admin','operator'))
    def writefile():
        d=request.get_json()
        if d.get('op') not in ('write','mkdir','delete'): raise ValueError('Aksi file tidak valid.')
        result=agent('file',d); audit('file.'+d['op'],str(d.get('domain'))+':'+str(d.get('path')))
        return jsonify(result)
    @app.get('/api/download/<kind>/<int:rid>')
    @auth(('admin','operator'))
    def download(kind,rid):
        if kind not in ('backups','databases'): raise ValueError('Unduhan tidak tersedia.')
        with db() as c: row=c.execute('SELECT * FROM resources WHERE id=? AND kind=?',(rid,kind)).fetchone()
        if not row or row['status']!='active': raise ValueError('Objek belum aktif.')
        result=agent('download' if kind=='backups' else 'db_export',{'name':row['name']})
        audit('download',row['name']); return send_file(io.BytesIO(base64.b64decode(result['content'])),as_attachment=True,download_name=result['filename'],mimetype='application/octet-stream')
    @app.post('/api/restore/<int:rid>')
    @auth(('admin',))
    def restore(rid):
        with db() as c:
            row=c.execute("SELECT * FROM resources WHERE id=? AND kind='backups' AND status='active'",(rid,)).fetchone()
            if not row: raise ValueError('Cadangan tidak ditemukan.')
            if request.get_json().get('confirm')!=row['name']: raise ValueError('Konfirmasi tidak sesuai.')
            jid=enqueue(c,'restore',{'name':row['name']})
        audit('backup.restore',row['name']); return jsonify(job=jid),202
    @app.get('/api/audit')
    @auth(('admin',))
    def audits():
        with db() as c: return jsonify([dict(x) for x in c.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 300')])
    @app.get('/api/users')
    @auth(('admin',))
    def users():
        with db() as c: return jsonify([dict(x) for x in c.execute('SELECT id,username,role,created,totp IS NOT NULL AS mfa FROM users')])
    @app.post('/api/users')
    @auth(('admin',))
    def add_user():
        d=request.get_json(); name=identifier(d['username']); pw=password(d['password']); role=d.get('role','viewer')
        if role not in ('admin','operator','viewer'): raise ValueError('Role tidak valid.')
        with db() as c: c.execute('INSERT INTO users(username,password,role) VALUES(?,?,?)',(name,generate_password_hash(pw),role))
        audit('user.create',name); return jsonify(ok=True),201
    @app.delete('/api/users/<int:uid>')
    @auth(('admin',))
    def delete_user(uid):
        if uid==g.user['id']: raise ValueError('Akun sendiri tidak boleh dihapus.')
        with db() as c: c.execute('DELETE FROM users WHERE id=?',(uid,))
        audit('user.delete',str(uid)); return jsonify(ok=True)
    @app.post('/api/password')
    @auth()
    def change_password():
        d=request.get_json()
        if not check_password_hash(g.user['password'],str(d.get('current',''))): raise ValueError('Password lama tidak sesuai.')
        new=password(d.get('password',''))
        with db() as c:
            c.execute('UPDATE users SET password=? WHERE id=?',(generate_password_hash(new),g.user['id']))
            c.execute('DELETE FROM sessions WHERE user_id=? AND token!=?',(g.user['id'],session['sid']))
        audit('password.change'); return jsonify(ok=True)
    @app.post('/api/mfa/setup')
    @auth()
    def setup_mfa():
        if g.user['totp']: raise ValueError('Autentikator sudah aktif.')
        secret_value=base64.b32encode(secrets.token_bytes(20)).decode()
        with db() as c: c.execute('UPDATE users SET pending_totp=? WHERE id=?',(encrypt(secret_value),g.user['id']))
        return jsonify(secret=secret_value)
    @app.post('/api/mfa/confirm')
    @auth()
    def confirm_mfa():
        d=request.get_json()
        if not check_password_hash(g.user['password'],str(d.get('password',''))): raise ValueError('Password tidak sesuai.')
        if not g.user['pending_totp']: raise ValueError('Mulai pemasangan autentikator terlebih dahulu.')
        counter=totp_counter(decrypt(g.user['pending_totp']),d.get('code',''))
        if counter<0: raise ValueError('Kode autentikator salah.')
        with db() as c:
            c.execute('UPDATE users SET totp=pending_totp,pending_totp=NULL,last_totp=? WHERE id=?',(counter,g.user['id']))
            c.execute('DELETE FROM sessions WHERE user_id=? AND token!=?',(g.user['id'],session['sid']))
        audit('mfa.enable'); return jsonify(ok=True)
    return app

app=create_app()
