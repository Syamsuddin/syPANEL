#!/usr/bin/env python3
import argparse,getpass,os,sys
from werkzeug.security import generate_password_hash
from sypanel.core import init,db,password,identifier,DATA
p=argparse.ArgumentParser(description='syPanel administration')
p.add_argument('command',choices=['init','create-admin','reset-password','reset-mfa','check','dev'])
p.add_argument('--username',default='admin')
a=p.parse_args(); init()
if a.command=='init': print('Database siap:',DATA)
elif a.command in ('create-admin','reset-password'):
    name=identifier(a.username); pw=password(getpass.getpass('Password (minimal 12 karakter): '))
    if pw!=getpass.getpass('Ulangi password: '): sys.exit('Password berbeda.')
    with db() as c:
        if a.command=='create-admin': c.execute("INSERT INTO users(username,password,role) VALUES(?,?,'admin')",(name,generate_password_hash(pw)))
        else:
            user=c.execute('SELECT id FROM users WHERE username=?',(name,)).fetchone()
            if not user: sys.exit('Pengguna tidak ditemukan.')
            c.execute('UPDATE users SET password=? WHERE id=?',(generate_password_hash(pw),user['id']))
            c.execute('DELETE FROM sessions WHERE user_id=?',(user['id'],))
    print('Akun diperbarui.')
elif a.command=='reset-mfa':
    with db() as c:
        user=c.execute('SELECT id FROM users WHERE username=?',(a.username,)).fetchone()
        if not user: sys.exit('Pengguna tidak ditemukan.')
        c.execute('UPDATE users SET totp=NULL,pending_totp=NULL,last_totp=-1 WHERE id=?',(user['id'],))
        c.execute('DELETE FROM sessions WHERE user_id=?',(user['id'],))
    print('Autentikator direset. Daftarkan ulang dari panel.')
elif a.command=='check':
    from sypanel.core import agent
    import json
    print(json.dumps(agent('metrics'),indent=2))
elif a.command=='dev':
    if os.environ.get('SYPANEL_MODE','sandbox')!='sandbox': sys.exit('Gunakan Gunicorn dan systemd untuk mode live.')
    import subprocess
    from sypanel.app import app
    child=subprocess.Popen([sys.executable,'-m','sypanel.worker'])
    try: app.run(host='127.0.0.1',port=8080,debug=False)
    finally: child.terminate(); child.wait()
