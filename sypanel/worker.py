import time,json,sqlite3,os
from .core import db,init,decrypt,agent

def process_one():
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        row=c.execute("SELECT * FROM jobs WHERE status='queued' ORDER BY id LIMIT 1").fetchone()
        if not row: return False
        c.execute("UPDATE jobs SET status='running' WHERE id=?",(row['id'],))
    try:
        payload=decrypt(row['payload']); result=agent(row['action'],payload)
        with db() as c:
            if row['resource_id']:
                if row['action'].endswith('.delete'): c.execute('DELETE FROM resources WHERE id=?',(row['resource_id'],))
                else:
                    item=c.execute('SELECT data FROM resources WHERE id=?',(row['resource_id'],)).fetchone()
                    if item:
                        data=result.get('updated') or json.loads(item['data'])
                        data.update({k:v for k,v in result.items() if k not in ('message','updated')})
                        c.execute("UPDATE resources SET status='active',name=?,data=? WHERE id=?",(data['name'],json.dumps(data),row['resource_id']))
            if row['action']=='ssl':
                item=c.execute("SELECT * FROM resources WHERE kind='sites' AND name=?",(payload['domain'],)).fetchone()
                if item:
                    data=json.loads(item['data']); data['ssl']=result.get('ssl',False)
                    c.execute('UPDATE resources SET data=? WHERE id=?',(json.dumps(data),item['id']))
            c.execute("UPDATE jobs SET status='done',message=?,finished=CURRENT_TIMESTAMP,payload='' WHERE id=?",(result.get('message','Selesai.'),row['id']))
    except Exception as e:
        with db() as c:
            # Do not retain raw SQL or command arguments in the job log.
            message=str(e)
            try:
                for k,v in payload.items():
                    if k in ('password','secret','token') and isinstance(v,str): message=message.replace(v,'[REDACTED]')
            except UnboundLocalError: pass
            c.execute("UPDATE jobs SET status='failed',message=?,finished=CURRENT_TIMESTAMP WHERE id=?",(message[:1800],row['id']))
            if row['resource_id']: c.execute("UPDATE resources SET status='error' WHERE id=?",(row['resource_id'],))
    return True

def main():
    init()
    # Never repeat a server mutation automatically following a process crash.
    with db() as c:
        c.execute("UPDATE resources SET status='error' WHERE id IN (SELECT resource_id FROM jobs WHERE status='running')")
        c.execute("UPDATE jobs SET status='failed',message='Worker terhenti. Periksa kondisi server sebelum mengulang.' WHERE status='running'")
    while True:
        if not process_one(): time.sleep(1)

if __name__=='__main__': main()
