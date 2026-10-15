"""ScamGuard KZ educational, loopback-only sandbox server.

Not suitable for real bank / production / personal data processing.
Run: SCAMGUARD_API_KEY=your-local-secret python server.py
"""
from __future__ import annotations
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock
from time import monotonic, time
from datetime import datetime, timezone
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get('SCAMGUARD_DB_PATH', str(HERE / 'scamguard_demo.sqlite3')))
API_KEY = os.environ.get('SCAMGUARD_API_KEY', '')
ADDR = '127.0.0.1'
PORT = int(os.environ.get('SCAMGUARD_PORT', '8765'))
MAX_BODY = 8192
STORE_LOCK = Lock()
RATE_LOCK = Lock()
RATE = {}
RULES = [
    ('NEW_RECIPIENT', 'New recipient', 14, lambda p,a: not p['known']),
    ('UNUSUAL_AMOUNT', 'Unusual amount', 16, lambda p,a: a >= p['usualAmount'] * 2),
    ('VERY_HIGH_AMOUNT', 'Very high amount', 9, lambda p,a: a >= p['usualAmount'] * 5),
    ('NEW_ACCOUNT', 'New recipient account', 10, lambda p,a: p['newAccount']),
    ('UNUSUAL_TIME', 'Unusual transfer time', 9, lambda p,a: p['oddTime']),
    ('MULTI_SENDER_PATTERN', 'Multiple unrelated past senders', 18, lambda p,a: p['multiSenders'] >= 10),
    ('RAPID_OUTFLOW', 'Past rapid outflows', 16, lambda p,a: p['rapidOutflow']),
    ('NETWORK_RISK', 'Historical risky account links', 17, lambda p,a: p['riskyLinks']),
]


def db_connection():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with db_connection() as con:
        con.execute('''CREATE TABLE IF NOT EXISTS pilot_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT, received_at TEXT NOT NULL,
            name TEXT NOT NULL, organization TEXT NOT NULL,
            contact TEXT NOT NULL, goal TEXT NOT NULL, consent INTEGER NOT NULL)''')
        con.execute('''CREATE TABLE IF NOT EXISTS demo_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL,
            received_at TEXT NOT NULL, display_time TEXT NOT NULL,
            recipient TEXT NOT NULL, amount INTEGER NOT NULL, score INTEGER NOT NULL,
            decision TEXT NOT NULL)''')
        con.execute('''CREATE TABLE IF NOT EXISTS check_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT, received_at TEXT NOT NULL,
            tx_hash TEXT NOT NULL, score INTEGER NOT NULL, recommendation TEXT NOT NULL,
            processing_ms REAL NOT NULL)''')
        con.execute('CREATE INDEX IF NOT EXISTS history_session_idx ON demo_history(session_id, id DESC)')


def evaluate(profile: dict, amount: float):
    fired = [(code, label, points) for code,label,points,condition in RULES if condition(profile, amount)]
    score = min(100, sum(points for _,_,points in fired))
    result = 'ALLOW' if score <= 39 else 'VERIFY' if score <= 74 else 'HOLD'
    return score, result, fired


def require_profile(data):
    if not isinstance(data, dict):
        raise ValueError('context must be a JSON object')
    boolean = ('known','newAccount','rapidOutflow','riskyLinks','oddTime')
    for k in boolean:
        if k not in data or type(data[k]) is not bool:
            raise ValueError('context.'+k+' must be a boolean')
    for k in ('usualAmount', 'multiSenders'):
        if k not in data or type(data[k]) not in (int,float):
            raise ValueError('context.'+k+' must be numeric')
    if not (1 <= data['usualAmount'] <= 1_000_000_000):
        raise ValueError('context.usualAmount is out of range')
    if data['multiSenders'] != int(data['multiSenders']) or not (0 <= data['multiSenders'] <= 1_000_000):
        raise ValueError('context.multiSenders is out of range')
    return data


def check_transaction(payload):
    if not isinstance(payload, dict):
        raise ValueError('Expected a JSON object')
    tid = payload.get('transaction_id')
    if not isinstance(tid, str) or not re.fullmatch(r'[A-Za-z0-9_-]{5,80}', tid):
        raise ValueError('transaction_id must be 5–80 ASCII letters/digits/_/-')
    if payload.get('currency') != 'KZT':
        raise ValueError('Only KZT demo transactions supported')
    amount = payload.get('amount')
    if type(amount) not in (int,float) or not (0 < amount <= 1_000_000_000):
        raise ValueError('amount must be a positive numeric KZT value')
    context = require_profile(payload.get('context'))
    if not isinstance(context.get('observed_at'),str) or not isinstance(payload.get('requested_at'),str):
        raise ValueError('context.observed_at and requested_at are required for pre-transfer scoring')
    if True:
        try:
            earlier = datetime.fromisoformat(context['observed_at'].replace('Z','+00:00'))
            current = datetime.fromisoformat(payload['requested_at'].replace('Z','+00:00'))
            if earlier.tzinfo is None or current.tzinfo is None or earlier > current:
                raise ValueError('context.observed_at must be on/before requested_at')
        except (TypeError, AttributeError):
            raise ValueError('Invalid ISO dates for requested_at/observed_at')
    score, decision, fired = evaluate(context, amount)
    return dict(transaction_id=tid, risk_score=score,
        risk_level='LOW' if decision=='ALLOW' else 'MEDIUM' if decision=='VERIFY' else 'HIGH',
        recommendation=decision, reason_codes=[x[0] for x in fired] or ['NO_FLAGS'],
        model_version='rules-mvp-1.0', synthetic_context_only=True,
        warning='Educational rule-based result, not a fraud probability or bank decision')


def rate_ok(key, max_requests=15, window_seconds=3600):
    with RATE_LOCK:
        now=monotonic()
        recent=[t for t in RATE.get(key,[]) if now-t < window_seconds]
        if len(recent) >= max_requests:
            RATE[key]=recent
            return False
        recent.append(now)
        RATE[key]=recent
        return True


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


class Handler(BaseHTTPRequestHandler):
    server_version='ScamGuardSandbox/0.4'
    sys_version=''

    def log_message(self, fmt, *args):
        # No request bodies, contacts, API keys, or cookies in logs.
        print('[sandbox]', self.command, urlsplit(self.path).path, '-', self.address_string())

    def response_headers(self, status=200, content_type='application/json; charset=utf-8', cookie=None):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('X-Frame-Options','DENY')
        if cookie:
            self.send_header('Set-Cookie', f'sg_demo={cookie}; HttpOnly; SameSite=Strict; Path=/; Max-Age=2592000')

    def send_json(self, value, code=200, cookie=None):
        body=json.dumps(value, ensure_ascii=False).encode('utf-8')
        self.response_headers(code, cookie=cookie)
        self.send_header('Content-Length',str(len(body)))
        self.end_headers();self.wfile.write(body)

    def forbidden_origin(self):
        origin=self.headers.get('Origin','')
        return bool(origin and origin not in (f'http://127.0.0.1:{PORT}', f'http://localhost:{PORT}'))

    def session(self):
        cookie=SimpleCookie()
        try: cookie.load(self.headers.get('Cookie',''))
        except Exception: pass
        entry=cookie.get('sg_demo')
        sid=entry.value if entry else None
        if sid and re.fullmatch('[a-f0-9]{32}',sid):
            return sid,None
        sid=secrets.token_hex(16)
        return sid,sid

    def read_payload(self):
        if self.headers.get('Content-Type','').split(';')[0].strip() != 'application/json':
            raise ValueError('Use application/json')
        rawlen=self.headers.get('Content-Length','')
        if not rawlen.isdecimal():
            raise ValueError('Content-Length required')
        length=int(rawlen)
        if length<=0 or length>MAX_BODY:
            raise ValueError('Invalid JSON body length')
        try:
            return json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError('Invalid JSON')

    def do_GET(self):
        path=urlsplit(self.path).path
        if path=='/health':
            return self.send_json({'service':'scamguard-local-sandbox','status':'ok','mode':'synthetic-only'})
        if path=='/api/history':
            if self.forbidden_origin():return self.send_json({'error':'forbidden origin'},403)
            sid,new=self.session()
            with STORE_LOCK, db_connection() as con:
                rows=con.execute('SELECT display_time AS time,recipient AS name,amount,score,decision FROM demo_history WHERE session_id=? ORDER BY id DESC LIMIT 8',(sid,)).fetchall()
            return self.send_json({'history':[dict(row) for row in rows]},cookie=new)
        if path in ('/','/index.html'):
            content=(HERE/'index.html').read_bytes()
            self.response_headers(200,'text/html; charset=utf-8')
            self.send_header('Content-Length',str(len(content)))
            self.end_headers();self.wfile.write(content)
            return
        return self.send_json({'error':'not found'},404)

    def do_DELETE(self):
        path=urlsplit(self.path).path
        if path!='/api/history':return self.send_json({'error':'not found'},404)
        if self.forbidden_origin() or self.headers.get('X-Requested-With')!='ScamGuardDemo':return self.send_json({'error':'forbidden'},403)
        sid,new=self.session()
        with STORE_LOCK, db_connection() as con:
            con.execute('DELETE FROM demo_history WHERE session_id=?',(sid,))
        self.send_json({'ok':True},cookie=new)

    def do_POST(self):
        path=urlsplit(self.path).path
        if path not in ('/api/history','/api/pilot','/v1/transaction/check'):
            return self.send_json({'error':'not found'},404)
        if self.forbidden_origin():return self.send_json({'error':'forbidden origin'},403)
        if path == '/v1/transaction/check':
            if not API_KEY: return self.send_json({'error':'Set SCAMGUARD_API_KEY on server to activate API'},503)
            if not hmac.compare_digest(self.headers.get('X-API-Key',''),API_KEY):
                return self.send_json({'error':'unauthorized'},401)
            if not rate_ok('bank-api',300,60):return self.send_json({'error':'rate limited'},429)
        else:
            if self.headers.get('X-Requested-With')!='ScamGuardDemo':return self.send_json({'error':'missing local demo header'},403)
            if not rate_ok((path,self.client_address[0]),5 if path=='/api/pilot' else 120,3600 if path=='/api/pilot' else 60):
                return self.send_json({'error':'too many requests'},429)
        try: payload=self.read_payload()
        except ValueError as ex:return self.send_json({'error':str(ex)},400)
        if path=='/api/pilot':
            try:
                if not isinstance(payload,dict) or payload.get('consent') is not True:
                    raise ValueError('Explicit consent required')
                name=payload.get('name','');org=payload.get('organization','');contact=payload.get('contact','');goal=payload.get('goal','')
                if any(type(v) is not str for v in (name,org,contact,goal)):
                    raise ValueError('All form fields must be strings')
                if not (2<=len(name.strip())<=100 and 5<=len(contact.strip())<=150 and len(org)<=150 and len(goal)<=1500):
                    raise ValueError('Invalid name, contact, organization or goal length')
            except ValueError as ex:return self.send_json({'error':str(ex)},422)
            with STORE_LOCK,db_connection() as con:
                cur=con.execute('INSERT INTO pilot_requests(received_at,name,organization,contact,goal,consent) VALUES(?,?,?,?,?,1)',(utcnow(),name.strip(),org.strip(),contact.strip(),goal.strip()))
                new_id=cur.lastrowid
            return self.send_json({'ok':True,'request_id':new_id},201)
        if path=='/api/history':
            sid,new=self.session()
            try:
                if not isinstance(payload,dict):raise ValueError('Invalid history record')
                t,n,a,score,d=(payload.get(k) for k in ('time','name','amount','score','decision'))
                if not isinstance(t,str) or len(t)>25 or not isinstance(n,str) or len(n)>100 or type(a) not in (int,float) or not (0<a<=1e9) or type(score) is not int or not (0<=score<=100) or d not in ('ALLOW','VERIFY','HOLD'):
                    raise ValueError('Invalid demo record')
            except ValueError as ex:return self.send_json({'error':str(ex)},422)
            with STORE_LOCK,db_connection() as con:
                con.execute('INSERT INTO demo_history(session_id,received_at,display_time,recipient,amount,score,decision) VALUES(?,?,?,?,?,?,?)',(sid,utcnow(),t,n,int(a),score,d))
                con.execute('DELETE FROM demo_history WHERE session_id=? AND id NOT IN (SELECT id FROM demo_history WHERE session_id=? ORDER BY id DESC LIMIT 8)',(sid,sid))
            return self.send_json({'ok':True},201,cookie=new)
        start=monotonic()
        try: result=check_transaction(payload)
        except (ValueError, OverflowError, TypeError) as ex:return self.send_json({'error':str(ex)},422)
        duration=round((monotonic()-start)*1000,4)
        with STORE_LOCK,db_connection() as con:
            con.execute('INSERT INTO check_audit(received_at,tx_hash,score,recommendation,processing_ms) VALUES(?,?,?,?,?)',
                        (utcnow(),hashlib.sha256(result['transaction_id'].encode('utf-8')).hexdigest()[:20],result['risk_score'],result['recommendation'],duration))
        result['processing_time_ms']=duration
        return self.send_json(result)


def main():
    init_db()
    print(f'ScamGuard local sandbox → http://{ADDR}:{PORT}')
    print('Not production. Local-only HTTP. Do not use real banking/customer data.')
    print('Authenticated check API:', 'enabled (X-API-Key)' if API_KEY else 'disabled (set SCAMGUARD_API_KEY)')
    ThreadingHTTPServer((ADDR,PORT),Handler).serve_forever()


if __name__=='__main__':
    main()
