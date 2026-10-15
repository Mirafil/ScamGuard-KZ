import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from http.server import ThreadingHTTPServer
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
import server

class TestScamGuard(unittest.TestCase):
    def test_evaluation_case(self):
        profile={'known':False,'usualAmount':25000,'newAccount':True,'multiSenders':29,'rapidOutflow':True,'riskyLinks':True,'oddTime':False}
        score,decision,reasons=server.evaluate(profile,150000)
        self.assertEqual(score,100)
        self.assertEqual(decision,'HOLD')
        self.assertEqual(len(reasons),7)

    def test_safe(self):
        profile={'known':True,'usualAmount':15000,'newAccount':False,'multiSenders':1,'rapidOutflow':False,'riskyLinks':False,'oddTime':False}
        self.assertEqual(server.evaluate(profile,12500)[:2],(0,'ALLOW'))

    def test_timing_leak(self):
        obj=json.loads((Path(__file__).parent.parent/'example_transaction.json').read_text())
        obj['context']['observed_at']='2026-10-08T08:35:00+05:00'
        with self.assertRaisesRegex(ValueError,'before requested_at'):
            server.check_transaction(obj)

    def test_unknown_context_rejected(self):
        obj=json.loads((Path(__file__).parent.parent/'example_transaction.json').read_text())
        obj.pop('context')
        with self.assertRaisesRegex(ValueError,'context'):
            server.check_transaction(obj)

    def test_http_integration(self):
        old_db,old_key,old_port=server.DB_PATH,server.API_KEY,server.PORT
        with tempfile.TemporaryDirectory() as d:
            server.DB_PATH=Path(d)/'test.sqlite3';server.API_KEY='test-secret-key'
            server.init_db()
            httpd=ThreadingHTTPServer(('127.0.0.1',0),server.Handler)
            server.PORT=httpd.server_port
            t=threading.Thread(target=httpd.serve_forever,daemon=True);t.start()
            base=f'http://127.0.0.1:{httpd.server_port}'
            payload=(Path(__file__).parent.parent/'example_transaction.json').read_bytes()
            try:
                req=Request(base+'/v1/transaction/check',data=payload,headers={'Content-Type':'application/json'},method='POST')
                with self.assertRaises(HTTPError) as e:urlopen(req)
                self.assertEqual(e.exception.code,401)
                req.add_header('X-API-Key','test-secret-key')
                with urlopen(req) as res:obj=json.load(res)
                self.assertEqual(obj['recommendation'],'HOLD')
                self.assertEqual(obj['risk_score'],100)
                with urlopen(base+'/health') as res:self.assertEqual(json.load(res)['status'],'ok')
                pilot={'name':'Sample Tester','organization':'Student University','contact':'demo@example.test','goal':'Test sandbox','consent':True}
                req=Request(base+'/api/pilot',data=json.dumps(pilot).encode(),headers={'Content-Type':'application/json','X-Requested-With':'ScamGuardDemo'},method='POST')
                with urlopen(req) as res:self.assertEqual(json.load(res)['request_id'],1)
                history={'time':'12:31','name':'Test R.','amount':2500,'score':45,'decision':'VERIFY'}
                from urllib.request import build_opener, HTTPCookieProcessor
                from http.cookiejar import CookieJar
                opener=build_opener(HTTPCookieProcessor(CookieJar()))
                with opener.open(base+'/api/history') as res:self.assertEqual(json.load(res)['history'],[])
                hreq=Request(base+'/api/history',data=json.dumps(history).encode(),headers={'Content-Type':'application/json','X-Requested-With':'ScamGuardDemo'},method='POST')
                with opener.open(hreq) as res:self.assertEqual(json.load(res)['ok'],True)
                with opener.open(base+'/api/history') as res:self.assertEqual(json.load(res)['history'][0]['score'],45)
                hreq=Request(base+'/api/history',headers={'X-Requested-With':'ScamGuardDemo'},method='DELETE')
                with opener.open(hreq) as res:self.assertEqual(json.load(res)['ok'],True)
                with opener.open(base+'/api/history') as res:self.assertEqual(json.load(res)['history'],[])
                with server.db_connection() as con:
                    self.assertEqual(con.execute('SELECT COUNT(*) FROM pilot_requests').fetchone()[0],1)
                    self.assertEqual(con.execute('SELECT COUNT(*) FROM check_audit').fetchone()[0],1)
            finally:
                httpd.shutdown();httpd.server_close();t.join(timeout=3)
        server.DB_PATH,server.API_KEY,server.PORT=old_db,old_key,old_port

if __name__=='__main__':unittest.main()
