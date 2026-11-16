import http.client,json,re,sqlite3,tempfile,threading,time,unittest
from pathlib import Path
from communications.configuration import validate_initial,save_initial
from communications.setup import SetupServer

FIELDS=dict(gateway_url='http://127.0.0.1:8080',gateway_username='synthetic-user',gateway_password='synthetic-secret',installed_version='1.78.3',owner_name='Example',owner_number='+442079460123',device_number='')
class SetupTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'data';self.code='synthetic-one-time-code'
  self.server=SetupServer(('127.0.0.1',0),self.root,self.code,time.time()+600);self.thread=threading.Thread(target=self.server.serve_forever);self.thread.start()
 def tearDown(self):self.server.shutdown();self.server.server_close();self.thread.join();self.temp.cleanup()
 def request(self,method,path='/',value=None,headers=None):
  c=http.client.HTTPConnection('127.0.0.1',self.server.server_port);h={'Host':self.server.hostname,**(headers or {})}
  body=json.dumps(value) if value is not None else None
  if body is not None:h['Content-Type']='application/json'
  c.request(method,path,body=body,headers=h);r=c.getresponse();data=r.read();result=(r.status,dict(r.getheaders()),data);c.close();return result
 def session(self):
  status,h,body=self.request('GET');self.assertEqual(status,200);csrf=re.search(r"data.csrf='([^']+)'",body.decode()).group(1)
  return dict(FIELDS,csrf=csrf,setup_code=self.code),{'Cookie':h['Set-Cookie'].split(';')[0],'Origin':self.server.origin}
 def test_form_and_cli_share_config_no_send(self):
  v,h=self.session();status,_,_=self.request('POST','/save',v,h);self.assertEqual(status,200)
  actual=json.loads((self.root/'config.json').read_text());self.assertEqual(actual,validate_initial(FIELDS,self.root));self.assertFalse(actual['outbound_enabled']);self.assertFalse(actual['inbox_full_body_verified'])
  with sqlite3.connect(self.root/'messages.db') as db:self.assertEqual(db.execute('SELECT count(*) FROM messages').fetchone()[0],0);self.assertEqual(db.execute('SELECT count(*) FROM contacts').fetchone()[0],1)
  self.assertEqual((self.root/'config.json').stat().st_mode&0o777,0o600);self.assertEqual(self.request('POST','/save',v,h)[0],403)
 def test_origin_host_csrf_and_code_required(self):
  v,h=self.session()
  for value,headers in [(v,dict(h,Origin='https://evil.invalid')),(v,dict(h,Host='evil.invalid')),(dict(v,csrf='bad'),h),(dict(v,setup_code='bad'),h)]:self.assertEqual(self.request('POST','/save',value,headers)[0],403)
  self.assertFalse((self.root/'config.json').exists())
 def test_expiry_and_existing_configuration_preserved(self):
  v,h=self.session();self.server.expires=time.time()-1;self.assertEqual(self.request('POST','/save',v,h)[0],403)
  self.server.expires=time.time()+600;save_initial(self.root,FIELDS);before=(self.root/'config.json').read_bytes();self.assertEqual(self.request('POST','/save',v,h)[0],409);self.assertEqual(before,(self.root/'config.json').read_bytes())
 def test_private_ip_international_number_and_safe_defaults(self):
  for field,value in [('gateway_url','https://8.8.8.8'),('gateway_url','http://user:pass@127.0.0.1'),('gateway_url','http://127.0.0.1/message'),('owner_number','2025550123')]:
   with self.assertRaises(ValueError):validate_initial(dict(FIELDS,**{field:value}),self.root)
  with self.assertRaises(ValueError):SetupServer(('0.0.0.0',0),self.root,self.code,time.time()+60)
 def test_bad_input_does_not_claim_storage(self):
  with self.assertRaises(ValueError):save_initial(self.root,dict(FIELDS,owner_number='national-only'))
  self.assertFalse((self.root/'setup.claim').exists());save_initial(self.root,FIELDS)
if __name__=='__main__':unittest.main()
