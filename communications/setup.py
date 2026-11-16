"""Optional temporary loopback setup; no gateway calls or message sends."""
import argparse
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import secrets
import signal
import threading
import time
from datetime import datetime,timezone
from http.cookies import SimpleCookie
from .common import atomic_private_json
from .configuration import private_directory,save_initial,validate_initial
from .server import Server,Handler,strict_json

PAGE = '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">\n<title>Agent SMS Bridge setup</title><style>\n:root{font-family:system-ui,-apple-system,sans-serif;color:#172b2b;background:#f3f6f4}*{box-sizing:border-box}\nbody{margin:0;padding:32px 18px}main{max-width:660px;margin:auto;background:white;padding:32px;border-radius:18px;box-shadow:0 8px 32px #15352b10}\nh1{font-size:28px;margin:10px 0}p{line-height:1.55;color:#45605a}.eyebrow{font-size:12px;text-transform:uppercase;letter-spacing:.12em;color:#21755d}\nlabel{display:block;font-weight:650;margin-top:22px}input{width:100%;padding:12px;margin-top:7px;border:1px solid #bacbc4;border-radius:8px;font:inherit;color:inherit}\ninput:focus{outline:2px solid #28866c;outline-offset:2px}small{display:block;font-size:13px;color:#60716b;margin-top:6px;line-height:1.45}\n.row{display:grid;grid-template-columns:1fr 1fr;gap:18px}.note{padding:12px 15px;background:#edf5f0;border-radius:8px;font-size:14px}\nbutton{margin-top:25px;border:0;border-radius:9px;background:#17664f;color:white;padding:13px 20px;font:inherit;font-weight:650;cursor:pointer}\nbutton:disabled{opacity:.65;cursor:wait}#error{color:#a12d24;white-space:pre-wrap}a{color:#17664f}footer{font-size:12px;color:#60716b;margin-top:22px}\n@media(max-width:520px){main{padding:22px}.row{grid-template-columns:1fr;gap:0}h1{font-size:25px}}\n</style><main><div class="eyebrow">Private · one-time setup</div><h1>Agent SMS Bridge</h1>\n<p>Connect your SMS device. Open SMSGate on your Android phone, then copy the Local Server details below. This temporary form is available only through a loopback connection. Enter the setup code from the private file created by the setup command.</p>\n<p class="note">Available until <strong>__EXPIRY__</strong>. It closes after a successful save. Saving does not send a text.</p>\n<form id="setup" autocomplete="off"><label for="setup_code">Setup code</label><input id="setup_code" name="setup_code" type="password" required autocomplete="off"><small>Read the code from your private setup-code.json file. Never paste it into a public URL.</small>\n<label for="gateway_url">Local Server URL</label><input id="gateway_url" name="gateway_url" type="url" required maxlength="250" placeholder="http://192.168.x.x:8080" spellcheck="false" autocapitalize="none">\n<small>On SMSGate’s Home tab, find the running Local Server card. Use its local/private IP and port, usually 8080. Don’t use the public IP or add /message.</small>\n<div class="row"><div><label for="gateway_username">SMSGate username</label><input id="gateway_username" name="gateway_username" required maxlength="512" spellcheck="false" autocapitalize="none"></div>\n<div><label for="gateway_password">SMSGate password</label><input id="gateway_password" name="gateway_password" type="password" required maxlength="2048" autocomplete="off"></div></div>\n<small>Use the credentials shown in SMSGate’s Local Server section. Your Google and phone account passwords are not used.</small>\n<label for="installed_version">SMSGate version</label><input id="installed_version" name="installed_version" maxlength="100"  placeholder="Version and build, if shown">\n<small>Record the exact installed version. The adapter contract was validated against SMSGate 1.78.3; verify full incoming content on your own installation before enabling it.</small>\n<div class="row"><div><label for="owner_name">Your name <span style="font-weight:400">(optional)</span></label><input id="owner_name" name="owner_name" maxlength="100" placeholder="Owner"></div>\n<div><label for="owner_number">Your authorized phone number</label><input id="owner_number" name="owner_number" type="tel" required maxlength="40" placeholder="+country code …"></div></div>\n<small>This is the only number initially allowed to receive outgoing texts. Include the country code.</small>\n<label for="device_number">Device’s mobile number <span style="font-weight:400">(optional)</span></label><input id="device_number" name="device_number" type="tel" maxlength="40" placeholder="Leave blank if unsure">\n<small>The device SIM’s phone number, not its IP address. It helps label outgoing messages; it is not required to connect.</small>\n<p id="error" role="alert"></p><button id="save" type="submit">Save private setup</button></form>\n<footer>Saved only in protected storage on the server. This form listens on loopback only. Use an authenticated SSH tunnel for remote setup. An http:// device API needs a separately encrypted tunnel; use verified HTTPS where supported.\n<br><a href="https://docs.sms-gate.app/getting-started/local-server/" target="_blank" rel="noreferrer noopener">Official SMSGate Local Server guide</a></footer>\n</main><script nonce="__NONCE__">\nconst form=document.getElementById(\'setup\'),button=document.getElementById(\'save\'),error=document.getElementById(\'error\');\nform.addEventListener(\'submit\',async event=>{event.preventDefault();button.disabled=true;error.textContent=\'\';\ntry{const data=Object.fromEntries(new FormData(form));data.csrf=\'__CSRF__\';\nconst response=await fetch(\'/save\',{method:\'POST\',credentials:\'same-origin\',headers:{\'Content-Type\':\'application/json\'},body:JSON.stringify(data)});\nconst result=await response.json();if(!response.ok)throw new Error(result.error||\'Setup could not be saved.\');\nform.reset();document.querySelector(\'main\').innerHTML=\'<div class="eyebrow">Saved privately</div><h1>You’re all set.</h1><p>The setup page is now closed. Run the documented connection and full-content checks before enabling outbound messages. No message was sent by this form.</p>\';\n}catch(problem){error.textContent=problem.message;button.disabled=false;}});\n</script></html>'

class SetupServer(Server):
    def __init__(self,address,root,setup_code,expires):
        if not ipaddress.ip_address(address[0]).is_loopback:raise ValueError('loopback_setup_only')
        self.root=private_directory(root)
        self.code_hash=hashlib.sha256(setup_code.encode()).digest()
        self.expires=expires;self.sessions={};self.guard=threading.Lock();self.done=threading.Event();self.saved=False
        super().__init__(address,None,{})
        self.hostname=address[0]+':'+str(self.server_port);self.origin='http://'+self.hostname
        self.RequestHandlerClass=SetupHandler

class SetupHandler(Handler):
    def handle_route(self,method):
        try:
            if (not ipaddress.ip_address(self.client_address[0]).is_loopback or time.time()>=self.server.expires
                or self.server.saved or self.headers.get('Host')!=self.server.hostname or len(self.headers.get_all('Host',[]))!=1):
                return self.response(403,{'error':'Setup is closed or unavailable.'})
            if method=='GET' and self.path=='/':
                if self.headers.get('Origin') not in (None,self.server.origin):
                    return self.response(403,{'error':'Open the setup address directly.'})
                session,csrf,nonce=(secrets.token_urlsafe(32) for _ in range(3))
                with self.server.guard:
                    if len(self.server.sessions)>=16:self.server.sessions.pop(next(iter(self.server.sessions)))
                    self.server.sessions[session]=csrf
                expiry=datetime.fromtimestamp(self.server.expires,timezone.utc).strftime('%H:%M UTC')
                body=PAGE.replace('__EXPIRY__',expiry).replace('__CSRF__',csrf).replace('__NONCE__',nonce).encode()
                self.send_response(200)
                for k,v in {'Content-Type':'text/html; charset=utf-8','Content-Length':str(len(body)),
                    'Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY',
                    'Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-"+nonce+"'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
                    'Set-Cookie':'setup_session='+session+'; HttpOnly; SameSite=Strict; Path=/; Max-Age='+str(max(0,int(self.server.expires-time.time()))),
                    'Connection':'close'}.items():self.send_header(k,v)
                self.end_headers();self.wfile.write(body)
            elif method=='POST' and self.path=='/save':
                if self.headers.get('Origin')!=self.server.origin or len(self.headers.get_all('Origin',[]))!=1:
                    return self.response(403,{'error':'Origin rejected.'})
                if int(self.headers.get('Content-Length','0'))>16384:raise ValueError('too-large')
                value=strict_json(self.body());cookie=SimpleCookie();cookie.load(self.headers.get('Cookie',''))
                session=cookie.get('setup_session');csrf=self.server.sessions.get(session.value) if session else None
                if not isinstance(value,dict) or not csrf or not isinstance(value.get('csrf'),str) or not hmac.compare_digest(value['csrf'],csrf):
                    return self.response(403,{'error':'Reload the setup page.'})
                code=value.get('setup_code')
                if not isinstance(code,str) or not hmac.compare_digest(hashlib.sha256(code.encode()).digest(),self.server.code_hash):
                    return self.response(403,{'error':'Setup code rejected.'})
                value={k:v for k,v in value.items() if k not in ('csrf','setup_code')}
                validate_initial(value,self.server.root)
                with self.server.guard:
                    if self.server.saved or time.time()>=self.server.expires or (self.server.root/'config.json').exists():
                        return self.response(409,{'error':'Setup already saved or closed.'})
                    save_initial(self.server.root,value);self.server.saved=True;self.server.sessions.clear()
                try:self.response(200,{'saved':True})
                finally:self.server.done.set()
            else:self.response(404,{'error':'Not found.'})
        except (ValueError,TypeError):self.response(400,{'error':'Check the private IP URL, credentials and explicit international phone numbers.'})
        except (BrokenPipeError,ConnectionError,TimeoutError):pass
        except Exception:self.response(503,{'error':'Setup failed. Inspect private configuration before retrying; no credentials logged.'})


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--data-dir',type=Path,required=True)
    p.add_argument('--port',type=int,default=4192);p.add_argument('--expires-seconds',type=int,default=600)
    args=p.parse_args();os.umask(0o077)
    if not 60<=args.expires_seconds<=1800:raise ValueError('expiry_out_of_range')
    root=private_directory(args.data_dir)
    if (root/'config.json').exists() or (root/'setup.claim').exists():raise ValueError('setup_already_saved_or_recovery_required')
    code=secrets.token_urlsafe(32);atomic_private_json(root/'setup-code.json',{'setup_code':code})
    server=SetupServer(('127.0.0.1',args.port),root,code,time.time()+args.expires_seconds)
    for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,lambda *_:server.done.set())
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    print(json.dumps({'url':server.origin+'/','setup_code_file':str(root/'setup-code.json'),'expires_seconds':args.expires_seconds}),flush=True)
    server.done.wait(timeout=max(0,server.expires-time.time()));server.shutdown();server.server_close();thread.join(timeout=5)
    print('setup_closed',flush=True)

if __name__=='__main__':
    try:main()
    except Exception as e:raise SystemExit('setup_failed:'+type(e).__name__) from None
