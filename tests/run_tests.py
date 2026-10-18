#!/usr/bin/env python3
import http.server
import importlib.util
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('webscope_engine', ROOT/'lib/engine.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
passed = 0

def ok(condition, label):
    global passed
    if not condition:
        raise AssertionError(label)
    passed += 1
    print('PASS '+label, flush=True)

class Handler(http.server.BaseHTTPRequestHandler):
    events = []
    external_port = None
    slow = False
    simple = False
    received = threading.Event()
    def log_message(self, *args):
        pass
    def do_HEAD(self):
        self.respond(False)
    def do_GET(self):
        self.respond(True)
    def respond(self, body):
        Handler.events.append((self.command, self.headers.get('Host'), self.path))
        Handler.received.set()
        if Handler.slow:
            time.sleep(2)
        port = self.server.server_address[1]
        scheme = 'https' if isinstance(self.connection, ssl.SSLSocket) else 'http'
        origin = f'{scheme}://fixture.test:{port}'
        status = 200
        ctype = 'text/html'
        content = '<html><a href="/docs/start">Docs</a></html>'
        location = None
        if self.path == '/':
            content = f'''<html><script src="/app.js"></script><script src="/huge.js"></script>
            <script src="/query.js?token=DO_NOT_EXPORT_QUERY"></script>
            <a href="/.env">Environment</a><a href="/backup.sql">Backup</a>
            <a href="/docs/start">Docs</a><a href="/logout">Log out</a>
            <a href="/private/secret">Private</a><a href="/redirect-local">Local redirect</a>
            <a href="/redirect-external">External redirect</a><a href="/encoded%2f.env">Encoded</a>
            <a href="{scheme}://sub.fixture.test:{port}/child">Child</a>
            <a href="http://outside.invalid/">Outside</a>
            <script>const client_secret="SYNTHETIC_INLINE_DO_NOT_EXPORT";</script></html>'''
        elif self.path == '/robots.txt':
            ctype = 'text/plain'
            content = f'User-agent: *\nDisallow: /private/\nSitemap: {origin}/sitemap.xml\n'
        elif self.path == '/sitemap.xml':
            ctype = 'application/xml'
            content = f'<urlset><url><loc>{origin}/docs/sitemap</loc></url><url><loc>{origin}/db.sqlite</loc></url></urlset>'
        elif self.path == '/app.js':
            ctype = 'application/javascript'
            content = 'const api_key="SYNTHETIC_JS_DO_NOT_EXPORT"; import("./chunk.js"); fetch("/api/data");\n//# sourceMappingURL=app.js.map'
        elif self.path == '/chunk.js':
            ctype = 'application/javascript'
            content = 'export const ready=true;'
        elif self.path == '/huge.js':
            ctype = 'application/javascript'
            content = 'x'*70000
        elif self.path in ('/.env', '/backup.sql', '/db.sqlite', '/app.js.map'):
            ctype = 'text/plain'
            content = 'PRIVATE_BODY_MUST_NOT_BE_REQUESTED'
        elif self.path == '/api/data':
            ctype = 'application/json'
            content = '{"private":"MUST_NOT_FETCH_API"}'
        elif self.path == '/redirect-local':
            status = 302
            location = '/docs/redirected'
        elif self.path == '/redirect-external':
            status = 302
            location = 'http://outside.invalid/private?token=DO_NOT_EXPORT_REDIRECT'
        if self.path == '/' and Handler.simple:
            content='<html><script src="/app.js"></script></html>'
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Set-Cookie', 'session=DO_NOT_EXPORT_COOKIE; Secure; HttpOnly; SameSite=Lax')
        self.send_header('X-Content-Type-Options', 'nosniff')
        if location:
            self.send_header('Location', location)
        # Deliberately hide oversized body length from HEAD, exercise actual GET cap.
        self.send_header('Content-Length', str(len(content.encode()) if body or self.path != '/huge.js' else 0))
        self.end_headers()
        if body:
            try:
                self.wfile.write(content.encode())
            except (BrokenPipeError, ConnectionResetError):
                pass

with tempfile.TemporaryDirectory(prefix='webscope-tests-') as tmp:
    t = Path(tmp)
    bindir = t/'bin'
    bindir.mkdir()
    dig = bindir/'dig'
    dig.write_text('''#!/usr/bin/env python3
import os,sys
from pathlib import Path
host,typ=sys.argv[-2:]
mode=os.environ.get('FIXTURE_DNS_MODE','local')
if not host.endswith('fixture.test'):
 print('unexpected fixture DNS name',file=sys.stderr);sys.exit(2)
print(';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1')
if mode=='servfail':
 print(';; status: SERVFAIL');sys.exit(1)
if typ=='AAAA' and mode=='ipv6':print(f'{host}. 30 IN AAAA ::1')
if typ=='A' and mode!='ipv6':
 ip='169.254.169.254' if mode=='metadata' else '127.0.0.1'
 print(f'{host}. 30 IN A {ip}')
 if mode=='mixed':print(f'{host}. 30 IN A 169.254.169.254')
if typ=='CNAME' or mode=='cname' and typ=='A':
 print(f'{host}. 30 IN CNAME unapproved.github.io.')
if typ=='TXT':print(f'{host}. 30 IN TXT "DO_NOT_EXPORT_TXT"')
''')
    dig.chmod(0o755)
    env = os.environ.copy()
    env.update({'PATH': str(bindir)+':'+env['PATH'], 'HTTP_PROXY':'http://127.0.0.1:1', 'HTTPS_PROXY':'http://127.0.0.1:1', 'ALL_PROXY':'http://127.0.0.1:1'})
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    def cli(extra=(), output=None, mode='local', timeout=80):
        e = env.copy()
        e['FIXTURE_DNS_MODE'] = mode
        return subprocess.run([str(ROOT/'webscope.sh'), 'fixture.test', '--authorized', '--include-subdomains', '--allow-http', '--port', str(port), '--allow-nonpublic', '--cidr', '127.0.0.0/8', '--timeout', '1', '--rate', '10', '--budget', '60', '--output', str(output or t/'reports')]+list(extra), env=e, text=True, capture_output=True, timeout=timeout)
    def report(output):
        runs = sorted(Path(output).glob('run-*'))
        return json.loads((runs[-1]/'report.json').read_text()), runs[-1]
    try:
        args = m.parser().parse_args(['fixture.test', '--include-subdomains'])
        scope = m.validate(args)
        for host, expected in [('fixture.test', True), ('a.fixture.test', True), ('badfixture.test', False), ('fixture.test.attacker.invalid', False), ('127.0.0.1', False), ('x;touch.fixture.test', False)]:
            ok(scope.host(host) == expected, 'exact host boundary '+host)
        ok(scope.url('https://FIXTURE.test./')[0]=='https://fixture.test/','URL host case and trailing dot canonicalized')
        canonical=m.Engine(args,scope,t,None,time.monotonic()+5)
        canonical.host('API.FIXTURE.TEST.','fixture')
        ok('api.fixture.test' in canonical.hosts,'candidate names canonicalized before queueing')
        for value in ['http://fixture.test/', 'https://fixture.test:22/', 'https://user:password@fixture.test/', 'https://fixture.test/a%2fb', 'https://fixture.test/a/../b', 'https://fixture.test/.%2e/', 'https://fixture.test/ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789']:
            try:
                scope.url(value)
                accepted = True
            except m.PolicyError:
                accepted = False
            ok(not accepted, 'reject unsafe or unapproved URL '+value.split('@')[-1])
        url, query = scope.url('https://fixture.test/app.js?secret=DO_NOT_EXPORT#client')
        ok(query and url == 'https://fixture.test/app.js', 'query values omitted; caller must not request query references')
        for value in ['/.env', '/backup.sql', '/config.json', '/app.js.map', '/db.sqlite', '/.git/config', '/id_rsa']:
            ok(scope.sensitive('https://fixture.test'+value), 'URLMiner-derived sensitive classification '+value)
        ok(not scope.sensitive('https://fixture.test/app.js'), 'normal JS remains eligible')
        p = cli(['--dry-run'], output=t/'dry')
        ok(p.returncode == 0 and not (t/'dry').exists() and not Handler.events, 'dry-run causes no output or target requests')
        p = subprocess.run([str(ROOT/'webscope.sh'), 'fixture.test', '--output', str(t/'unauthorized')], env=env, capture_output=True)
        ok(p.returncode == 2 and not (t/'unauthorized').exists(), 'authorization acknowledgement required')
        p = cli(['--ct', '--dry-run'], output=t/'dry-ct')
        ok(p.returncode == 0, 'explicit CT plan accepted without network')
        p = subprocess.run([str(ROOT/'webscope.sh'), 'fixture.test', '--ct', '--dry-run'], env=env, capture_output=True)
        ok(p.returncode == 2, 'CT requires domain-tree authorization')
        p = cli(output=t/'main')
        if p.returncode not in (0, 3):
            raise AssertionError((p.returncode,p.stdout,p.stderr))
        r, run = report(t/'main')
        ok(r['completion'] == 'partial' and any('REQUEST_FAILED' in x for x in r['errors']), 'oversized native response produces partial coverage')
        ok(len(r['hosts']) == 2, 'root and linked subdomain discovered without guessed names')
        ok(all(x['host'].endswith('fixture.test') for x in r['hosts']), 'no outside assets enter inventory')
        paths = {m.urlsplit(x['url']).path:x for x in r['urls']}
        ok('/app.js' in paths and '/chunk.js' in paths, 'HTML script and JS import discovery')
        ok(paths['/app.js']['status'] == 'BOUNDED_PUBLIC_DOCUMENT_PARSED', 'actual bounded public JS GET parsed')
        ok('/api/data' in paths and 'route_hint' in paths['/api/data']['kinds'], 'JS route hints exported without API execution')
        ok('/docs/sitemap' in paths, 'root sitemap locations imported')
        ok('/docs/redirected' in paths, 'approved redirect requeued through scope validation')
        ok(r['rejected_counts'].get('HOST_NOT_APPROVED',0)>0, 'external links and redirect blocked')
        for path in ['/.env','/backup.sql','/db.sqlite','/app.js.map']:
            ok(paths[path]['status'] == 'METADATA_ONLY_REVIEW_REQUIRED', 'HTTP 200 sensitive candidate remains unconfirmed '+path)
            ok(not any(method=='GET' and request_path==path for method,host,request_path in Handler.events), 'no sensitive body download '+path)
        for path in ['/api/data','/query.js','/logout','/private/secret']:
            ok(not any(method=='GET' and request_path.startswith(path) for method,host,request_path in Handler.events), 'no unsafe/body request '+path)
        ok(not any(p=='/private/secret' for _,_,p in Handler.events), 'robots disallow respected even for HEAD')
        ok(not any('outside.invalid' in (host or '') for _,host,_ in Handler.events), 'no external redirect connection')
        ok(r['potential_js_literals'] and all(x['value']=='[REDACTED]' for x in r['potential_js_literals']), 'potential JS literals redacted and never validated')
        ok(r['headers'] and r['headers'][0]['cookie_flags'][0]['secure'], 'original HeaderGuard offline normalization and safe cookie flags')
        ok(any('GitHub Pages' in x.get('provider_hints',[]) for x in r['dns']), 'original DNSShield CNAME provider classifier used offline')
        combined=''.join(p.read_text() for p in run.rglob('*') if p.is_file())
        for secret in ['SYNTHETIC_INLINE_DO_NOT_EXPORT','SYNTHETIC_JS_DO_NOT_EXPORT','DO_NOT_EXPORT_QUERY','DO_NOT_EXPORT_COOKIE','DO_NOT_EXPORT_TXT','DO_NOT_EXPORT_REDIRECT','PRIVATE_BODY_MUST_NOT_BE_REQUESTED','MUST_NOT_FETCH_API']:
            ok(secret not in combined, 'sensitive marker absent from persisted reports '+secret)
        ok(not list(run.glob('.work-*')), 'temporary response bodies and headers removed')
        ok(not (run/'INCOMPLETE').exists(),'finalized report clears incomplete marker')
        ok(all(not p.stat().st_mode & 0o077 for p in run.rglob('*')), 'private file and directory permissions')
        ok('https://fixture.test' not in combined, 'fixture requests preserve explicit HTTP scheme')
        ok(all(v in r['integrations'] for v in ['ReconScope','URLMiner','DNSShield','HeaderGuard','TLSWatch','SurfaceIntel']), 'all six integration roles explicitly declared')
        longname='.'.join(['a'*55]*4)+'.fixture.test'
        large=','.join([longname]*600)
        normalized=m.local(['bash',str(ROOT/'adapters/reconscope-local.sh')],input_bytes=large.encode())
        ok(normalized==large,'large hostname normalization uses bounded stdin, not oversized argv')
        imported=t/'hosts.txt';imported.write_text('api.fixture.test\nOUTSIDE.INVALID\nbad;touch.fixture.test\n')
        p=cli(['--import-hosts',str(imported),'--max-requests','1'],output=t/'import')
        ir,_=report(t/'import')
        ok(any(h['host']=='api.fixture.test' for h in ir['hosts']), 'ReconScope local normalization/import adapter executed')
        ok(not any(h['host']=='outside.invalid' for h in ir['hosts']), 'imported external names filtered')
        ok('REQUEST_LIMIT' in ir['errors'], 'request cap stops collection and reports partial')
        for mode in ['metadata','mixed','cname','servfail']:
            before=len(Handler.events)
            p=cli(['--max-requests','2'],output=t/mode,mode=mode)
            rr,_=report(t/mode)
            ok(p.returncode==3 and len(Handler.events)==before, 'native transport blocks unsafe/incomplete DNS '+mode)
        before=len(Handler.events)
        p=subprocess.run([str(ROOT/'webscope.sh'),'fixture.test','--authorized','--allow-http','--port',str(port),'--timeout','1','--rate','10','--max-requests','1','--output',str(t/'no-private')],env=env,capture_output=True)
        ok(p.returncode==3 and len(Handler.events)==before, 'loopback forbidden without explicit nonpublic authorization')
        bad=t/'bad-input';bad.write_bytes(b'host\0injection')
        p=cli(['--import-hosts',str(bad),'--dry-run'],output=t/'bad-dry')
        ok(p.returncode==2 and not (t/'bad-dry').exists(), 'malformed imports fail before output/network')
        unsafe=t/'unsafe';unsafe.mkdir(mode=0o755);unsafe.chmod(0o755)
        p=cli(output=unsafe)
        ok(p.returncode==2, 'unsafe existing report permissions refused')
        symlink=t/'symlink';symlink.symlink_to(t/'main',target_is_directory=True)
        p=cli(output=symlink)
        ok(p.returncode==2, 'output symlinks refused')
        locked=t/'locked';locked.mkdir(mode=0o700)
        import fcntl
        with (locked/'.lock').open('w') as lock:
            os.chmod(locked/'.lock',0o600);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            p=cli(output=locked)
            ok(p.returncode==75, 'overlapping output lock refused')
        cert=t/'public-cert.pem';key=t/'fixture-key.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=fixture.test','-addext','subjectAltName=DNS:fixture.test','-keyout',str(key),'-out',str(cert)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
        p=cli(['--ca-file',str(key),'--dry-run'],output=t/'bad-ca')
        ok(p.returncode==2 and not (t/'bad-ca').exists(),'private key rejected as CA configuration before output/network')
        tlsserver=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(cert,key)
        tlsserver.socket=ctx.wrap_socket(tlsserver.socket,server_side=True)
        threading.Thread(target=tlsserver.serve_forever,daemon=True).start()
        tlsport=tlsserver.server_address[1]
        try:
            p=subprocess.run([str(ROOT/'webscope.sh'),'fixture.test','--authorized','--port',str(tlsport),'--allow-nonpublic','--cidr','127.0.0.0/8','--ca-file',str(cert),'--timeout','2','--rate','10','--max-requests','4','--output',str(t/'tls')],env=env,text=True,capture_output=True,timeout=35)
            tr,_=report(t/'tls')
            ok(any(x['engine']=='TLSWatch-local-certificate' for x in tr['tls']), 'actual TLSWatch certificate helper runs on locally collected public leaf')
            ok(any(x['engine']=='SurfaceIntel' and x.get('severity')=='CRITICAL' for x in tr['tls']), 'SurfaceIntel native TLS expiry classification retained')
            ok(any(x.get('check')=='Hostname match' and x['status']=='PASS' for x in tr['tls']), 'native local TLS hostname validation')
            ok(any(x.get('status')=='RESPONSE_RECEIVED' or x.get('body_sha256') for x in tr['urls']), 'HTTPS requests use explicit fixture CA without insecure retry')
        finally:
            tlsserver.shutdown();tlsserver.server_close()
        # Additional scope and adapter regressions; CT responses are synthetic only.
        p=cli(['--dry-run']+['--port','80']*17,output=t/'too-many-ports')
        ok(p.returncode==2 and not (t/'too-many-ports').exists(),'oversized option lists refused before network')
        for switches,label in [(['--cidr','127.0.0.1/8'],'non-network CIDR'),(['--port','0'],'invalid port'),(['--rate','0'],'unbounded rate'),(['--exclude','fixture.test'],'excluded root')]:
            p=cli(switches+['--dry-run'],output=t/'invalid-plan')
            ok(p.returncode==2 and not (t/'invalid-plan').exists(),'dry validation rejects '+label)
        try:
            scope.url('https://fixture.test/token=PRIVATE_PATH_VALUE')
            accepted=True
        except m.PolicyError:accepted=False
        ok(not accepted,'credential-shaped URL path omitted before persistence')
        ex=m.Scope(m.parser().parse_args(['fixture.test','--include-subdomains','--exclude','sub.fixture.test','--exclude-path','/internal/']))
        ok(not ex.host('a.sub.fixture.test') and ex.host('api.fixture.test'),'excluded subtree boundaries')
        try:
            ex.url('https://fixture.test/internal/doc')
            accepted=True
        except m.PolicyError:accepted=False
        ok(not accepted,'path exclusion checked before requests')
        htmlparser=m.Links();htmlparser.feed('<form action="/delete"><input name="password"></form><script src="/good.js"></script>')
        ok(htmlparser.links==[('/good.js','javascript')],'forms are not submitted or crawled')
        offline=m.Engine(args,scope,t,None,time.monotonic()+5)
        offline.parse('https://fixture.test/robots.txt','robots',0,'text/plain',b'User-agent: *\nDisallow: /admin/\nDisallow: *\n')
        ok('/' in offline.robots['https://fixture.test'],'robots wildcard conservatively blocks all paths')
        ok('https://fixture.test/admin/' in offline.urls,'robots directories recorded without content requests')
        class FakeCT:
            def __init__(self,payload):self.payload=payload
            def call(self,*args):return {'status':'200','reason':'RESPONSE_RECEIVED','body':'fixture'}
            def bytes(self,*args):return json.dumps(self.payload).encode()
        for payload,expected in [([{'name_value':'ct.fixture.test\n*.fixture.test\noutside.invalid'}],True),({'invalid':'shape'},False)]:
            ca=m.parser().parse_args(['fixture.test','--include-subdomains','--ct','--max-requests','1'])
            ce=m.Engine(ca,m.validate(ca),t,FakeCT(payload),time.monotonic()+5)
            try:ce.discover()
            except m.BudgetError:pass
            ok(('ct.fixture.test' in ce.hosts)==expected,'CT parser fixture candidate acceptance '+str(expected))
            ok('outside.invalid' not in ce.hosts and '*.fixture.test' not in ce.hosts,'CT names remain strictly scoped')
            if not expected:ok('CT_UNAVAILABLE_OR_BOUNDED' in ce.errors,'CT outage retains configured root with incomplete coverage')
        p=cli(['--allow-cname','unapproved.github.io','--max-requests','1'],output=t/'allowed-cname',mode='cname')
        ar,_=report(t/'allowed-cname')
        ok(any(x['http_status']==200 for x in ar['urls']),'explicit CNAME approval permits pinned original-host request')
        Handler.slow=True;Handler.received.clear()
        try:
            p=cli(['--max-requests','1'],output=t/'timeout')
            rr,_=report(t/'timeout')
            ok(p.returncode==3 and any('REQUEST_FAILED' in e for e in rr['errors']),'native HTTP timeout produces partial report')
            Handler.received.clear()
            cmd=[str(ROOT/'webscope.sh'),'fixture.test','--authorized','--allow-http','--port',str(port),'--allow-nonpublic','--cidr','127.0.0.0/8','--rate','10','--timeout','5','--output',str(t/'signal')]
            proc=subprocess.Popen(cmd,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            ok(Handler.received.wait(10),'interrupt test reached owned local service')
            proc.terminate();stdout,stderr=proc.communicate(timeout=10)
            sr,srun=report(t/'signal')
            ok(proc.returncode==143 and 'INTERRUPTED' in sr['errors'],'SIGTERM preserves explicit partial report and exit status')
            ok(not list(srun.glob('.work-*')),'SIGTERM removes private transient response files')
        finally:Handler.slow=False
        import socket
        class IPv6Server(http.server.ThreadingHTTPServer):address_family=socket.AF_INET6
        v6=IPv6Server(('::1',0),Handler)
        threading.Thread(target=v6.serve_forever,daemon=True).start()
        try:
            e=env.copy();e['FIXTURE_DNS_MODE']='ipv6'
            p=subprocess.run([str(ROOT/'webscope.sh'),'fixture.test','--authorized','--allow-http','--port',str(v6.server_address[1]),'--allow-nonpublic','--cidr','::1/128','--rate','10','--timeout','1','--max-requests','1','--output',str(t/'ipv6')],env=e,capture_output=True,timeout=20)
            vr,_=report(t/'ipv6')
            ok(any(x['http_status']==200 for x in vr['urls']),'native IPv6 loopback request pinned through SurfaceIntel')
        finally:v6.shutdown();v6.server_close()
        Handler.simple=True
        try:
            p=cli(output=t/'complete')
            cr,cleanrun=report(t/'complete')
            ok(p.returncode==0 and cr['completion']=='complete_within_declared_limits' and not cr['errors'],'complete owned-local end-to-end run exits zero')
        finally:Handler.simple=False
        import jsonschema
        schema=json.loads((ROOT/'schemas/report.schema.json').read_text())
        for output in [t/'main',t/'tls',t/'ipv6',t/'signal',t/'complete']:
            rr,_=report(output);jsonschema.Draft202012Validator(schema).validate(rr)
            ok(True,'JSON schema validation '+output.name)
        if os.environ.get('WEBSCOPE_WRITE_SAMPLES')=='1':
            dst=ROOT/'examples/controlled-local'
            shutil.rmtree(dst,ignore_errors=True)
            shutil.copytree(run,dst)
            clean_dst=ROOT/'examples/complete-local'
            shutil.rmtree(clean_dst,ignore_errors=True)
            shutil.copytree(cleanrun,clean_dst)
    finally:
        server.shutdown();server.server_close()
print(f'RESULT: {passed} passed, 0 failed')
