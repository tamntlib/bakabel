"""FIXTURE ONLY real Unix HTTP relay. No Engine reply/inventory manipulation.
Only unsupported nested ContainerCreate CPU keys are removed under independently
measured outer aggregate 2-core quota. This does NOT prove inner cgroups.
"""
import copy, http.client, http.server, json, select, socket, socketserver, threading

CPU_KEYS=('NanoCpus','CpusetCpus','CpusetMems')
def normalize_create(value):
    result=copy.deepcopy(value); host=result.get('HostConfig',{})
    omitted={k:host.pop(k) for k in CPU_KEYS if k in host}
    return result,omitted

def validate_isolation(inner,outer,quota,affinity):
    assert inner and outer and inner!=outer, 'requires distinct real daemon IDs'
    assert quota=='200000 100000', 'requires measured outer aggregate 2CPU quota'
    assert affinity in ('0-1','0,1'), 'requires measured outer PID1 affinity 0,1'

class HijackResponse(http.client.HTTPResponse):
    def __init__(self,sock,*args,**kwargs):
        super().__init__(sock,*args,**kwargs)
        self.fp.close()
        # Keep readline/read1 semantics, but never prefetch any upgraded bytes.
        import io
        self.fp=io.BufferedReader(sock.makefile('rb',buffering=0),buffer_size=1)

class UnixConnection(http.client.HTTPConnection):
    def __init__(self,path): super().__init__('localhost',timeout=180); self.path=str(path)
    def connect(self):
        self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); self.sock.settimeout(180); self.sock.connect(self.path)

def tunnel(front,back):
    readers=[front,back]
    while readers:
        ready,_,_=select.select(readers,[],[],180)
        if not ready: raise TimeoutError('fixture relay hijack idle deadline')
        for src in ready:
            dst=back if src is front else front
            data=src.recv(65536)
            if not data:
                readers.remove(src)
                dst.shutdown(socket.SHUT_WR)
            else: dst.sendall(data)

class Server(socketserver.ThreadingMixIn,socketserver.UnixStreamServer):
    daemon_threads=True

class Relay:
    def __init__(self,path,target,log,*,inner,outer,quota,affinity):
        validate_isolation(inner,outer,quota,affinity)
        self.path=str(path); self.target=str(target); self.log=log; self.lock=threading.Lock(); self.records=[]
        relay=self
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version='HTTP/1.1'; rbufsize=0; wbufsize=0
            def log_message(self,*args): pass
            def do_GET(self): self.proxy()
            do_POST=do_DELETE=do_PUT=do_HEAD=do_GET
            def proxy(self):
                conn=UnixConnection(relay.target)
                try:
                    n=int(self.headers.get('Content-Length',0)); body=self.rfile.read(n) if n else None
                    if self.command=='POST' and self.path.split('?')[0].endswith('/containers/create'):
                        value=json.loads(body); value,omitted=normalize_create(value)
                        record={'path':self.path,'omitted':omitted,'image':value.get('Image'),'entrypoint':value.get('Entrypoint'),'cmd':value.get('Cmd'),'env':value.get('Env'),'labels':value.get('Labels'),'HostConfig':value.get('HostConfig')}
                        with relay.lock:
                            relay.records.append(record)
                            with open(relay.log,'a') as f: f.write(json.dumps(record)+'\n')
                        body=json.dumps(value).encode()
                    upgrade=self.headers.get('Upgrade') is not None
                    if upgrade: conn.response_class=HijackResponse
                    headers={k:v for k,v in self.headers.items() if k.lower() not in ('host','content-length','connection')}
                    headers['Connection']='Upgrade' if upgrade else 'close'
                    conn.request(self.command,self.path,body=body,headers=headers)
                    resp=conn.getresponse()
                    with relay.lock:
                        with open(str(relay.log)+'.http','a') as f: f.write(json.dumps({'method':self.command,'path':self.path,'status':resp.status})+'\n')
                    self.send_response_only(resp.status,resp.reason)
                    for k,v in resp.getheaders():
                        if k.lower() not in ('connection','transfer-encoding','content-length'): self.send_header(k,v)
                    if resp.status==101:
                        self.send_header('Connection','Upgrade'); self.end_headers()
                        tunnel(self.connection,conn.sock)
                    else:
                        self.send_header('Connection','close'); self.end_headers()
                        while True:
                            chunk=resp.read1(65536)
                            if not chunk: break
                            self.wfile.write(chunk)
                except (BrokenPipeError,ConnectionResetError): pass
                except http.client.IncompleteRead:
                    if '/events' not in self.path: raise
                finally:
                    self.close_connection=True; conn.close()
        self.server=Server(self.path,Handler)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
    def start(self): self.thread.start()
    def close(self): self.server.shutdown(); self.server.server_close()
