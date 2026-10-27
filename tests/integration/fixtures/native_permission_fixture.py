"""Owned-file Linux fanotify permission fixture, not a Restic/provider substitute.

No mounts, policy changes, syscall/exit rewriting, wrappers or source agents.
CAP_SYS_ADMIN is needed on the EXCLUSIVE HOSTED fixture host, not in workers.
Kernel permissions apply even to a root/CAP_DAC_OVERRIDE reader. Unavailable
fanotify is a blocked gate, never permission to fall back to chmod or polling.
"""
import ctypes
import errno
import os
from pathlib import Path
import re
import select
import struct
import threading
import time

OPEN_PERM=0x10000
ACCESS_PERM=0x20000
EVENT_ON_CHILD=0x08000000
METADATA=struct.Struct('=IBBHQii')


class PermissionDecodeError(ValueError):
    def __init__(self,message,fds):
        super().__init__(message);self.fds=fds


def decode_events(data):
    # Pure decoder: transfer all received descriptor ownership on failure too.
    # This includes valid records preceding an overflow/unsupported record.
    rows=[];fds=set();error=None
    while data:
        if len(data)<METADATA.size:
            error='short permission metadata';break
        length,version,_,metadata_len,mask,fd,pid=METADATA.unpack_from(data)
        if fd>=0:fds.add(fd)
        if length!=24 or metadata_len!=24 or version!=3 or length>len(data) or fd<0 or pid<=0 or mask & 0x4000:
            error='unsupported/overflow permission metadata'
        if mask & ~0x40000000 not in (OPEN_PERM,ACCESS_PERM):error='unsupported permission mask'
        rows.append({'mask':mask,'fd':fd,'pid':pid})
        if length<METADATA.size or length>len(data):break
        data=data[length:]
    if error:raise PermissionDecodeError(error,fds)
    if len(fds)!=len(rows):raise PermissionDecodeError('duplicate permission descriptor',fds)
    return rows


def permission_response(fd,allow):
    if type(fd) is not int or fd<0 or type(allow) is not bool: raise ValueError('invalid permission response')
    return struct.pack('=iI',fd,1 if allow else 2)


def read_position(pid,path):
    """Actual native descriptor offset, not sampled bytes or a timed guess."""
    st=Path(path).stat(); positions=[]
    for fd in (Path('/proc')/str(pid)/'fd').iterdir():
        try:
            current=fd.stat()
            if (current.st_dev,current.st_ino)!=(st.st_dev,st.st_ino):continue
            fields=dict(line.split(':',1) for line in (fd.parent.parent/'fdinfo'/fd.name).read_text().splitlines())
            if int(fields['flags'].strip(),8)&os.O_ACCMODE != os.O_RDONLY:continue
            positions.append(int(fields['pos'].strip()))
        except FileNotFoundError:continue
    if len(positions)!=1: raise ValueError('unique native reader descriptor unavailable')
    return positions[0]


def process_identity(pid,cid,exe,command):
    """Bind permission event TGID to exact cgroup and native image executable."""
    if type(pid) is not int or pid<=0 or not re.fullmatch('[a-f0-9]{64}',cid): raise ValueError('invalid native PID binding')
    proc=Path('/proc')/str(pid)
    ticks=int(proc.joinpath('stat').read_text().rsplit(')',1)[1].split()[19])
    if cid not in proc.joinpath('cgroup').read_text():return None
    actual=proc.joinpath('exe').stat(); expected=proc.joinpath('root',exe.lstrip('/')).stat()
    if (actual.st_dev,actual.st_ino)!=(expected.st_dev,expected.st_ino):return None
    argv=proc.joinpath('cmdline').read_bytes().rstrip(b'\0').split(b'\0')
    # Literal complete argument only; no substring admission or raw argv export.
    if command.encode() not in argv[1:]:return None
    status=dict(line.split(':',1) for line in proc.joinpath('status').read_text().splitlines())
    uid=int(status['Uid'].split()[0]);cap=status['CapEff'].strip().lower()
    if not re.fullmatch('[a-f0-9]{16}',cap): raise ValueError('native capability observation unavailable')
    if ticks!=int(proc.joinpath('stat').read_text().rsplit(')',1)[1].split()[19]):raise ValueError('native PID incarnation changed')
    return {'pid':pid,'start_ticks':ticks,'worker_id':cid,'exe':Path(exe).name,'command':command,'uid':uid,'cap_eff':cap}


class PermissionGate:
    @classmethod
    def from_fd(cls,fd,classify,*,hold_seconds=10):
        if not 0<hold_seconds<=10:raise ValueError('permission hold exceeds fixture bound')
        self=cls.__new__(cls);self.fd=fd;self.classify=classify;self.hold_seconds=hold_seconds
        self.lock=threading.RLock();self.hit=threading.Event();self.held=None
        self.errors=[];self.closed=False;self.thread=None;self.count=0
        self.quiescent=threading.Condition(self.lock);self.active=0;self.retired=False
        self.pending={};self.watchdog=None;self.failure=None
        return self

    def __init__(self,classify,*,hold_seconds=10):
        libc=ctypes.CDLL(None,use_errno=True)
        libc.fanotify_init.argtypes=[ctypes.c_uint,ctypes.c_uint];libc.fanotify_init.restype=ctypes.c_int
        # FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK; no unlimited queue/marks.
        fd=libc.fanotify_init(0x4|0x1|0x2,os.O_RDONLY|os.O_CLOEXEC|os.O_LARGEFILE)
        if fd<0:raise PermissionError('native fanotify unavailable')
        state=self.from_fd(fd,classify,hold_seconds=hold_seconds)
        self.__dict__.update(state.__dict__);self.libc=libc
        libc.fanotify_mark.argtypes=[ctypes.c_int,ctypes.c_uint,ctypes.c_uint64,ctypes.c_int,ctypes.c_char_p]
        libc.fanotify_mark.restype=ctypes.c_int

    def mark(self,path,mask):
        if mask not in (ACCESS_PERM,OPEN_PERM|EVENT_ON_CHILD):raise ValueError('unsupported owned permission mark')
        if self.libc.fanotify_mark(self.fd,1,mask,-100,os.fsencode(path))<0:
            raise TimeoutError('native owned-file permission mark unavailable')

    def start(self):
        with self.lock:
            if self.closed or self.thread is not None:raise RuntimeError('permission gate already started/closed')
            self.thread=threading.Thread(target=self.loop,daemon=True);self.thread.start()

    def _watch(self):
        # Independent of classification: include its time AND batch admission
        # in the absolute bound, without recycling a classifier's event FD.
        with self.lock:
            while not self.closed:
                try:self.expire()
                except Exception as exc:self._fail('permission-transport-failed',exc)
                self.quiescent.wait(.005)

    def _cancel_pending(self):
        for event in list(self.pending.values()):
            try:self.answer(event,False)
            except Exception as exc:
                if self.failure is None:self.failure=exc

    def _fail(self,code,exc=None):
        self.errors.append(code);self.closed=True;self.hit.set()
        if self.failure is None:self.failure=exc
        self._cancel_pending();self.quiescent.notify_all()

    def answer(self,event,allow):
        with self.lock:
            state=self.pending.get(event['fd'])
            if state is None or (state is not event and event.get('deadline')!=state['deadline']):
                raise RuntimeError('permission event ownership expired')
            if state['answered']:return state['disposition']
            if self.retired:raise RuntimeError('permission authority already retired')
            disposition='allowed' if allow else 'denied'
            try:
                if os.write(self.fd,permission_response(event['fd'],allow))!=8:
                    raise OSError(errno.EIO,'short permission response')
            except OSError as exc:
                if exc.errno==errno.ENOENT:disposition='kernel-canceled'
                else:
                    self.errors.append('permission-response-failed')
                    raise
            finally:
                if state:
                    state['answered']=True;state['disposition']=disposition
                if not state or not state['classifying']:
                    self.pending.pop(event['fd'],None);os.close(event['fd'])
                if self.held and self.held['fd']==event['fd']:
                    self.held=None
                if self.errors or self.closed:self.hit.set()
                elif self.held is None:self.hit.clear()
            return disposition

    def dispatch(self,events,received_at=None):
        with self.lock:
            if self.retired:
                for event in events:os.close(event['fd'])
                raise RuntimeError('permission authority already retired')
            self.active+=1
            deadline=(time.monotonic() if received_at is None else received_at)+self.hold_seconds
            # Admit the WHOLE received batch before classification can block.
            for event in events:
                self.pending[event['fd']]={**event,'deadline':deadline,'answered':False,
                    'classifying':False,'disposition':None}
            if self.watchdog is None and not self.closed:
                self.watchdog=threading.Thread(target=self._watch,daemon=True);self.watchdog.start()
        try:
            for event in events:
                with self.lock:
                    state=self.pending.get(event['fd'])
                    if state is None:continue # Watchdog already denied/closed queued event.
                    state['classifying']=True;self.count+=1
                try:
                    if self.count>4096:raise ValueError('permission event bound')
                    action='deny' if self.closed else self.classify(event)
                    if action not in ('hold','allow','deny'):raise ValueError('unknown permission action')
                except Exception:
                    with self.lock:self.errors.append('permission-classification-failed');self.hit.set()
                    action='deny'
                with self.lock:
                    state['classifying']=False
                    if state['answered']:
                        self.pending.pop(event['fd'],None);os.close(event['fd']);continue
                    if self.closed or self.errors or time.monotonic()>=deadline:action='deny'
                    if action=='hold' and self.held is not None:
                        self.errors.append('permission-classification-failed');self.hit.set();action='deny'
                    if action=='hold':
                        self.held={**event,'deadline':deadline};self.hit.set()
                    else:self.answer(state,action=='allow')
        finally:
            with self.lock:
                self.active-=1;self.quiescent.notify_all()

    def current_hold(self):
        with self.lock:
            if self.closed or self.errors or self.held is None or time.monotonic()>=self.held['deadline']:
                raise TimeoutError('permission hold expired or unavailable')
            return dict(self.held)

    def await_hold(self,seconds=40):
        if not self.hit.wait(seconds):raise TimeoutError('native permission boundary not reached')
        return self.current_hold()

    def release(self,allow):
        with self.lock:return self.answer(self.current_hold(),allow)

    def release_after_kill(self):
        # Cancellation is NOT proof of a crash; terminal137 is still required.
        with self.lock:return self.answer(self.current_hold(),False)

    def expire(self,now=None):
        with self.lock:
            now=time.monotonic() if now is None else now
            for event in list(self.pending.values()):
                if not event['answered'] and now>=event['deadline']:
                    self.errors.append('permission-hold-expired');self.hit.set()
                    self.answer(event,False)

    def _retire(self):
        # Caller holds lock and has proven dispatchers quiescent. Only this
        # path releases group authority; response errors cannot skip it.
        if self.retired:return
        failure=None
        try:
            for event in list(self.pending.values()):
                try:self.answer(event,False)
                except Exception as exc:
                    if failure is None:failure=exc
        finally:
            self.held=None;self.hit.set();os.close(self.fd);self.retired=True
        if failure is not None:raise failure

    def loop(self):
        try:
            while not self.closed:
                try:
                    if select.select([self.fd],[],[],.02)[0]:
                        data=os.read(self.fd,65536);received_at=time.monotonic()
                        if not data:raise EOFError('permission transport closed')
                        try:events=decode_events(data)
                        except PermissionDecodeError as exc:
                            for fd in exc.fds:os.close(fd)
                            raise
                        self.dispatch(events,received_at)
                except BlockingIOError:continue
        except Exception as exc:
            with self.lock:self._fail('permission-transport-failed',exc)
        finally:
            # The dispatcher has returned before retiring the group, even on
            # transport failure. The watchdog uses the same lock/state checks.
            with self.lock:
                if self.closed and not self.active:
                    try:self._retire()
                    except Exception as exc:
                        if self.failure is None:self.failure=exc

    def close(self):
        end=time.monotonic()+1
        with self.lock:
            self.closed=True;self.hit.set();self._cancel_pending();self.quiescent.notify_all()
        for thread in (self.thread,self.watchdog):
            if thread and thread is not threading.current_thread():thread.join(max(0,end-time.monotonic()))
        with self.lock:
            while self.active:
                remaining=end-time.monotonic()
                if remaining<=0:raise TimeoutError('permission dispatcher did not quiesce; authority retained')
                self.quiescent.wait(remaining)
            if any(thread and thread.is_alive() for thread in (self.thread,self.watchdog)):
                raise TimeoutError('permission dispatcher did not quiesce; authority retained')
            self._retire()
            if self.failure is not None:raise self.failure
