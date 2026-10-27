"""Host-only numeric syscall receipts. Never persist strace output or payloads."""
import re
import os
from pathlib import Path
import signal
import subprocess
import threading
import time


class WriteStream:
    """Bounded per-TID pairing of strace's interleaved unfinished writes."""
    def __init__(self,root_pid,path_kind):
        self.root_pid=root_pid; self.path_kind=path_kind; self.pending={}
        self.failure=None
        self.diagnostics={key:0 for key in ('lines','paired','parsed_failures','parse_rejected',
            'path_unmatched','setup_failures','write_other_errno')}

    def feed(self,line):
        self.failure=None
        if self.diagnostics['lines']>=10000: raise ValueError('trace count bound')
        self.diagnostics['lines']+=1
        if len(line)>4096: raise ValueError('trace line bound')
        match=re.match(r'(?:\[pid\s+(\d+)\]\s+|(\d+)\s+)?(.*)',line.strip())
        pid=int(match[1] or match[2] or self.root_pid); text=match[3]
        if text.endswith('<unfinished ...>'):
            if pid in self.pending or len(self.pending)>=128: raise ValueError('trace pairing bound')
            self.pending[pid]=line.strip().removesuffix('<unfinished ...>')
            return None
        resumed=re.match(r'<\.\.\. (write|pwrite64|writev|open|openat|openat2|creat|fallocate|ftruncate) resumed>(.*)',text)
        if resumed:
            prefix=self.pending.pop(pid,None)
            if prefix is None: raise ValueError('unpaired trace resume')
            if not re.search(r'\b'+resumed[1]+r'\(',prefix): raise ValueError('trace syscall pairing drift')
            line=prefix+resumed[2]
            self.diagnostics['paired']+=1
        self.failure=project_failure(line,root_pid=self.root_pid,path_kind=self.path_kind)
        if self.failure is None:
            self.diagnostics['parse_rejected']+=1
        else:
            self.diagnostics['parsed_failures']+=1
            if self.failure['path_kind'] is None: self.diagnostics['path_unmatched']+=1
            if self.failure['stage'] != 'write': self.diagnostics['setup_failures']+=1
            elif self.failure['errno'] != 28: self.diagnostics['write_other_errno']+=1
        return project_write(line,root_pid=self.root_pid,path_kind=self.path_kind)


    def finish(self):
        if self.pending: raise ValueError('trace_incomplete')


class WriteTrace:
    """Attach only to caller-verified owned PIDs; never signal the tracee.

    -s0 prevents write-buffer disclosure even to the pipe. Decoded FD paths are
    transient classification input, NEVER exported. Missing tracing is a gate
    failure, not a reason to fall back to a stderr phrase or statvfs alone.
    """
    def __init__(self, pids, path_kind, *, authority=None, diagnose_setup=False):
        if not pids or any(type(p) is not int or p <= 0 for p in pids):
            raise ValueError('invalid trace identity')
        self.pids=list(dict.fromkeys(pids)); self.path_kind=path_kind
        self.writes=[]; self.errors=[]; self.attached=False; self.proc=None
        self.authority=authority
        self.diagnose_setup=diagnose_setup; self.failures=[]; self.diagnostics={}
        self.identities={p:Path(f'/proc/{p}/stat').read_text().rsplit(')',1)[1].split()[19] for p in self.pids}
        self.bindings={p:self.process_binding(p) for p in self.pids}

    @staticmethod
    def process_binding(pid):
        return (Path(f'/proc/{pid}/cgroup').read_text(),os.readlink(f'/proc/{pid}/exe'))

    def validate(self):
        if self.authority is not None: self.authority()
        for pid in self.pids:
            if (self.process_binding(pid) != self.bindings[pid] or
                    Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()[19] != self.identities[pid]):
                raise ValueError('trace incarnation changed')

    def writer_binding(self,tid):
        # Read while the observed writer still exists; disappeared/ambiguous
        # provenance is an observer failure, never a made-up ancestry binding.
        chain=[]; current=tid; seen=set()
        while current not in seen and len(chain)<32:
            seen.add(current)
            fields=Path(f'/proc/{current}/stat').read_text().rsplit(')',1)[1].split()
            status=Path(f'/proc/{current}/status').read_text().splitlines()
            tgid=int(next(s.split()[1] for s in status if s.startswith('Tgid:')))
            tracer=int(next(s.split()[1] for s in status if s.startswith('TracerPid:')))
            if tracer != self.proc.pid: raise ValueError('writer tracer drift')
            ticks=fields[19]; parent=int(fields[1])
            chain.append({'pid':current,'tgid':tgid,'ppid':parent,'start_ticks':ticks})
            if current in self.identities:
                if ticks != self.identities[current]: raise ValueError('writer root incarnation drift')
                if Path(f'/proc/{tid}/cgroup').read_text() != self.bindings[current][0]:
                    raise ValueError('writer cgroup drift')
                return {'chain':chain,'root_pid':current}
            current=tgid if tgid != current else parent
        raise ValueError('writer root ancestry unavailable')

    def start(self):
        if self.proc is not None: raise ValueError('trace already started')
        # strace -p accepts numeric PIDs, not pidfds. This precheck refuses
        # preexisting drift; it cannot atomically close the kernel attach race.
        # Retain the postcheck and fail/detach on any observed drift. Do not
        # claim pidfd authority or successful acceptance from a late rejection.
        self.validate()
        calls='trace=write,pwrite64,writev'
        if self.diagnose_setup: calls+=',open,openat,openat2,creat,fallocate,ftruncate'
        self.proc=subprocess.Popen(['strace','-f','-qq','-yy','-s','0','-e',
            calls,'-e','status=failed','-e','signal=none',
            *[arg for pid in self.pids for arg in ('-p',str(pid))]],
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        def consume():
            count=0; projector=WriteStream(self.pids[0],self.path_kind)
            self.diagnostics=projector.diagnostics
            try:
                while True:
                    raw=self.proc.stderr.readline(4097)
                    if not raw:
                        try: projector.finish()
                        except ValueError: self.errors.append('trace_incomplete')
                        break
                    count+=1
                    if len(raw)>4096 or count>10000:
                        if not self.errors: self.errors.append('trace_bound')
                        continue
                    line=raw.decode('utf-8',errors='replace').strip()
                    row=projector.feed(line)
                    if row is not None:
                        row['writer']=self.writer_binding(row['pid'])
                        if len(self.writes)<128: self.writes.append(row)
                        elif not self.errors: self.errors.append('trace_bound')
                    if self.diagnose_setup and projector.failure is not None and row is None:
                        failure=projector.failure
                        if failure['path_kind'] is not None:
                            failure['writer']=self.writer_binding(failure['pid'])
                            if len(self.failures)<128: self.failures.append(failure)
                            elif not self.errors: self.errors.append('trace_bound')
                    if line.startswith('strace:') and not self.errors:
                        self.errors.append('trace_protocol')
            except Exception:
                self.errors.append('trace_reader')
        self.thread=threading.Thread(target=consume,name='owned-write-trace',daemon=True); self.thread.start()
        end=time.monotonic()+3
        try:
            while time.monotonic()<end and self.proc.poll() is None:
                attached=True
                for pid in self.pids:
                    if Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()[19] != self.identities[pid]:
                        raise ValueError('trace incarnation changed')
                    for task in Path(f'/proc/{pid}/task').iterdir():
                        status=(task/'status').read_text()
                        tracer=int(next(line.split()[1] for line in status.splitlines() if line.startswith('TracerPid:')))
                        attached &= tracer == self.proc.pid
                if attached:
                    self.validate()
                    self.attached=True; return
                time.sleep(.01)
            raise ValueError('trace attachment unavailable')
        except BaseException:
            self.finish(); raise

    def finish(self):
        if self.proc is None: return
        if self.proc.poll() is None: self.proc.send_signal(signal.SIGINT)
        try: self.proc.wait(3)
        except subprocess.TimeoutExpired:
            self.errors.append('trace_shutdown'); self.proc.kill(); self.proc.wait(3)
        self.thread.join(3)
        if self.thread.is_alive(): raise ValueError('trace reader not quiescent')
        self.proc.stderr.close()
        if self.proc.returncode not in (0,-signal.SIGINT): self.errors.append('trace_exit')

    def receipt(self):
        if self.proc is None or self.proc.poll() is None or self.thread.is_alive():
            raise ValueError('trace not quiescent')
        result={'root_pids':self.pids,'start_ticks':self.identities,'attached':self.attached,
                'errors':self.errors,'writes':self.writes,'quiescent':True}
        if self.diagnose_setup: result.update(diagnostics=self.diagnostics,failures=self.failures)
        return result



def project_failure(line, *, root_pid, path_kind):
    """Finite diagnostic only: never substitutes for project_write proof."""
    match=re.fullmatch(r'(?:\[pid\s+(\d+)\]\s+|(\d+)\s+)?(write|pwrite64|writev|open|openat|openat2|creat|fallocate|ftruncate)\((.*)\)\s+= -1 ([A-Z0-9]+) \([^\n]*\)',line.strip())
    if match is None: return None
    first,second,syscall,args,code=match.groups()
    stage='write' if syscall in ('write','pwrite64','writev') else (
        'allocate' if syscall in ('fallocate','ftruncate') else 'create_open')
    fd=None; path=None
    if stage in ('write','allocate'):
        target=re.match(r'(\d+)<([^\n<>]+)>',args)
        if target: fd=int(target[1]); path=target[2]
    else:
        target=re.match(r'(?:[^,]+, )?"([^"\\]*)",',args)
        if target: path=target[1]
    kind=path_kind(path.removesuffix(' (deleted)')) if path is not None else None
    # Do not export arbitrary callback results, errno tokens, paths or messages.
    if kind not in ('temp_pack','restore_output'): kind=None
    codes={'ENOSPC':28,'EIO':5,'EACCES':13,'EPERM':1,'ENOENT':2,'ENOMEM':12,
           'EMFILE':24,'ENFILE':23,'EROFS':30,'EBADF':9,'EPIPE':32,'EINVAL':22}
    return {'pid':int(first or second or root_pid),'syscall':syscall,'fd':fd,
            'errno':codes.get(code),'path_kind':kind,'stage':stage}


def project_write(line, *, root_pid, path_kind):
    match = re.fullmatch(r'(?:\[pid\s+(\d+)\]\s+|(\d+)\s+)?(write|pwrite64|writev)\((\d+)<([^\n]+)>,.*\)\s+= -1 ENOSPC \(No space left on device\)',line.strip())
    if not match: return None
    first, second, syscall, fd, path = match.groups()
    kind = path_kind(path.removesuffix(' (deleted)'))
    if kind is None: return None
    return {'pid':int(first or second or root_pid),'syscall':syscall,'fd':int(fd),'errno':28,'path_kind':kind}
