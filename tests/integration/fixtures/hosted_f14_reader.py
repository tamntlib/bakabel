#!/usr/bin/env python3
"""Host-only Linux/x86-64 reader exit-boundary fault; no image/source hook.

Attach while the real Restic reader is backpressured behind restore-start.
Trace its threads, wait for actual exit_group(0) ENTRY (all user-space writes
already happened), then SIGKILL only that exact pidfd. Never change bytes,
registers, Engine responses, source processes, or the production executable.
"""
import ctypes
import errno
import os
from pathlib import Path
import platform
import signal
import time
import threading
import argparse
import hashlib
import json
import re
import sys


def read_process(pid):
    root = Path('/proc')/str(pid)
    raw = (root/'stat').read_text(); fields = raw[raw.rfind(')')+2:].split()
    cmd = (root/'cmdline').read_bytes()
    if len(cmd) > 4096 or not cmd.endswith(b'\0'): raise ValueError('reader argv bound')
    return {'pid':pid,'ppid':int(fields[1]),'start_ticks':int(fields[19]),
            'exe':os.readlink(root/'exe'),'argv':[x.decode() for x in cmd[:-1].split(b'\0')],
            'cgroup':(root/'cgroup').read_text().strip()}


def check_binding(binding, owner, process):
    expected = binding['owner']; cid = expected.get('workerContainerID','')
    if (owner != expected or owner.get('workerStartAuthorized') is not True or
            owner.get('phase') != 'exec_started' or owner.get('status') != 'active' or
            owner.get('execKind') != 'restore' or not re.fullmatch('[a-f0-9]{64}',cid) or
            not re.fullmatch('[a-f0-9]{32}',owner.get('runID','')) or
            not re.fullmatch('restore_[a-f0-9]{48}',owner.get('importRunID',''))):
        raise ValueError('reader fault lacks fresh strict durable authorization')
    if (process != binding['reader'] or process.get('ppid') != binding['worker_pid'] or
            process.get('exe') != '/usr/bin/restic' or cid not in process.get('cgroup','') or
            process.get('argv') != ['/usr/bin/restic','--no-cache','dump',binding['snapshot_id'],binding['dump_path']] or
            type(process.get('pid')) is not int or process['pid'] <= 1 or
            type(process.get('start_ticks')) is not int or process['start_ticks'] <= 0):
        raise ValueError('reader process identity/command/incarnation changed')


def find_reader(worker_pid, snapshot_id, dump_path):
    tasks = list((Path('/proc')/str(worker_pid)/'task').iterdir())
    if not 1 <= len(tasks) <= 128: raise ValueError('worker thread bound')
    children = set()
    for task in tasks:
        try: children.update(int(x) for x in (task/'children').read_text().split())
        except FileNotFoundError: continue
    if len(children) > 128: raise ValueError('worker child bound')
    found = []
    for pid in children:
        try: process = read_process(pid)
        except (FileNotFoundError,ProcessLookupError): continue
        if process['argv'] == ['/usr/bin/restic','--no-cache','dump',snapshot_id,dump_path]: found.append(process)
    if len(found) != 1: raise ValueError('unique live ordinary Restic dump reader unavailable')
    return found[0]


class SyscallInfo(ctypes.Structure):
    _fields_ = [('op',ctypes.c_ubyte),('pad',ctypes.c_ubyte*3),('arch',ctypes.c_uint),
               ('ip',ctypes.c_ulonglong),('sp',ctypes.c_ulonglong),('data',ctypes.c_ulonglong*8)]


FAILURE_TYPES={'OSError','ProcessLookupError','PermissionError','TimeoutError',
               'ChildProcessError','ValueError','RuntimeError','FileNotFoundError','OtherError'}
TRACE_PHASES={'attach','wait','clone','syscall_info','authorize','ready','resume','terminal','detach','unknown'}
FAILURE_ERRNOS={'ESRCH','EPERM','EACCES','EIO','EINVAL','ECHILD','EINTR','ENOENT','OTHER'}


def project_failure(row):
    """Fixed finite public projection; never retain arbitrary helper stdout."""
    def integer(key,maximum):
        value=row.get(key)
        return value if type(value) is int and 0<=value<=maximum else None
    def finite(key,allowed,fallback=None):
        value=row.get(key)
        return value if type(value) is str and value in allowed else fallback
    return {'state':'failed','type':finite('type',FAILURE_TYPES,'OtherError'),
            'errno':finite('errno',FAILURE_ERRNOS),
            'phase':finite('phase',TRACE_PHASES,'unknown'),
            'natural_exit_code':integer('natural_exit_code',255),
            'injected':row.get('injected') if type(row.get('injected')) is bool else None,
            'owned_tasks':integer('owned_tasks',128),'stopped_tasks':integer('stopped_tasks',128),
            'detach_verified':row.get('detach_verified') if type(row.get('detach_verified')) is bool else None,
            'cleanup_failed':row.get('cleanup_failed') is True}


def failure_record(exc,diagnostic=None):
    row=dict(diagnostic or {})
    row.update(type=type(exc).__name__,errno=errno.errorcode.get(getattr(exc,'errno',None),'OTHER')
               if isinstance(exc,OSError) else None,cleanup_failed=getattr(exc,'f14_cleanup_failed',False) is True)
    return project_failure(row)


def trace_exit(pid, validate, ready, *, inject, seconds=20, diagnostic=None):
    """Trace an authorized process; callbacks must fail closed. No PID guessing.

    ready runs only after every observed thread is stopped and attached. The
    parent may then forward its UNCHANGED Docker restore-start request. On
    failure detach/resume all owned threads rather than leave a trace-stop.
    """
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise RuntimeError('F14 requires Linux x86-64 syscall ABI')
    if type(pid) is not int or pid <= 1 or type(inject) is not bool:
        raise ValueError('invalid exact reader selector')
    diagnostic={} if diagnostic is None else diagnostic
    diagnostic['phase']='attach'
    libc = ctypes.CDLL(None,use_errno=True)
    libc.ptrace.restype = ctypes.c_long
    libc.ptrace.argtypes = [ctypes.c_uint,ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p]
    def ptrace(request,tid,addr=0,data=0):
        diagnostic['phase']={0x4206:'attach',0x4207:'attach',0x4201:'clone',
                             0x420e:'syscall_info',24:'resume',17:'detach'}.get(request,'unknown')
        result = libc.ptrace(request,tid,ctypes.c_void_p(addr),ctypes.c_void_p(data))
        if result == -1:
            code = ctypes.get_errno(); raise OSError(code,os.strerror(code))
        return result
    end = time.monotonic()+seconds
    tids = set(); stopped = set(); natural = None; injected = False
    fd = os.pidfd_open(pid)
    def wait(tid=-1,deadline=None):
        diagnostic['phase']='wait'
        deadline=end if deadline is None else deadline
        while time.monotonic() < deadline:
            # A clone's initial stop can be waitable BEFORE its parent's clone
            # event. Wait only already-authorized tids; the parent event admits
            # the new tid before we consume its stop. Never reap unrelated work.
            for target in ([tid] if tid != -1 else sorted(tids)):
                found,status = os.waitpid(target,os.WNOHANG|0x40000000) # __WALL
                if found: return found,status
            time.sleep(.001)
        raise TimeoutError('bounded F14 reader tracing')
    try:
        diagnostic['phase']='authorize';validate()
        # Stop each thread immediately. Re-scan until no untraced thread can
        # clone; TRACECLONE covers subsequent births once tracing resumes.
        while True:
            discovered = {int(p.name) for p in (Path('/proc')/str(pid)/'task').iterdir()}
            if not discovered or len(discovered) > 128: raise ValueError('reader thread bound')
            pending = discovered-tids
            if not pending: break
            for tid in sorted(pending):
                try:
                    ptrace(0x4206,tid,0,1|8) # SEIZE, TRACESYSGOOD|TRACECLONE
                    tids.add(tid); ptrace(0x4207,tid) # INTERRUPT
                    found,status = wait(tid)
                    if found != tid or not os.WIFSTOPPED(status): raise ValueError('reader exited before attachment')
                    stopped.add(tid)
                except OSError as exc:
                    if exc.errno != errno.ESRCH: raise
                    tids.discard(tid)
            if time.monotonic() >= end: raise TimeoutError('bounded reader attachment')
        diagnostic['phase']='authorize';validate()
        diagnostic['phase']='ready';ready()
        for tid in list(stopped): ptrace(24,tid); stopped.discard(tid) # SYSCALL
        while tids:
            tid,status = wait()
            if tid not in tids:
                # Only auto-attached children reported by our own clone events
                # are admitted below; no unrelated wait status grants authority.
                raise ValueError('unexpected traced task')
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                tids.remove(tid); stopped.discard(tid)
                if tid == pid:
                    result = {'natural_exit_code':natural,'injected':injected,
                              'terminal_exit_code':os.WEXITSTATUS(status) if os.WIFEXITED(status) else None,
                              'terminal_signal':os.WTERMSIG(status) if os.WIFSIGNALED(status) else None}
                continue
            if not os.WIFSTOPPED(status): raise ValueError('unknown reader wait state')
            stopped.add(tid)
            sig = os.WSTOPSIG(status); event = status >> 16
            deliver = 0
            if event == 3: # PTRACE_EVENT_CLONE
                child = ctypes.c_ulonglong()
                ptrace(0x4201,tid,0,ctypes.addressof(child)) # GETEVENTMSG
                if child.value <= 1 or len(tids) >= 128: raise ValueError('reader clone bound')
                tids.add(child.value)
            elif sig == signal.SIGTRAP|0x80:
                info = SyscallInfo()
                try:
                    size = ptrace(0x420e,tid,ctypes.sizeof(info),ctypes.addressof(info))
                except OSError as exc:
                    if exc.errno != errno.ESRCH: raise
                    # A sibling exit_group can invalidate a queued syscall
                    # stop. ESRCH is NOT terminal proof: retain this admitted
                    # task and require its actual wait status below. Do not
                    # keep a stale stopped flag that could deadlock cleanup.
                    stopped.discard(tid)
                    continue
                if size < 24 or info.arch != 0xc000003e: raise ValueError('unknown syscall ABI')
                if info.op == 1 and info.data[0] == 231: # x86-64 exit_group entry
                    natural = info.data[1]
                    if natural != 0: raise ValueError('reader already failing naturally')
                    diagnostic['phase']='authorize'
                    validate() # fresh owner + exact executable/argv/incarnation
                    if inject:
                        signal.pidfd_send_signal(fd,signal.SIGKILL)
                        injected = True
            elif event == 128 and sig == signal.SIGTRAP:
                pass # auto-attached clone interrupt
            elif sig in (signal.SIGTRAP,signal.SIGSTOP):
                raise ValueError('unexpected reader trace stop')
            else:
                deliver = sig # Preserve ordinary signal semantics.
            try: ptrace(24,tid,0,deliver); stopped.discard(tid)
            except OSError as exc:
                if exc.errno != errno.ESRCH: raise
                stopped.discard(tid) # Retain ownership until actual terminal wait.
        diagnostic['phase']='terminal'
        if natural != 0 or result['injected'] != inject: raise ValueError('reader exit boundary not observed')
        return result
    finally:
        # Cleanup drains the entire admitted group: a leader terminal wait can
        # depend on first consuming its siblings' ptrace exit notifications.
        # Keep the original operation exception even if cleanup also fails.
        primary=sys.exc_info()[1]
        failed_phase=diagnostic['phase']
        diagnostic.update(natural_exit_code=natural,injected=injected,owned_tasks=len(tids),stopped_tasks=len(stopped),detach_verified=False)
        cleanup_end=time.monotonic()+1
        tracer_tid=threading.get_native_id()
        failures=[];interrupted=set();detach_attempted=set()
        def attached(tid):
            try:status=(Path('/proc')/str(tid)/'status').read_text()
            except (FileNotFoundError,ProcessLookupError):
                # procfs may open status while a detached task still exists,
                # then return ESRCH from read after it exits. That task cannot
                # retain our tracer; unlike ptrace ESRCH, this is procfs absence.
                return False
            tracer=next(line.split(':',1)[1].strip() for line in status.splitlines() if line.startswith('TracerPid:'))
            return tracer==str(tracer_tid)
        try:
            while tids and time.monotonic()<cleanup_end:
                for tid in sorted(tids.copy()):
                    if tid in stopped and tid not in detach_attempted:
                        detach_attempted.add(tid)
                        try:ptrace(17,tid) # DETACH resumes only this admitted task.
                        except OSError as exc:
                            if exc.errno!=errno.ESRCH:failures.append(exc)
                        if not attached(tid):
                            tids.discard(tid);stopped.discard(tid)
                    elif tid not in stopped and tid not in interrupted:
                        interrupted.add(tid)
                        try:ptrace(0x4207,tid)
                        except OSError as exc:
                            if exc.errno!=errno.ESRCH:failures.append(exc)
                if not tids:break
                try:tid,status=wait(deadline=cleanup_end)
                except (OSError,TimeoutError,ChildProcessError) as exc:
                    failures.append(exc);break
                if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                    tids.discard(tid);stopped.discard(tid)
                elif os.WIFSTOPPED(status):
                    stopped.add(tid);detach_attempted.discard(tid)
                    if status >> 16 == 3:
                        child=ctypes.c_ulonglong()
                        try:
                            ptrace(0x4201,tid,0,ctypes.addressof(child))
                            if child.value<=1 or len(tids)>=128:raise RuntimeError('reader cleanup clone bound')
                            tids.add(child.value)
                        except (OSError,RuntimeError) as exc:
                            failures.append(exc)
                else:failures.append(RuntimeError('unknown reader cleanup wait state'));break
            # ESRCH alone never removes authority. Check actual native tracer
            # ownership, even for failed DETACH or a task whose wait vanished.
            remaining=[tid for tid in tids if attached(tid)]
            diagnostic['detach_verified']=not remaining
            if remaining or failures:
                cleanup_error=RuntimeError('F14 owned reader cleanup could not detach/resume')
                if primary is not None:
                    primary.f14_cleanup_failed=True
                    primary.add_note('F14 owned reader cleanup could not detach/resume')
                else:raise cleanup_error from (failures[0] if failures else None)
        except Exception:
            if primary is None:raise
            primary.f14_cleanup_failed=True
            primary.add_note('F14 owned reader cleanup could not detach/resume')
        finally:
            diagnostic['phase']=failed_phase
            os.close(fd)


def authorize(binding, owner_path, engine):
    from run_resource_probe import worker_owned
    def current_owner():
        if owner_path.stat().st_size > 65536: raise ValueError('owner size bound')
        return json.loads(owner_path.read_text())
    process=binding['reader']; owner=current_owner()
    check_binding(binding,owner,read_process(process['pid']))
    obj=engine.inspect(owner['workerContainerID']); dest=engine.inspect(owner['sourceContainerID'])
    if (engine.call('GET','/info')['ID'] != owner['daemonID'] or
            not worker_owned(obj,owner,binding['image_id'],owner['daemonID']) or
            obj['State'].get('Running') is not True or obj['State'].get('Pid') != binding['worker_pid'] or
            dest.get('Id') != owner['sourceContainerID'] or dest['State'].get('Running') is not True or
            dest['State'].get('StartedAt') != owner['sourceStartedAt']):
        raise ValueError('fresh exact worker/target identity changed')
    # Engine observations do not grant stale authority. Last read before the
    # only signal is the strict durable owner AND the same reader incarnation.
    check_binding(binding,current_owner(),read_process(process['pid']))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binding',type=Path,required=True)
    parser.add_argument('--owner',type=Path,required=True)
    parser.add_argument('--socket',type=Path,required=True)
    args = parser.parse_args(argv)
    if (os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true' or
            os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'):
        parser.error('host-only helper requires exclusive hosted root fixture')
    if args.binding.stat().st_size > 65536: raise ValueError('binding size bound')
    binding = json.loads(args.binding.read_text()); process = binding['reader']; checks = 0
    from run_resource_probe import Engine
    engine = Engine(args.socket)
    def validate():
        nonlocal checks
        authorize(binding,args.owner,engine)
        checks += 1
    def ready(): print(json.dumps({'state':'armed'}),flush=True)
    diagnostic={}
    try:result = trace_exit(process['pid'],validate,ready,inject=binding['mode'] == 'fault',diagnostic=diagnostic)
    except Exception as exc:
        print(json.dumps(failure_record(exc,diagnostic)),flush=True)
        return 1
    result.update(pid=process['pid'],ppid=process['ppid'],start_ticks=process['start_ticks'],
                  argv_sha256=hashlib.sha256(json.dumps(process['argv'],separators=(',',':')).encode()).hexdigest(),
                  fresh_authorization_checks=checks)
    print(json.dumps({'state':'terminal','reader':result}),flush=True)
    return 0


if __name__ == '__main__':
    try: raise SystemExit(main())
    except Exception as exc:
        # Finite codes only; no raw exceptions, argv, paths, env or process data.
        print(json.dumps(failure_record(exc)),flush=True)
        raise SystemExit(1)
