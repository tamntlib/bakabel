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


def trace_exit(pid, validate, ready, *, inject, seconds=20):
    """Trace an authorized process; callbacks must fail closed. No PID guessing.

    ready runs only after every observed thread is stopped and attached. The
    parent may then forward its UNCHANGED Docker restore-start request. On
    failure detach/resume all owned threads rather than leave a trace-stop.
    """
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise RuntimeError('F14 requires Linux x86-64 syscall ABI')
    if type(pid) is not int or pid <= 1 or type(inject) is not bool:
        raise ValueError('invalid exact reader selector')
    libc = ctypes.CDLL(None,use_errno=True)
    libc.ptrace.restype = ctypes.c_long
    libc.ptrace.argtypes = [ctypes.c_uint,ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p]
    def ptrace(request,tid,addr=0,data=0):
        result = libc.ptrace(request,tid,ctypes.c_void_p(addr),ctypes.c_void_p(data))
        if result == -1:
            code = ctypes.get_errno(); raise OSError(code,os.strerror(code))
        return result
    end = time.monotonic()+seconds
    tids = set(); stopped = set(); natural = None; injected = False
    fd = os.pidfd_open(pid)
    def wait(tid=-1,deadline=None):
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
        validate()
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
        validate(); ready()
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
                size = ptrace(0x420e,tid,ctypes.sizeof(info),ctypes.addressof(info))
                if size < 24 or info.arch != 0xc000003e: raise ValueError('unknown syscall ABI')
                if info.op == 1 and info.data[0] == 231: # x86-64 exit_group entry
                    natural = info.data[1]
                    if natural != 0: raise ValueError('reader already failing naturally')
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
        if natural != 0 or result['injected'] != inject: raise ValueError('reader exit boundary not observed')
        return result
    finally:
        # The operation budget may already be exhausted. Cleanup gets its own
        # fixed short budget and never waits for/reaps an unrelated child.
        cleanup_end=time.monotonic()+1
        tracer_tid=threading.get_native_id()
        failures=[]
        try:
            while tids:
                tid=min(tids)
                try:
                    if tid not in stopped:
                        ptrace(0x4207,tid)
                        _,status=wait(tid,deadline=cleanup_end)
                        if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                            tids.discard(tid);continue
                        if not os.WIFSTOPPED(status):raise RuntimeError('unknown reader cleanup wait state')
                        stopped.add(tid)
                        if status >> 16 == 3:
                            # A clone event can race the operation timeout.
                            child=ctypes.c_ulonglong()
                            ptrace(0x4201,tid,0,ctypes.addressof(child))
                            if child.value<=1 or len(tids)>=128:raise RuntimeError('reader cleanup clone bound')
                            tids.add(child.value)
                    ptrace(17,tid) # DETACH resumes the owned task.
                except (OSError,TimeoutError,ChildProcessError) as exc:
                    # ESRCH alone is not proof: a live running tracee can also
                    # reject DETACH. Verify proc attachment before accepting it.
                    try:
                        status=(Path('/proc')/str(tid)/'status').read_text()
                        tracer=next(line.split(':',1)[1].strip() for line in status.splitlines() if line.startswith('TracerPid:'))
                        if tracer==str(tracer_tid):failures.append(exc)
                    except FileNotFoundError:pass
                else:
                    try:
                        status=(Path('/proc')/str(tid)/'status').read_text()
                        if any(line=='TracerPid:\t'+str(tracer_tid) for line in status.splitlines()):
                            failures.append(RuntimeError('reader still attached after detach'))
                    except FileNotFoundError:pass
                finally:
                    tids.discard(tid);stopped.discard(tid)
            if failures:raise RuntimeError('F14 owned reader cleanup could not detach/resume') from failures[0]
        finally:os.close(fd)


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
    result = trace_exit(process['pid'],validate,ready,inject=binding['mode'] == 'fault')
    result.update(pid=process['pid'],ppid=process['ppid'],start_ticks=process['start_ticks'],
                  argv_sha256=hashlib.sha256(json.dumps(process['argv'],separators=(',',':')).encode()).hexdigest(),
                  fresh_authorization_checks=checks)
    print(json.dumps({'state':'terminal','reader':result}),flush=True)
    return 0


if __name__ == '__main__':
    try: raise SystemExit(main())
    except Exception as exc:
        # Finite codes only; no raw exceptions, argv, paths, env or process data.
        print(json.dumps({'state':'failed','type':type(exc).__name__}),flush=True)
        raise SystemExit(1)
