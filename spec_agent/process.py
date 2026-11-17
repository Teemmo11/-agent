"""POSIX process groups, bounded logs, sanitized environment, no shell."""
import os
import selectors
import shutil
import signal
import subprocess
import time
from pathlib import Path
from .artifacts import sha256_file, utc_now, write_json_atomic
from .models import CommandResult


def _invoke(argv, *, cwd, timeout=60, prefix='tool', max_log_bytes=8*1024*1024):
    cwd = Path(cwd).resolve()
    cwd.mkdir(parents=True, exist_ok=True)
    out, err = cwd / f'{prefix}.stdout.log', cwd / f'{prefix}.stderr.log'
    started, tick = utc_now(), time.monotonic()
    proc, rc, failure, limit, expired = None, None, None, None, False
    def kill():
        if proc:
            try: os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError: pass
    with out.open('xb') as so, err.open('xb') as se:
        try:
            if os.name != 'posix': raise OSError('Requires POSIX/WSL process groups')
            env = {k:v for k,v in os.environ.items() if k in ('PATH','HOME','LANG','LC_ALL','TMPDIR')}
            proc = subprocess.Popen(list(argv), cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, shell=False)
            size = 0
            with selectors.DefaultSelector() as selector:
                for pipe, sink in ((proc.stdout,so),(proc.stderr,se)):
                    os.set_blocking(pipe.fileno(), False)
                    selector.register(pipe, selectors.EVENT_READ, sink)
                while selector.get_map():
                    if time.monotonic()-tick >= timeout:
                        expired = True
                        break
                    if proc.poll() is not None: kill()
                    for key,_ in selector.select(.03):
                        chunk = os.read(key.fileobj.fileno(),65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        remaining = max_log_bytes-size
                        key.data.write(chunk[:remaining])
                        size += min(len(chunk),remaining)
                        if len(chunk)>remaining: limit='LOG_LIMIT_EXCEEDED'; break
                    if limit: break
            if expired or limit: kill()
            try: rc = proc.wait(timeout=max(.01, timeout-(time.monotonic()-tick)))
            except subprocess.TimeoutExpired:
                expired=True; kill(); rc=proc.wait(timeout=5)
        except (OSError, subprocess.SubprocessError) as exc:
            failure=type(exc).__name__
        finally:
            if proc:
                kill(); proc.wait(timeout=5)
                proc.stdout.close(); proc.stderr.close()
    result=CommandResult(list(argv),shutil.which(argv[0]),str(cwd),started,utc_now(),
        round(time.monotonic()-tick,4),rc,expired,str(out),str(err),sha256_file(out),sha256_file(err),failure,limit)
    write_json_atomic(cwd/f'{prefix}.execution.json',result)
    return result


def invoke(argv, *, cwd, timeout=60, prefix='tool', max_log_bytes=8*1024*1024, trace=None):
    """Observe execution without copying potentially large stdout/stderr into logs."""
    command_id = str(Path(cwd).resolve()/prefix)
    if trace:
        trace.emit('tool.started',command_id=command_id,argv=list(argv),cwd=str(cwd),timeout_seconds=timeout)
    try:
        result = _invoke(argv,cwd=cwd,timeout=timeout,prefix=prefix,max_log_bytes=max_log_bytes)
    except Exception as exc:
        if trace: trace.emit('tool.failed',level='ERROR',command_id=command_id,error_type=type(exc).__name__)
        raise
    if trace:
        trace.emit('tool.finished',level='INFO' if result.ok else 'WARNING',command_id=command_id,
                   duration_seconds=result.duration_seconds,returncode=result.returncode,
                   timed_out=result.timed_out,spawn_error=result.spawn_error,resource_limit=result.resource_limit,
                   stdout=result.stdout_path,stderr=result.stderr_path,
                   stdout_sha256=result.stdout_sha256,stderr_sha256=result.stderr_sha256,
                   execution_file=str(Path(cwd)/f'{prefix}.execution.json'))
    return result
