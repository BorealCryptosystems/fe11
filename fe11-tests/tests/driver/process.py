# SPDX-License-Identifier: Apache-2.0
"""Bounded Linux subprocess I/O; credentials are written only to stdin."""
import os
import math
from pathlib import Path
import selectors
import resource
import signal
import subprocess
import time


def stop(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def execute(command, environment, directory, frames, maximum_output=16 * 1024 * 1024,
            *, deadline_seconds=3600, child_umask=-1):
    """Drain both streams while feeding stdin; kill/reap the whole group on failure.

    Returned files are private diagnostics. The supervisor publishes only parsed
    records from the worker's closed schema, never these raw streams or frames.
    The deadline is a safety timeout, not a required execution duration. Normal
    campaigns use 3600 seconds. A zero deadline deliberately tests expiration
    without imposing a speed requirement on the child or waiting an hour.
    """
    if (type(deadline_seconds) not in (int, float) or not math.isfinite(deadline_seconds)
            or not 0 <= deadline_seconds <= 3600):
        raise ValueError("invalid process deadline")
    if type(child_umask) is not int or not -1 <= child_umask <= 0o777:
        raise ValueError("invalid child-only permission mask")
    directory = Path(directory).resolve()
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    if os.name != "posix" or maximum_output <= 0:
        raise ValueError("invalid native process environment")
    # This dedicated supervisor owns its process limits; children inherit zero
    # core size, including GDB's inferior. No host-wide setting is changed.
    _soft, hard = resource.getrlimit(resource.RLIMIT_CORE)
    resource.setrlimit(resource.RLIMIT_CORE, (0, hard))
    started = time.monotonic()
    deadline = started + deadline_seconds
    process = subprocess.Popen(command, cwd=directory, env=environment, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
                               umask=child_umask)
    selector = selectors.DefaultSelector()
    state = "EXITED"
    sent = 0
    count = {"stdout": 0, "stderr": 0}
    handles = {}
    try:
        for name in ("stdout", "stderr"):
            stream = getattr(process, name)
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
            descriptor = os.open(directory / (name + ".raw"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            handles[name] = os.fdopen(descriptor, "wb")
        os.set_blocking(process.stdin.fileno(), False)
        selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                state = "TIMEOUT"
                stop(process)
                break
            events = selector.select(min(remaining, 1))
            for key, _mask in events:
                stream, name = key.fileobj, key.data
                if name == "stdin":
                    try:
                        if sent < len(frames):
                            sent += os.write(stream.fileno(), memoryview(frames)[sent:])
                        if sent == len(frames):
                            selector.unregister(stream)
                            stream.close()
                    except BrokenPipeError:
                        selector.unregister(stream)
                        stream.close()
                    except BlockingIOError:
                        pass
                    continue
                try:
                    block = os.read(stream.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not block:
                    selector.unregister(stream)
                    stream.close()
                    continue
                count[name] += len(block)
                if count[name] > maximum_output:
                    state = "OUTPUT_LIMIT"
                    stop(process)
                    break
                handles[name].write(block)
            if state != "EXITED":
                break
        if process.poll() is None:
            try:
                process.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                state = "TIMEOUT"
                stop(process)
    except BaseException:
        stop(process)
        raise
    finally:
        selector.close()
        for stream in (process.stdin, process.stdout, process.stderr):
            if not stream.closed:
                stream.close()
        for stream in handles.values():
            stream.close()
    signal_number = -process.returncode if process.returncode < 0 else None
    if state == "EXITED" and signal_number is not None:
        state = "CRASH" if signal_number in (signal.SIGABRT, signal.SIGSEGV,
                signal.SIGBUS, signal.SIGILL, signal.SIGFPE) else "SIGNALED"
    return dict(state=state, exit_code=process.returncode, signal=signal_number,
                bytes=count, input_bytes_sent=sent,
                elapsed_seconds=time.monotonic() - started)


def frames(officer, user):
    """Encode two binary PINs without text conversion, environment or argv fields."""
    if len(officer) > 4096 or len(user) > 4096:
        raise ValueError("credential frame exceeds bound")
    result = bytearray()
    for pin in (officer, user):
        result.extend(len(pin).to_bytes(4, "big"))
        result.extend(pin)
    return result


def erase(value):
    """Clear the mutable buffer; Python/runtime copies are not covered by this claim."""
    value[:] = b"\0" * len(value)
