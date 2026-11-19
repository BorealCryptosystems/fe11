# SPDX-License-Identifier: Apache-2.0
"""GDB function-entry observer; no inferior calls or credential-buffer access.

Only explicit initialization-metadata cases inspect the public flags and NULL
presence bits of CK_C_INITIALIZE_ARGS. No pointed-to value or address is logged.
Montgomery generation cases also record the scalar CK_RV at function return.

Run only through the isolated supervisor. FE11_OBSERVER_CONFIG contains a path
to public observation metadata; credentials remain on the inferior's stdin.
GDB Python API: https://sourceware.org/gdb/current/onlinedocs/gdb.html/Breakpoints-In-Python.html
"""
from pathlib import Path
import hashlib
import json
import os
import re
import sys
import gdb


def target_image(name):
    """Interpret procfs aliases in the inferior's process, never GDB's process."""
    if name.startswith("/proc/self/"):
        pid = gdb.selected_inferior().pid
        if pid <= 0:
            raise ValueError("inferior process not available")
        name = "/proc/" + str(pid) + "/" + name[len("/proc/self/"):]
    return Path(name).resolve(strict=True)


def configure_symbol_root(directory, module):
    """Bind proc/self to the stopped inferior for GDB's symbol-file reads.

    The supervisor stops at the first instruction before loading this script.
    A private sysroot prevents GDB from opening its own pipe when the program
    loads a library through /proc/self/fd. Symlinks only select symbol files;
    the inferior's filesystem view and loader configuration remain unchanged.
    See https://sourceware.org/gdb/current/onlinedocs/gdb.html/Files.html .
    """
    pid = gdb.selected_inferior().pid
    if pid <= 0:
        raise ValueError("observer requires a stopped live inferior")
    root = directory / "symbol-root"
    root.mkdir(mode=0o700)
    (root / "proc").mkdir(mode=0o700)
    (root / "proc/self").symlink_to(Path("/proc") / str(pid), target_is_directory=True)
    names = {"lib", "lib64", "usr", module.parts[1]}
    if "proc" in names:
        raise ValueError("module must have a persistent image path")
    for name in sorted(names):
        source = Path("/") / name
        if source.is_dir():
            (root / name).symlink_to(source, target_is_directory=True)
    gdb.execute("set sysroot " + str(root), to_string=True)


def file_digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


class Journal:
    def __init__(self, configuration):
        self.module = Path(configuration["module"]).resolve(strict=True)
        self.module_sha = configuration["module_sha256"]
        if not re.fullmatch(r"[0-9a-f]{64}", self.module_sha):
            raise ValueError("invalid module digest")
        if file_digest(self.module) != self.module_sha:
            raise ValueError("observer module identity mismatch")
        functions = configuration["functions"]
        if not functions or len(functions) > 128 or len(set(functions)) != len(functions):
            raise ValueError("invalid observation set")
        if not all(re.fullmatch(r"C_[A-Za-z0-9]+", name) for name in functions):
            raise ValueError("invalid function name")
        output = Path(configuration["output"])
        if not output.is_absolute() or output.is_symlink():
            raise ValueError("invalid observation output")
        self.output = output.open("x", encoding="ascii")
        self.generation_returns = None
        if configuration.get("generation_returns") is True:
            self.generation_returns = (output.parent / "keypair-returns").open("x", encoding="ascii")
        self.generation_entries = 0
        self.generation_completions = 0
        self.initialization_metadata = configuration.get("initialization_metadata", False)
        if not isinstance(self.initialization_metadata, bool):
            raise ValueError("invalid initialization metadata selection")
        self.peer_module = None
        if "peer_module" in configuration:
            self.peer_module = Path(configuration["peer_module"]).resolve(strict=True)
            if (self.peer_module.samefile(self.module)
                    or file_digest(self.peer_module) != self.module_sha):
                raise ValueError("peer must be a distinct file with identical verified bytes")
        self.sequence = 0
        self.failed = False
        self.terminal = False
        self.resolved = {}
        self.breakpoints = []
        self.write(dict(kind="observer", module_sha256=self.module_sha,
                        script_sha256=file_digest(Path(__file__)), gdb_version=gdb.VERSION,
                        python_version=sys.version.split()[0]))
        for function in functions:
            self.breakpoints.append(Entry(function, self))

    def write(self, record):
        try:
            self.output.write(json.dumps(record, separators=(",", ":")) + "\n")
            self.output.flush()
        except (OSError, ValueError):
            self.failed = True
            gdb.write("FE11_OBSERVER_INCOMPLETE\n", gdb.STDERR)

    def validate_locations(self, _event=None, required=None):
        if self.peer_module is not None:
            return self.validate_peer_locations(required)
        for point in self.breakpoints:
            if not point.is_valid() or point.pending:
                if point.function == required:
                    self.failed = True
                continue
            locations = point.locations
            if not locations:
                if point.function == required:
                    self.failed = True
                continue
            if len(locations) != 1:
                self.failed = True
                self.write(dict(kind="observer_failure", category="multiple_locations", function=point.function))
                continue
            address = locations[0].address
            image = gdb.solib_name(address) if address is not None else None
            # During dlclose, GDB can announce a breakpoint modification after
            # removing the image mapping but before marking the point pending.
            # That is not an entry event. Every actual entry still requires a
            # currently mapped address in the selected image.
            if image is None and point.function != required:
                continue
            try:
                resolved_image = target_image(image) if image is not None else None
            except FileNotFoundError:
                # A descriptor may already be closed during unload notification.
                # An actual function entry must still have a live image.
                if point.function != required:
                    continue
                resolved_image = None
            if resolved_image != self.module:
                # Loader notifications may precede GDB's breakpoint relocation.
                # An old address or procfs descriptor can already name another
                # mapping. It is not evidence that this function was called.
                # Only the actual entry requires a currently matching image;
                # never cache or credit an incidental foreign location.
                if point.function == required:
                    self.failed = True
                    self.write(dict(kind="observer_failure", category="foreign_location", function=point.function))
                continue
            previous = self.resolved.get(point.function)
            # A legitimate unload/reload can relocate the same verified image.
            # Record each resolved address instead of imposing address stability.
            if previous != address:
                if file_digest(resolved_image) != self.module_sha:
                    self.failed = True
                    self.write(dict(kind="observer_failure", category="image_changed", function=point.function))
                    continue
                self.resolved[point.function] = address
                self.write(dict(kind="location", function=point.function, address=address,
                                module_sha256=self.module_sha))

    def validate_peer_locations(self, required):
        """Only the explicit two-image scenario admits multiple locations."""
        for point in self.breakpoints:
            if not point.is_valid() or point.pending or not point.locations:
                if point.function == required:
                    self.failed = True
                continue
            if len(point.locations) > 2:
                self.failed = True
                self.write(dict(kind="observer_failure", category="extra_peer_location", function=point.function))
                continue
            verified = []
            for location in point.locations:
                image = gdb.solib_name(location.address) if location.address is not None else None
                if image is None and point.function != required:
                    continue
                try:
                    resolved = target_image(image) if image is not None else None
                except FileNotFoundError:
                    resolved = None
                if resolved not in (self.module, self.peer_module):
                    self.failed = True
                    self.write(dict(kind="observer_failure", category="foreign_peer_location", function=point.function))
                    continue
                if file_digest(resolved) != self.module_sha:
                    self.failed = True
                    continue
                verified.append(location.address)
                old = self.resolved.get(point.function, ())
                if location.address not in old:
                    self.write(dict(kind="location", function=point.function, address=location.address,
                                    module_sha256=self.module_sha, runtime="A" if resolved == self.module else "B"))
            if verified:
                self.resolved[point.function] = tuple(verified)

    def entered(self, function):
        self.validate_locations(required=function)
        if function not in self.resolved or self.terminal:
            self.failed = True
        thread = gdb.selected_thread()
        inferior = gdb.selected_inferior()
        if thread is None or inferior is None:
            self.failed = True
            return
        self.sequence += 1
        entry = dict(kind="entry", sequence=self.sequence, process=inferior.pid,
                     thread=list(thread.ptid), function=function)
        if self.peer_module is not None:
            image = gdb.solib_name(gdb.selected_frame().pc())
            resolved = target_image(image) if image is not None else None
            if resolved not in (self.module, self.peer_module):
                raise ValueError("entry is outside the selected runtime pair")
            entry["runtime"] = "A" if resolved == self.module else "B"
        if self.initialization_metadata and function == "C_Initialize":
            # GDB uses the exact selected image's debug ABI. The expression is
            # constant, contains no inferior call, and reads only this public
            # descriptor. Native callbacks and pReserved are never dereferenced.
            argument = gdb.selected_frame().read_var("pInitArgs")
            descriptor = argument.cast(gdb.lookup_type("CK_C_INITIALIZE_ARGS_PTR"))
            if int(descriptor) == 0:
                raise ValueError("initialization descriptor absent")
            value = descriptor.dereference()
            flags = int(value["flags"])
            if flags < 0 or flags > 3:
                raise ValueError("unexpected initialization flags")
            entry["initialization"] = dict(flags=flags,
                mutexes=[bool(value[name]) for name in ("CreateMutex", "DestroyMutex", "LockMutex", "UnlockMutex")],
                reserved_null=not bool(value["pReserved"]))
        self.write(entry)
        if function == "C_GenerateKeyPair" and self.generation_returns is not None:
            self.generation_entries += 1
            GenerationReturn(self)

    def stopped(self, event):
        if isinstance(event, gdb.SignalEvent):
            self.failed = True
            signal = event.stop_signal
            self.write(dict(kind="signal", signal=signal if re.fullmatch(r"SIG[A-Z0-9]+", signal) else "UNKNOWN"))

    def exited(self, event):
        if self.terminal:
            self.failed = True
        self.terminal = True
        code = getattr(event, "exit_code", None)
        if self.generation_returns is not None:
            self.generation_returns.close()
        complete = (not self.failed and self.generation_completions == self.generation_entries and isinstance(code, int)
                    and len(self.resolved) == len(self.breakpoints))
        self.write(dict(kind="observer_terminal", complete=complete, exit_code=code,
                        events=self.sequence, resolved=len(self.resolved)))
        self.output.close()


class GenerationReturn(gdb.FinishBreakpoint):
    """Observe only CK_RV. Never inspect keys, templates or object handles."""
    def __init__(self, journal):
        super().__init__(gdb.newest_frame(), internal=True)
        self.silent = True
        self.journal = journal

    def stop(self):
        try:
            code = int(self.return_value)
            if not 0 <= code < 2**64:
                raise ValueError("invalid CK_RV")
            self.journal.generation_returns.write(str(code) + "\n")
            self.journal.generation_returns.flush()
            self.journal.generation_completions += 1
        except Exception:
            self.journal.failed = True
            gdb.write("FE11_OBSERVER_INCOMPLETE\n", gdb.STDERR)
        return False

    def out_of_scope(self):
        self.journal.failed = True


class Entry(gdb.Breakpoint):
    def __init__(self, function, journal):
        self.function = function
        self.journal = journal
        # Qualified names exclude similarly named C++ member functions.
        super().__init__(function, internal=True, qualified=True)
        self.silent = True

    def stop(self):
        try:
            self.journal.entered(self.function)
        except Exception:
            self.journal.failed = True
            gdb.write("FE11_OBSERVER_INCOMPLETE\n", gdb.STDERR)
        # Never change execution state or infer a return value.
        return False


config_path = Path(os.environ["FE11_OBSERVER_CONFIG"])
if not config_path.is_absolute() or config_path.stat().st_size > 65536:
    raise ValueError("invalid observer configuration")
configuration = json.loads(config_path.read_text())
if set(configuration) not in ({"module", "module_sha256", "functions", "output"},
                               {"module", "module_sha256", "functions", "output", "initialization_metadata"},
                               {"module", "module_sha256", "functions", "output", "generation_returns"},
                               {"module", "module_sha256", "functions", "output", "peer_module"}):
    raise ValueError("unknown observer configuration field")
output_path = Path(configuration["output"])
if not output_path.resolve().is_relative_to(config_path.parent.resolve()):
    raise ValueError("observer output must stay in its owned job directory")
configure_symbol_root(config_path.parent, Path(configuration["module"]).resolve(strict=True))
gdb.execute("set breakpoint pending on")
journal = Journal(configuration)
gdb.events.breakpoint_modified.connect(journal.validate_locations)
gdb.events.new_objfile.connect(journal.validate_locations)
gdb.events.free_objfile.connect(journal.validate_locations)
gdb.events.stop.connect(journal.stopped)
gdb.events.exited.connect(journal.exited)
