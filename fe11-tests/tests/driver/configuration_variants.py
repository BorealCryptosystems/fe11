# SPDX-License-Identifier: Apache-2.0
"""Apply explicit module configurations to one newly provisioned owned case."""

VARIANTS = {
    "removable-true": "slots.removable = true\n",
    "removable-false": "slots.removable = false\n",
    "mechanisms-include": "slots.mechanisms = CKM_SHA256\n",
    "mechanisms-exclude": "slots.mechanisms = -CKM_SHA256\n",
    "mechanisms-empty": "slots.mechanisms =\n",
    "mechanisms-default": "",
    "reset-true": "library.reset_on_fork = true\n",
    "reset-false": "library.reset_on_fork = false\n",
    "log-error": "log.level = ERROR\n",
    "log-warning": "log.level = WARNING\n",
    "log-info": "log.level = INFO\n",
    "log-debug": "log.level = DEBUG\n",
    "log-invalid": "log.level = INVALID\n",
    "malformed-line": "not a configuration assignment\n",
    "unknown-key": "unknown.public_test_option = true\n",
    "absent-file": None,
    "directory-missing": "",
    "directory-file": "",
    "directory-inaccessible": "",
    "log-owned": "",
    "log-unopenable": "",
    "log-secret-sentinel": "",
    "umask-zero": "objectstore.umask = 0\n",
    "umask-private": "objectstore.umask = 0077\n",
    "umask-deny": "objectstore.umask = 0777\n",
    "umask-invalid": "objectstore.umask = invalid\n",
}


def apply(root, config, case, vector):
    """No caller-supplied path or configuration text is interpolated."""
    variant = case["configuration_variant"]
    secret_case = variant == "log-secret-sentinel"
    expected_mode = "object-contract" if secret_case else "builder-runtime-choices"
    expected_prefix = "reporting-secret-sentinel" if secret_case else "configuration:" + variant
    if (case["worker_mode"] != expected_mode or variant not in VARIANTS
            or vector.stat().st_size > 8192
            or vector.read_text().splitlines()[0] != expected_prefix):
        raise ValueError("configuration fixture and recipe disagree")
    root = root.resolve(strict=True)
    if any(character in str(root) for character in ("\n", "\r", "\0")):
        raise ValueError("configuration directory contains a delimiter")
    if (config.is_symlink() or config.resolve(strict=True) != root / "softhsm.conf"
            or config.stat().st_size > 4096):
        raise ValueError("configuration must be the small owned case file")
    original = config.read_text()
    # Preserve the provisioned recipe before changing only this worker's file.
    with (root / "baseline-softhsm.conf").open("x") as stream:
        stream.write(original)
    change = VARIANTS[variant]
    if variant == "directory-inaccessible":
        target = root / "tokens"
        if target.is_symlink() or target.resolve(strict=True).parent != root:
            raise ValueError("permission target must be this case's owned store")
        target.chmod(0)
    elif variant in ("directory-missing", "directory-file"):
        target = root / "configuration-token-directory"
        if target.exists() or target.is_symlink():
            raise ValueError("configuration target must be new")
        if variant == "directory-file":
            with target.open("x") as stream:
                stream.write("This owned ordinary file is not a token directory.\n")
        change = "directories.tokendir = " + str(target) + "\n"
    elif variant in ("log-owned", "log-unopenable", "log-secret-sentinel"):
        target = root / "missing-log-parent" / "module.log" if variant == "log-unopenable" else root / "module.log"
        if target.exists() or target.is_symlink():
            raise ValueError("log target must be new")
        if variant == "log-unopenable" and target.parent.exists():
            raise ValueError("log failure requires an absent owned parent")
        change = "log.level = DEBUG\nlog.file = " + str(target) + "\n"
    if change is None:
        config.unlink()
    else:
        config.write_text(original + change)


def observe(root, case, credentials, public_result=None):
    """Return bounded file evidence; never expose module logs or credentials."""
    variant = case["configuration_variant"]
    root = root.resolve(strict=True)
    if variant == "directory-inaccessible":
        from denied_directory import inspect
        return inspect(root)
    if variant.startswith("umask-"):
        from permission_modes import inspect
        return inspect(root, variant)
    if variant == "log-secret-sentinel":
        from secret_log_scan import inspect
        return inspect(root, credentials, public_result)
    if variant == "log-owned":
        path = root / "module.log"
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1_048_576:
            raise ValueError("owned log is missing or outside its size bound")
        data = path.read_bytes()
        secret_present = any(bytes(value) in data or bytes(value).hex().encode() in data
                             for value in credentials if value)
        return {"status": "PASS" if data and not secret_present else "FAIL",
                "bytes": len(data), "credential_present": secret_present}
    if variant == "log-unopenable":
        absent = not (root / "missing-log-parent").exists()
        return {"status": "PASS" if absent else "FAIL", "owned_log_parent_absent": absent}
    return {"status": "PASS", "file_assertion": "NOT_REQUESTED"}
