# Token-store creation permissions

Four explicit module masks are installed before provisioning: 0, 0077, 0777,
and invalid octal text. The child process has OS umask zero; the supervisor's
mask is unchanged. Every created directory and file is inspected before owned
cleanup. An isolated root container is required to finish provisioning mode000.
This checks creation modes, not denial of access to a privileged process.
Invalid text becomes zero in the pinned module parser. No PKCS#11 error or
module-independent configuration grammar is inferred from that behavior.
