# Inaccessible owned token directory

After ordinary provisioning, the case sets its own token directory to mode000.
The native worker checks that Linux DAC bypass capabilities are absent. When
the supervisor has those capabilities, a child-only setpriv invocation removes
them before GDB and the worker start; the parent keeps its original privileges.
Initialization must fail with the exact native code, without a finalized owner.
Permissions are restored on the same checked directory after child exit, then
the ordinary ownership-checked cleanup removes the disposable token store.
