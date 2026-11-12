Owned module settings. Construction and setters perform no native calls.
Every opening choice must be supplied before any optional setter is used.

Opening and observation discover interfaces directly. Visible exports need not
belong to the same native runtime, so discovery does not reserve their lifecycle
or serialize them with existing instances. The application must respect the
module's native concurrency contract, including exclusion of concurrent Finalize,
until table and interface metadata have been copied. Retaining the library image
prevents unloading; it does not provide that lifecycle coordination. Once the
initializer is identified, runtime ownership and initialization are coordinated
separately. The selected initialization policy governs subsequent instance calls.

```no_run
use fe11::{InterfaceSelection, Module, ModuleConfig, ModuleOptions, Result, SymmetricLimits};
fn configured(config: ModuleConfig, options: ModuleOptions) -> Result<Module> {
    Module::builder(config, options)
        .interface(InterfaceSelection::Standard {
            version: (3, 2),
            required_flags: 0,
        })
        .symmetric_limits(SymmetricLimits {
            maximum_buffer_bytes: 8 << 20,
        })
        .open()
}
```
