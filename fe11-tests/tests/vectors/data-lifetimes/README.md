# Data object lifetimes

The eight cases cross TOKEN and PRIVATE with visibility after logout and
the lifetime of two independently searched aliases after creator closure.
Every retained value is read as CKO_DATA with exact application/value bytes.
Private session objects disappear on logout; private token objects become
visible again after login. Aliases do not extend a session object's lifetime.

Each invocation owns its fresh token and label. Cleanup refreshes the owned
reference after authentication changes, destroys remaining objects, closes
both sessions and finalizes before reporting results.
