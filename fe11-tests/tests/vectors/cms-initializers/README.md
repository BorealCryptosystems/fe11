# CMS initializer refusals

Session and AdvancedSession request normal and recovery CMS signing and
verification with real imported RSA keys and the corresponding usage flag.
Normal calls receive MECHANISM_INVALID; recovery initializers receive
FUNCTION_NOT_SUPPORTED from this recipe. The observer requires the exact
initializer and excludes any subsequent content call.

These cases distinguish unsupported native entry points from local routing or
content errors. They make no claim of valid CMS content or CMS cryptography.
The key fixture is shared with the separately retained RSA controls.
