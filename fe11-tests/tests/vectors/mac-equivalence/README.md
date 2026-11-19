# Managed and native HMAC

RFC4231 test case 6 supplies a 131-byte public test key, the 54-byte message
and its exact HMAC-SHA256 tag. One imported object is used through both the
managed introduced-key API and the native-object API. Each result must equal
the published tag independently. Single-part and multipart verification use
that same tag. Multipart includes an empty update between two nonempty parts.
