# Private material in diagnostic paths

Each execution uses fresh ephemeral credentials received over stdin and a
distinct private, sensitive, nonextractable session-key marker. The module
performs MAC generation and verification before explicit destruction/logout.
The supervisor scans its seven owned diagnostic files and pending public JSON
for the credential/key bytes in the listed encodings. It records only counts
and a Boolean. This bounded check makes no claim about other encodings, paths,
native-memory erasure or arbitrary process-memory disclosure.
