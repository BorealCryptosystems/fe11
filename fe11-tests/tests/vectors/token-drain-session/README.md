# Foreign sessions during token drainage

Each invocation provisions a second real token only in the fresh private
directory owned by its supervisor. An initialized token is never reset.
Token A is drained while token B owns a live SHA-256 operation. The three
foreign-session refusals must dispatch nothing and preserve B's digest.
All sessions and the module close explicitly before the supervisor removes
the isolated directory, including its two test tokens.
