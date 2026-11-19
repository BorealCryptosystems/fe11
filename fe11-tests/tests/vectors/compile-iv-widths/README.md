# Fixed-width CBC initialization vectors

Each invalid zero, block-minus-one or block-plus-one IV is paired with a
compiling block-sized control. The compiler must reject the exact public
constructor with E0308 at its IV expression. No fixture parser or native module
is involved in that refusal. Runtime positive vectors separately establish
successful CBC operations with the required width.
