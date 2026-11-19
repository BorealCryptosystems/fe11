# Input attribute-template boundaries

The flat and nested graphs exercise independent descriptor-count, depth and value-byte
limits. An empty search accepts zero limits. Invalid representations preserve exact
typed errors with no native call. Valid exact, plus-one and maximal limits encode
the same small graph; no huge buffer or slice is constructed. Native creations
remain owned for cleanup, with labels and nested descriptor lengths checked.
