# BP - Bitcoin Protocol

This is a Common Lisp implementation of the various components of the
Bitcoin Protocol. The serialization/deserialization utils may be used
for reading the block data both from peers and from local database on
disk. The cryptographic utilities are aggregated from FFI bindings to
the [secp256k1] and [ironclad].

## Interface

Functions `bp:deserialize` and `bp:serialize` can be used to read and
write any Bitcoin entity from and to any octet stream respectively:

``` cl
CL-USER> (ironclad:with-octet-input-stream (stream #(1 0 ... 0 0))
           (bp:deserialize 'bp:tx in-stream))
#<BP/CORE/TRANSACTION:TX 17e590f116d3deeb9b121bbb1c37b7916e6b7859461a3af7edf74e2348a9b347>
CL-USER> (ironclad:with-octet-output-stream (stream)
           (bp:deserialize 'tx out-stream))
#(1 0 ... 0 0)
```

Note that while `bp:serialize` function take an entity as its first
argument, `bp:deserialize` takes the symbol naming the class of the
entity, behaving as *class method*.

Functions `bp:decode` and `bp:encode` wrap above functions to decode
and encode Bitcoin entities from and to hex-encoded strings:

``` cl
CL-USER> (bp:decode 'bp:tx "0100000002f8615378...e097a988ac00000000")
#<BP/CORE/TRANSACTION:TX 17e590f116d3deeb9b121bbb1c37b7916e6b7859461a3af7edf74e2348a9b347>
CL-USER> (bp:encode *)
"0100000002f8615378...e097a988ac00000000"
```

[secp256k1]: https://github.com/bitcoin-core/secp256k1
[ironclad]: https://github.com/sharplispers/ironclad
