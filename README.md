# BP - Bitcoin Protocol

This is a Common Lisp implementation of the various components of the
Bitcoin Protocol. The serialization/deserialization utils may be used
for reading the block data both from peers and from local database on
disk. The cryptographic utilities are aggregated from FFI bindings to
the [secp256k1] and [ironclad].

[secp256k1]: https://github.com/bitcoin-core/secp256k1
[ironclad]: https://github.com/sharplispers/ironclad
