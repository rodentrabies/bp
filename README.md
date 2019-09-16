# BP - Bitcoin Protocol

This is a Common Lisp implementation of the various components of the
Bitcoin Protocol. The serialization/deserialization utils may be used
for reading the block data both from peers and from local database on
disk. The cryptographic utilities are aggregated from FFI bindings to
the [secp256k1] and [ironclad]. HTTP client code uses [aserve], while
and JSON handling is done with [jsown] package.

**THIS BITCOIN CONSENSUS RULES IMPLEMENTATION IS NOT, AND WILL
PROBABLY NEVER BE FULLY COMPLIANT WITH BITCOIN CORE IMPLEMENTATION. DO
NOT RELY ON IT FOR VALIDATING YOUR MAINNET TRANSACTIONS, AS IT MAY
EASILY PUT YOU OUT OF SYNC WITH THE NETWORK IN A LOT OF CORNER
CASES.**

## Interface
Currently, this library only provides utilities for stateless
interaction with Bitcoin from REPL. Storage, wallet and full node
capabilities are somewhere in a distant future.

### Chain interface
Functions `bp:get-block-hash`, `bp:get-block` and `bp:get-transaction`
allow to pull chain data from any external supplier specified with the
`bp:with-chain-supplier` macro:

``` cl
CL-USER> (bp:with-chain-supplier (:url      "http://localhost:8332"
                                  :username "btcuser"
                                  :password "btcpassword")
           (bp:get-transaction "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"))
#<BP/CORE/TRANSACTION:TX 0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098>
```

Under the hood, these operations call corresponding generic functions
`bp:chain-get-{block-hash,block,transaction}` which take the supplier
object as an explicit first argument.

### Model and serialization
Bitcoin data entities are represented by the following structures:
- `bp:block-header`;
- `bp:merkle-block`;
- `bp:tx`;
- `bp:txin`;
- `bp:txout`;
- `bp:script`.

Functions named `bp:block-*` (both for `bp:block-header` and
`bp:merkle-block`), `bp:tx-*`, `bp:txin-*` and `bp:txout-*` provide
access to the components of the corresponding entities.

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

### Validation
Functions `bp:validate` and `bp:validp` take an entity as well as the
optional context parameters, and validate it according to an
approximation of Bitcoin consensus rules. 

Both functions return `t` if the entity is valid, but the
`bp:validate` function signals an error otherwise, while the
`bp:validp` function simply returns `nil`.

Both functions assume the chain supplier context (i.e. they are called
within the body of `bp:with-chain-supplier`).

[secp256k1]: https://github.com/bitcoin-core/secp256k1
[ironclad]: https://github.com/sharplispers/ironclad
[aserve]: https://sourceforge.net/projects/portableaserve
[jsown]: https://github.com/madnificent/jsown
