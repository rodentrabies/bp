# BP - Bitcoin Protocol

[![Quicklisp](http://quickdocs.org/badge/bp.svg)](http://quickdocs.org/bp/)

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

## Installation
Elliptic curve cryptography utilities (transaction signing and
verification) use a [secp256k1] library, so it must be installed
before building the `bp` system (either manually, or using the system
package manager if available):

``` bash
# Ubuntu
apt install libsecp256k1 libsecp256k1-dev

# Arch Linux
pacman -Syu libsecp256k1

# macOS
brew tap cuber/homebrew-libsecp256k1
brew install libsecp256k1
```

Once [secp256k1] is ready, `bp` can be installed via [quicklisp] tool:

``` cl
(ql:quickload :bp)
```

Alternatively, `bp` system can be loaded from sources, assuming the
following Common Lisp packages are available locally:
- [`asdf`][asdf];
- [`aserve`][aserve];
- [`cffi`][cffi];
- [`ironclad`][ironclad];
- [`jsown`][jsown].

In order to load `bp` from sources, evaluate the following form (this
assumes that ASDF is able to find the system definition; more on that
[here][asdf-registry]):

``` cl
(asdf:load-system :bp)
```

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
- `bp:cblock`;
- `bp:tx`;
- `bp:txin`;
- `bp:txout`;
- `bp:script`.

Functions named `bp:block-*` (both for `bp:block-header` and
`bp:cblock`), `bp:tx-*`, `bp:txin-*` and `bp:txout-*` provide
access to the components of the corresponding entities.

Functions `bp:parse` and `bp:serialize` can be used to read and
write any Bitcoin entity from and to any octet stream respectively:

``` cl
CL-USER> (ironclad:with-octet-input-stream (stream #(1 0 ... 0 0))
           (bp:parse 'bp:tx in-stream))
#<BP/CORE/TRANSACTION:TX 17e590f116d3deeb9b121bbb1c37b7916e6b7859461a3af7edf74e2348a9b347>
CL-USER> (ironclad:with-octet-output-stream (stream)
           (bp:parse 'tx out-stream))
#(1 0 ... 0 0)
```

Note that while `bp:serialize` function take an entity as its first
argument, `bp:parse` takes the symbol naming the class of the
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

Dynamic variable `bp:*trace-script-execution*` can be used to enable
printing the steps of script execution (chain supplier macro omitted):

``` cl
CL-USER> (setf bp:*trace-script-execution* t)
t
CL-USER> (bp:validate (bp:get-transaction "17e590f116d3deeb9b121bbb1c37b7916e6b7859461a3af7edf74e2348a9b347"))
op:       OP_PUSH22
payload:  #(0 14 a4 b4 ca 48 de b 3f ff c1 54 4 a1 ac dc 8d ba ae 22 69
            55)
commands: <>
stack:    ()

op:       OP_HASH160
payload:  -
commands: <OP_PUSH20 OP_EQUAL>
stack:    (#(0 14 a4 b4 ca 48 de b 3f ff c1 54 4 a1 ac dc 8d ba ae 22
             69 55))

op:       OP_PUSH20
payload:  #(29 28 f4 3a f1 8d 2d 60 e8 a8 43 54 d 80 86 b3 5 34 13 39)
commands: <OP_EQUAL>
stack:    (#(29 28 f4 3a f1 8d 2d 60 e8 a8 43 54 d 80 86 b3 5 34 13 39))

op:       OP_EQUAL
payload:  -
commands: <>
stack:    (#(29 28 f4 3a f1 8d 2d 60 e8 a8 43 54 d 80 86 b3 5 34 13 39)
           #(29 28 f4 3a f1 8d 2d 60 e8 a8 43 54 d 80 86 b3 5 34 13 39))

op:       OP_FALSE
payload:  -
commands: <OP_PUSH20>
stack:    ()

op:       OP_PUSH20
payload:  #(a4 b4 ca 48 de b 3f ff c1 54 4 a1 ac dc 8d ba ae 22 69 55)
commands: <>
stack:    (#())

t
```

[secp256k1]: https://github.com/bitcoin-core/secp256k1
[asdf]: https://gitlab.common-lisp.net/asdf/asdf
[cffi]: https://github.com/cffi/cffi
[ironclad]: https://github.com/sharplispers/ironclad
[aserve]: https://sourceforge.net/projects/portableaserve
[jsown]: https://github.com/madnificent/jsown
[quicklisp]: https://www.quicklisp.org/beta
[asdf-registry]: https://common-lisp.net/project/asdf/asdf/Configuring-ASDF-to-find-your-systems.html
