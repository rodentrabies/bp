<!--
Copyright (c) 2019-2025 BP Developers & Contributors
See the accompanying file LICENSE for the full license governing this code.
-->

[asdf-registry]: https://common-lisp.net/project/asdf/asdf/Configuring-ASDF-to-find-your-systems.html
[asdf]: https://gitlab.common-lisp.net/asdf/asdf
[aserve]: https://sourceforge.net/projects/portableaserve
[bip-0034]: https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki
[brdf]: https://github.com/rodentrabies/brdf
[cffi]: https://github.com/cffi/cffi
[getdata-docs]: https://en.bitcoin.it/wiki/Protocol_documentation#getdata
[ironclad]: https://github.com/sharplispers/ironclad
[jsown]: https://github.com/madnificent/jsown
[quicklisp]: https://www.quicklisp.org/beta
[secp256k1]: https://github.com/bitcoin-core/secp256k1
[usocket]: https://github.com/usocket/usocket

[ci-status]: https://github.com/rodentrabies/bp/actions/workflows/ci.yml
[ci-status-badge]: https://github.com/rodentrabies/bp/actions/workflows/ci.yml/badge.svg


<!-- README.md starts with a logo. -->
<p align="center">
  <img src="docs/logo.svg" width="70%" alt="(bp) logo">
</p>


<div align="center">

# (bp) - Bitcoin Protocol (in Lisp)

</div>

<!--
Quicklisp badge is hidden for now because the library is no longer in
the registry for some reason.

[![Quicklisp](http://quickdocs.org/badge/bp.svg)](https://quickref.common-lisp.net/bp.html)
-->

[![CI][ci-status-badge]][ci-status]

**(bp)** is a Common Lisp implementation of the various components of
the Bitcoin Protocol. The serialization and deserialization utils may
be used for reading the block data both from peers and from local
database on disk. EC-based cryptographic operations are implemented as
FFI bindings to the [secp256k1] using [cffi], while hash-functions are
taken from [ironclad]. Low-level networking is implemented using
[usocket], HTTP client code uses [aserve] and JSON handling is done
with [jsown].

**THIS BITCOIN CONSENSUS RULES IMPLEMENTATION IS NOT, AND WILL
PROBABLY NEVER BE FULLY COMPLIANT WITH BITCOIN CORE IMPLEMENTATION. DO
NOT RELY ON IT FOR VALIDATING YOUR MAINNET TRANSACTIONS, AS IT MAY
EASILY PUT YOU OUT OF SYNC WITH THE NETWORK IN A LOT OF CORNER
CASES.**


<a id="table-of-contents"></a>
## Table of Contents
- [Installation](#installation)
- [Package structure](#package-structure)
- [`bp`, `bp.core` - core datastructures and consensus](#core)
  - [Chain interface](#chain-interface)
  - [Model](#model)
  - [Serialization](#serialization)
  - [Validation](#validation)
- [Subsystems](#subsystems)
  - [`bp.net` - peer-to-peer network](#network)
  - [`bp.rpc` - RPC node connection](#rpc)
- [Examples](#examples)
- [API changes](#api-changes)
- [License](#license)


<a id="installation"></a>
## Installation

Elliptic curve cryptography utilities (transaction signing and
verification) use a [secp256k1] library, so it must be installed
before building the `bp` system (either manually, or using the system
package manager if available):

``` bash
# Ubuntu
$ apt install libsecp256k1 libsecp256k1-dev

# Arch Linux
$ pacman -Syu libsecp256k1

# macOS
$ brew tap cuber/homebrew-libsecp256k1
$ brew install libsecp256k1
```

Once [secp256k1] is ready, `bp` can be installed via [quicklisp] tool:

    CL-USER> (ql:quickload "bp")

Alternatively, `bp` system can be loaded from sources, assuming the
following Common Lisp packages are available locally:
  - [`asdf`][asdf],
  - [`aserve`][aserve],
  - [`cffi`][cffi],
  - [`usocket`][usocket],
  - [`ironclad`][ironclad],
  - [`jsown`][jsown].

In order to load `bp` from sources, evaluate the following form (this
assumes that ASDF is able to find the system definition; more on that
[here][asdf-registry]):

``` lisp
CL-USER> (asdf:load-system "bp")
```



<a id="package-structure"></a>
## Package structure

`bp` codebase utilises ASDF's `package-inferred-system` extension,
which means that every file is a separate package whose name matches
the filesystem path of that file relative to the root directory,
e.g. `core/block.lisp` file corresponds to `bp.core.block` package.

Files called `all.lisp` contain interface packages that reexport all
API components of their "subpackages" - packages on the same project
hierarchy level. An interface package defined in a file
`<component>/all.lisp` has a name `bp.<component>`. For example,
interface package defined in `crypto/all.lisp` file is called
`bp.crypto`.

Below is a table that lists the top-level components of the `bp`
system:

| Interface package | Implementation packages                                                                                                                                                                   | Corresponding ASDF system                                                                                                                                                                     | Description                                                        |
|-------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------|
| `bp`, `bp.core`   | `bp.core`<br>`bp.core.parameters`<br>`bp.core.chain`<br>`bp.core.block`<br>`bp.core.transaction`<br>`bp.core.script`<br>`bp.core.encoding`<br>`bp.core.consensus`<br>`bp.core.merkletree` | `bp/core/all`<br>`bp/core/parameters`<br>`bp/core/chain`<br>`bp/core/block`<br>`bp/core/transaction`<br>`bp/core/script`<br>`bp/core/encoding`<br>`bp/core/consensus`<br>`bp/core/merkletree` | Bitcoin chain data,<br>consensus, serialization,<br>core utilities |
| `bp.crypto`       | `bp.crypto`<br>`bp.crypto.secp256k1`<br>`bp.crypto.hash`<br>`bp.crypto.random`                                                                                                            | `bp/crypto/all`<br>`bp/crypto/secp256k1`<br>`bp/crypto/hash`<br>`bp/crypto/random`                                                                                                            | Cryptographic tools                                                |
| `bp.net`          | `bp.net`<br>`bp.net.address`<br>`bp.net.message`<br>`bp.net.node`<br>`bp.net.parameters`                                                                                                  | `bp/net/all`<br>`bp/net/address`<br>`bp/net/message`<br>`bp/net/node`<br>`bp/net/parameters`                                                                                                  | Peer-to-peer network                                               |
| `bp.rpc`          | `bp.rpc`                                                                                                                                                                                  | `bp/rpc/all`                                                                                                                                                                                  | RPC interface to <br> Bitcoin node                                 |

It is **strongly advised** to avoid using packages in the second
column directly, as these might change in the future. At this point
only the interface packages (first column) and the symbols exported
from them can be considered an API.



<a id="core"></a>
## `bp`, `bp.core` - core datastructures and consensus

Currently this library only provides utilities for simple interaction
with Bitcoin network and/or Bitcoin Core node. Storage, wallet and
full node capabilities are somewhere in a distant future.


<a id="chain-interface"></a>
### Chain interface

Functions `bp:get-block-hash`, `bp:get-block` and `bp:get-transaction`
allow to pull chain data from any external supplier specified with the
`bp:with-chain-supplier` macro:

``` lisp
CL-USER> (bp:with-chain-supplier (bp.rpc:node-rpc-connection
                                  :url "http://localhost:8332"
                                  :username "btcuser"
                                  :password "btcpassword")
           (bp:get-transaction "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"))
#<BP.CORE.TRANSACTION:TX 0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098>
```

Non-`nil` keyword argument `:encoded` can be used with `bp:get-block`
and `bp:get-transaction` to return serialized transaction hex-encoded
in a string:

``` lisp
CL-USER> (bp:get-transaction "14...c3" :encoded t)
"010000000...ae00000000"
```

Under the hood, these operations call corresponding generic functions
`bp:chain-get-{block-hash,block,transaction}` which take the supplier
object as an explicit first argument.


<a id="model"></a>
### Model

Bitcoin data entities are represented by the following structures:
  - `bp:block-header`,
  - `bp:cblock`,
  - `bp:tx`,
  - `bp:txin`,
  - `bp:txout`,
  - `bp:script`.

Functions named `bp:block-*` (both for `bp:block-header` and
`bp:cblock`), `bp:tx-*`, `bp:txin-*` and `bp:txout-*` provide access
to the components of the corresponding entities.

<a id="serialization"></a>
### Serialization

Functions `bp:parse` and `bp:serialize` can be used to read and write
any Bitcoin entity from and to any octet stream respectively:

``` lisp
CL-USER> (ironclad:with-octet-input-stream (stream #(1 0 ... 0 0))
           (bp:parse 'bp:tx in-stream))
#<BP.CORE.TRANSACTION:TX 17e590f116d3deeb9b121bbb1c37b7916e6b7859461a3af7edf74e2348a9b347>
CL-USER> (ironclad:with-octet-output-stream (stream)
           (bp:parse 'tx out-stream))
#(1 0 ... 0 0)
```

Note that while `bp:serialize` function take an entity as its first
argument, `bp:parse` takes the symbol naming the class of the entity,
behaving as **class method**.

Functions `bp:decode` and `bp:encode` wrap above functions to decode
and encode Bitcoin entities from and to hex-encoded strings:

``` lisp
CL-USER> (bp:decode 'bp:tx "0100000002f8615378...e097a988ac00000000")
#<BP.CORE.TRANSACTION:TX 17e590f116d3deeb9b121bbb1c37b7916e6b7859461a3af7edf74e2348a9b347>
CL-USER> (bp:encode *)
"0100000002f8615378...e097a988ac00000000"
```


<a id="validation"></a>
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

``` lisp
CL-USER> (setf bp:*trace-script-execution* t)
T
CL-USER> (bp:validate
          (bp:get-transaction "17e590f116d3deeb9b121bbb1c37b7916e6b7859461a3af7edf74e2348a9b347"))
op:       OP_PUSH22
payload:  #(0 14 a4 b4 ca 48 de b 3f ff c1 54 4 a1 ac dc 8d ba ae 22 69 55)
commands: <>
stack:    ()

op:       OP_HASH160
payload:  -
commands: <OP_PUSH20 OP_EQUAL>
stack:    (#(0 14 a4 b4 ca 48 de b 3f ff c1 54 4 a1 ac dc 8d ba ae 22 69 55))

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

T
```

Validating certain entities requires additional information (block
height, transactions index, block/transaction itself, etc), which can
be packed into an instance of `bp:validation-context` class. For
example, validating a coinbase transaction will fail, because the only
transaction input it contains will have its `previous-tx-id` set to 0,
which is invalid for regular transactions. For example, to be
considered valid, a coinbase transaction must be the first transaction
of its block, while the block itself is required for amount
verification (to calculate the collected fees) and block height may be
needed to perform the [BIP-0034][bip-0034] check, so such a
transaction can be validated using the following form:

``` lisp
CL-USER> (let* ((block
                  (bp:get-block "00000000000000d0dfd4c9d588d325dce4f32c1b31b7c0064cba7025a9b9adcc"))
                (context
                  (make-instance 'bp:validation-context :tx-index 0 :height 227836 :block block))
           (bp:validate
            (bp:get-transaction "0f3601a5da2f516fa9d3f80c9bf6e530f1afb0c90da73e8f8ad0630c5483afe5")
            :context context)))
T
```



<a id="subsystems"></a>
## Subsystems

Below is the list of `bp` subsystems that are intended to be more or
less self-contained and suitable for use in other software separately
from the rest of the `bp` system.

<a id="network"></a>
### `bp.net` - peer-to-peer network

`bp.net` package provides simple utilities for interacting with Bitcoin
network - a subset of network messages and functions for establishing
connections with other network nodes as well as requesting blocks and
transactions.

In order to demontrate interaction with Bitcoin network, we can start
a `regtest` Bitcoin node:

``` bash
# Start Bitcoin daemon:
$ bitcoind --daemon --regtest --datadir=$HOME/.bitcoin

# Generate a few blocks:
$ bitcoin-cli --regtest generatetoaddress 5 $(bitcoin-cli --regtest getnewaddress)

# Enable net logging:
$ bitcoin-cli --regtest logging "[\"net\"]"

# Tail log file to see the incoming messages:
$ tail -f ~/.bitcoin/regtest/debug.log
```

Executing the following forms from Lisp REPL will perform a handshake
with Bitcoin node:

``` lisp
CL-USER> (defvar *node* (make-instance 'bp.net:simple-node :network :regtest))
...
CL-USER> (bp.net:connect-peer *node* :host "127.0.0.1" :port 18444)
...
```

`bp.net:simple-node` is a very simple network node implementation that
maintains a single peer connection and provides `bp.net:send-message`
and `bp.net:receive-message` functions for sending and receiving
messages, respectively.

Alternatively, `bp.net:simple-node` can be asked to discover a peer
using a hardcoded DNS seed, but this is currently only supported on
mainnet. The following form will select a random peer and shake hands
with it:

``` lisp
CL-USER> (setf *node* (make-instance 'bp.net:simple-node :peer :discover))
...
```

Objects of `bp.net:simple-node` partially implement chain supplier
interface - `bp:chain-get-block-hash` is currently not supported,
`bp:chain-get-transaction` only returns transactions that are
currently in the mempool or in relay set (this is an [intentional
limitation][getdata-docs] of the Bitcoin gossip protocol to prevent
clients from assuming all nodes keep full transaction indexes).
`bp:chain-get-block` works as expected. In the example below
`<block-hash>` must be a hash of one of the blocks generated by the
`generatetoaddress` command above:

``` lisp
CL-USER> (bp:chain-get-block *node* <block-hash>)
...
```



<a id="rpc"></a>
### `bp.rpc` - RPC node connection

`bp.rpc` package provides `bp.rpc:node-rpc-connection` class which is
an RPC client for the `bitcoind` RPC server. It was mentioned above as
one of the implementations of the chain supplier interface, but it
also supports the following RPC operations that correspond to the
`bitcoind` RPC methods (and `bitcoin-cli` commands) with the same
name:

- `bp.rpc:getblockhash`;
- `bp.rpc:getblock`;
- `bp.rpc:getrawtransaction`;
- `bp.rpc:getchaintxstats`.

Note that results of RPC operations are `jsown` JSON structures, so
specific parts of these structures have to be extracted manually:

``` lisp
cl-user> (let* ((node-connection (make-instance 'bp.rpc:node-rpc-connection :url <url>))
                (chain-stats (bp.rpc:getchaintxstats node-connection))
                (chain-blocks (jsown:val chain-stats "window_final_block_height"))
                (chain-txs (jsown:val chain-stats "txcount")))
           (format t "Blocks: ~a, transactions: ~a~%" chain-blocks chain-txs))
```
<a id="examples"></a>
## Examples

- [BRDF - Bitcoin time chain data represented as RDF][brdf]



<a id="change-log"></a>
## API changes

See [CHANGELOG.md](CHANGELOG.md).



<a id="license"></a>
## License

Copyright (c) 2019-2021 whythat \<whythat@protonmail.com\>\
Copyright (c) 2021-2023 rodentrabies \<rodentrabies@protonmail.com\>\
Copyright (c) 2019-2025 BP Developers & Contributors

Licensed under MIT License. See [LICENSE](LICENSE).
