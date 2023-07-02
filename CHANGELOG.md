# `bp` API changes

Here is a list of API changes for each version of `bp` to help users
to identify potential incompatibilities.

Changes that are marked with **\[BREAKING\]** are breaking the
compatibility with the older versions by removing/replacing one or
more exported symbols or changing the behaviour of one or more
exported functions. Generally these will become very rare with
versions 0.1 and onward, but until 0.1 are bound to happen to make API
as consistent as possible.

## BP 0.0.5

- **\[BREAKING\]** All slash-separated package names were replaced
  with dot-separated ones (e.g. `bp/crypto/secp256k1` became
  `bp.crypto.secp256k1`). The old package names are still available as
  aliases, but will be removed in the future. Package names
  `bp.crypto`, `bp.net` and `bp.rpc` should be used instead of aliases
  `bpcrypto`, `bpnet` and `bprpc`, which will be removed in the future
  as well.

## BP 0.0.4

- New representation format for `OP_PUSHDATA*` script commands now
  includes a byte sequence representation of the length of the payload
  to ensure `(serialize (parse ...))` produces the same byte sequence
  even for scripts with unexpected ends.

- Functions `bp.crypto.secp256k1:context-create-{none,sign,verify}`
  for context initialization no longer exist and their functionality
  has been replaced with `bp.crypto.secp256k1::context-create` and
  `bp.crypto.secp256k1::context-randomize` which are unexported.

## BP 0.0.3

- The RPC-based chain supplier `bp:node-connection` was renamed to
  `bp.rpc:node-rpc-connection` for clarity. It is still possible to
  use the `bp:node-connection` name, but it will issue a warning and
  will be removed in one of the next `0.0.*` releases.

- **\[BREAKING\]** Functions `bp:to-hex` and `bp:from-hex` were
  renamed to `bp:hex-encode` and `bp:hex-decode` respectively for
  consistency with other encoding functions.
