;;; Copyright (c) 2019-2025 BP Developers & Contributors
;;; See the accompanying file LICENSE for the full license governing this code.

(defsystem "bp"
    :description "Bitcoin Protocol components in Common Lisp"
  :version "0.0.6"
  :author "rodentrabies <rodentrabies@protonmail.com>"
  :license "MIT"
  :class :package-inferred-system
  :in-order-to ((test-op (test-op "bp/tests")))
  ;; Components:
  :depends-on ("bp/core/all"
               "bp/crypto/all"
               "bp/net/all"
               "bp/rpc/all")
  ;; External dependencies:
  :depends-on ("cffi"
               "aserve"
               "jsown"
               "ironclad"
               "usocket"))

(register-system-packages "bp/core/all" :bp.core)
(register-system-packages "bp/core/block" :bp.core.block)
(register-system-packages "bp/core/chain" :bp.core.chain)
(register-system-packages "bp/core/consensus" :bp.core.consensus)
(register-system-packages "bp/core/encoding" :bp.core.encoding)
(register-system-packages "bp/core/merkletree" :bp.core.merkletree)
(register-system-packages "bp/core/parameters" :bp.core.parameters)
(register-system-packages "bp/core/script" :bp.core.script)
(register-system-packages "bp/core/transaction" :bp.core.transaction)

(register-system-packages "bp/crypto/all" :bp.crypto)
(register-system-packages "bp/crypto/hash" :bp.crypto.hash)
(register-system-packages "bp/crypto/random" :bp.crypto.random)
(register-system-packages "bp/crypto/secp256k1" :bp.crypto.secp256k1)

(register-system-packages "bp/net/all" :bp.net)
(register-system-packages "bp/net/address" :bp.net.address)
(register-system-packages "bp/net/message" :bp.net.message)
(register-system-packages "bp/net/node" :bp.net.node)
(register-system-packages "bp/net/parameters" :bp.net.parameters)



(defsystem "bp/tests"
    :description "Test system for BP"
  :class :package-inferred-system
  :pathname "tests/"
  :perform (test-op (o c) (uiop:symbol-call :fiveam :run-all-tests))
  ;; Components:
  :depends-on ("bp"
               "bp/tests/all")
  ;; External dependencies:
  :depends-on ("fiveam"))

(register-system-packages "bp/tests/all" :bp.tests)
(register-system-packages "bp/tests/block" :bp.tests.block)
(register-system-packages "bp/tests/crypto" :bp.tests.crypto)
(register-system-packages "bp/tests/data" :bp.tests.data)
(register-system-packages "bp/tests/encoding" :bp.tests.encoding)
(register-system-packages "bp/tests/script" :bp.tests.script)
(register-system-packages "bp/tests/transaction" :bp.tests.transaction)
