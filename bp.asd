(defsystem "bp"
  :description "Bitcoin Protocol components in Common Lisp"
  :version "0.0.2"
  :author "Seibart Nedor <rodentrabies@protonmail.com>"
  :license "MIT"
  :class :package-inferred-system
  :pathname #P"./"
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



(defsystem "bp/tests"
  :description "Test system for BP."
  :class :package-inferred-system
  :pathname #P "./tests"
  :perform (test-op (o c) (uiop:symbol-call :fiveam :run-all-tests))
  ;; Components:
  :depends-on ("bp"
               "bp/tests/all")
  ;; External dependencies:
  :depends-on ("fiveam"))
