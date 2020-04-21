(defsystem "bp"
  :description "Bitcoin Protocol components in Common Lisp"
  :version "0.0.2"
  :author "whythat <whythat@protonmail.com>"
  :license "MIT"
  :class :package-inferred-system
  :pathname #P"./"
  :depends-on ("bp/core/all"
               "bp/crypto/all"
               "bp/net/all")
  :in-order-to ((test-op (test-op "bp/tests")))
  ;; External dependencies.
  :depends-on ("cffi" "aserve" "jsown" "ironclad" "usocket"))



(defsystem "bp/tests"
  :description "Test system for BP."
  :class :package-inferred-system
  :pathname #P "./tests"
  :depends-on ("bp" "bp/tests/all")
  :perform (test-op (o c) (uiop:symbol-call :fiveam :run-all-tests))
  ;; External dependencies.
  :depends-on ("fiveam"))
