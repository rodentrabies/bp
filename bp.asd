(defsystem "bp"
  :description "Bitcoin Protocol components in Common Lisp"
  :version "0.0.1"
  :author "whythat <whythat@protonmail.com>"
  :license "MIT"
  :class :package-inferred-system
  :pathname #P"./"
  :depends-on ("cffi" "aserve" "jsown" "ironclad" "bp/core/all" "bp/crypto/all")
  :in-order-to ((test-op (test-op "bp/tests"))))

(defsystem "bp/tests"
  :description "Test system for BP."
  :class :package-inferred-system
  :pathname #P "./tests"
  :depends-on ("bp" "fiveam" "bp/tests/all")
  :perform (test-op (o c) (uiop:symbol-call :fiveam :run-all-tests)))
