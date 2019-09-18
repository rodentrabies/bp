(defsystem :bp
  :description "Bitcoin Protocol components in Common Lisp"
  :version "0.0.1"
  :author "whythat <whythat@protonmail.com>"
  :license "MIT"

  :class :package-inferred-system
  :pathname #P"./"

  :depends-on (:cffi :aserve :jsown :ironclad :bp/core/all :bp/crypto/all))
