(defsystem :bp
  :description "Bitcoin Protocol components in Common Lisp"
  :version "0.0.1"
  :author "whythat <whythat@protonmail.com>"

  :class :package-inferred-system
  :pathname #P"./"

  :depends-on (:cffi :ironclad :bp/core/all :bp/crypto/all))
