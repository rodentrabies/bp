(uiop:define-package :bp/tests/all (:use :cl)
  (:use
   :bp/tests/encoding
   :bp/tests/crypto
   :bp/tests/block
   :bp/tests/transaction
   :bp/tests/script))
