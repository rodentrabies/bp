(uiop:define-package :bp/tests/all
  (:nicknames :bp.tests)
  (:use :cl)
  (:use
   :bp/tests/encoding
   :bp/tests/block
   :bp/tests/transaction
   :bp/tests/script))
