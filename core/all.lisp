(uiop:define-package :bp/core/all (:nicknames :bp)
  (:use :cl)
  (:use-reexport
   :bp/core/encoding
   :bp/core/transaction
   :bp/core/script
   :bp/core/block))

(in-package :bp/core/all)
