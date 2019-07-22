(uiop:define-package :bp/core/block
    (:use :cl)
  (:export
   #:cblock))

(in-package :bp/core/block)

(defstruct cblock-header)

(defstruct (cblock (:include cblock-header)))
