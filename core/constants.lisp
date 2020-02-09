(uiop:define-package :bp/core/constants (:use :cl)
  (:export
   #:+initial-block-reward+
   #:+halving-period+))

(in-package :bp/core/constants)

;;;-----------------------------------------------------------------------------
;;; Constants that define Bitcoin Protocol

(defconstant +initial-block-reward+ (* 50 (expt 10 8)) ;; 50 bitcoins
  "Initial reward included in newly mined blocks.")

(defconstant +halving-period+ 210000 ;; blocks
  "Number of blocks in between halving events - each 210000 blocks,
the block reward is reduced by half, eventually getting to 0 and
providing the limited supply property of Bitcoin.")
