(uiop:define-package :bp/core/parameters (:use :cl)
  (:export
   ;; Contants:
   #:+initial-block-reward+
   #:+halving-period+
   #:+testnet-bip-0016-switch-time+
   #:+mainnet-bip-0016-switch-time+
   ;; Variables:
   #:*bip-0016-active-p*
   #:*bip-0141-active-p*
   ;; BP-specific parameters:
   #:*bp-version*))

(in-package :bp/core/parameters)



;;;-----------------------------------------------------------------------------
;;; Constants that define Bitcoin Protocol

(defconstant +initial-block-reward+ (* 50 (expt 10 8)) ;; 50 bitcoins
  "Initial reward included in newly mined blocks.")

(defconstant +halving-period+ 210000 ;; blocks
  "Number of blocks in between halving events - each 210000 blocks,
the block reward is reduced by half, eventually getting to 0 and
providing the limited supply property of Bitcoin.")

(defconstant +testnet-bip-0016-switch-time+ 1329264000 ;; April 1, 2012
  "Block timestamp at which BIP-0016 was adopted by the testnet.")

(defconstant +mainnet-bip-0016-switch-time+ 1333238400 ;; February 15, 2012
  "Block timestamp at which BIP-0016 was adopted by the mainnet.")



;;;-----------------------------------------------------------------------------
;;; Variables that indicate whether certains upgrades (described in
;;; the corresponding BIP documents) are active or not.

(defparameter *bip-0016-active-p* t
  "Pay to Script Hash
https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki.")

(defparameter *bip-0141-active-p* t
  "Segregated Witness (Consensus layer)
https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki.")



;;;-----------------------------------------------------------------------------
;;; BP package parameters

(defvar *bp-version* "0.0.2"
  "Version of the BP package.")
