(uiop:define-package :bp/core/transaction
    (:use :cl :bp/core/encoding)
  (:export
   ;; Transaction API:
   #:tx
   #:tx-version
   #:tx-txins
   #:tx-txouts
   #:tx-locktime
   ;; Transaction input API:
   #:txin
   #:txin-previous-tx-id
   #:txin-previous-tx-index
   #:txin-script-sig
   #:txin-sequence
   ;; Transaction output API:
   #:txout
   #:txout-amount
   #:txout-script-pubkey))

(in-package :bp/core/transaction)

(defstruct tx
  version
  txins
  txouts
  locktime)

(defstruct txin
  previous-tx-id
  previous-tx-index
  script-sig
  sequence)

(defstruct txout
  amount
  script-pubkey)

