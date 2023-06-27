;;; Copyright (c) 2019-2023 BP Developers & Contributors
;;; See the accompanying file LICENSE for the full license governing this code.

(uiop:define-package :bp/net/parameters (:use :cl)
  (:use :bp/core/all)
  (:export
   ;; Network constants:
   #:+network-magic+
   #:+testnet-network-magic+
   #:+regtest-network-magic+
   #:+network-port+
   #:+testnet-network-port+
   #:+regtest-network-port+
   #:+bp-network-port+
   #:+bp-testnet-network-port+
   #:+bp-regtest-network-port+
   ;; Service flags:
   #:+node-network+
   #:+node-getutxo+
   #:+node-bloom+
   #:+node-witness+
   #:+node-network-limited+
   ;; Protocol parameters:
   #:*protocol-version*
   #:*user-agent*))


(in-package :bp/net/parameters)

;;;-----------------------------------------------------------------------------
;;; Network contants

(defconstant +network-magic+         #xd9b4bef9)
(defconstant +testnet-network-magic+ #x0709110b)
(defconstant +regtest-network-magic+ #xdab5bffa)

(defconstant +network-port+          8333)
(defconstant +testnet-network-port+ 18333)
(defconstant +regtest-network-port+ 18444)

(defconstant +bp-network-port+          6270)
(defconstant +bp-testnet-network-port+ 16270)
(defconstant +bp-regtest-network-port+ 26270)


;;;-----------------------------------------------------------------------------
;;; Network services

(defconstant +node-network+ 1
  "This service flag means that given node can serve full blocks
instead of just headers.")

(defconstant +node-getutxo+ 2
  "See BIP-0064.")

(defconstant +node-bloom+ 4
  "See BIP-0111.")

(defconstant +node-witness+ 8
  "See BIP-0111.")

(defconstant +node-network-limited+ 1024
  "See BIP-0159.")


;;;-----------------------------------------------------------------------------
;;; Protocol parameters:
(defvar *protocol-version* 70015)
(defvar *user-agent* (format nil "/bp:~a/" *bp-version*))
