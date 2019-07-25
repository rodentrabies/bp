(uiop:define-package :bp/core/all (:use :cl)
  (:nicknames :bp)
  (:use-reexport
   :bp/core/encoding
   :bp/core/transaction
   :bp/core/script
   :bp/core/block))

(in-package :bp/core/all)

(defclass chain-supplier ()
  ((network
    :accessor chain-supplier-network
    :initarg :network
    :initform :mainnet
    :documentation "Network marker (one of :MAINNET, :TESTNET, :REGTEST).")))

(defgeneric get-block-hash (supplier height)
  (:documentation "Get the hash of the block from SUPPLIER by its
  HEIGHT in the chain."))

(defgeneric get-block (supplier hash)
  (:documentation "Get raw block data from SUPPLIER by its HASH."))

(defgeneric get-transaction (supplier id)
  (:documentation "Get raw transaction data from SUPPLIER by its ID."))


(defclass node-connection (chain-supplier)
  ((url
    :accessor node-connection-url
    :initarg :url)
   (username
    :accessor node-connection-username
    :initarg :username)
   (password
    :accessor node-connection-password
    :initarg :password)))

(defmethod get-block-hash ((supplier node-connection) height)
  (error "not implemented"))

(defmethod get-block ((supplier node-connection) hash)
  (error "not implemented"))

(defmethod get-transaction ((supplier node-connection) id)
  (error "not implemented"))
