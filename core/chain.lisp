(uiop:define-package :bp/core/chain (:use :cl)
  ;; (:import-from :net.aserve.client)
  (:import-from :jsown)
  (:use :bp/core/block
        :bp/core/transaction
        :bp/core/encoding)
  (:export
   #:with-chain-supplier
   #:chain-get-block-hash
   #:chain-get-block
   #:chain-get-transaction
   #:get-block-hash
   #:get-block
   #:get-transaction))

(require :aserve)

(in-package :bp/core/chain)

(defclass chain-supplier ()
  ((network
    :accessor chain-supplier-network
    :initarg :network
    :initform :mainnet
    :documentation "Network marker (one of :MAINNET, :TESTNET, :REGTEST).")))

(defgeneric chain-get-block-hash (supplier height)
  (:documentation "Get the hash of the block from SUPPLIER by its
  HEIGHT in the chain."))

(defgeneric chain-get-block (supplier hash)
  (:documentation "Get raw block data from SUPPLIER by its HASH."))

(defgeneric chain-get-transaction (supplier id)
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

(defun do-simple-rpc-call (supplier method &rest arguments)
  (let* ((user (node-connection-username supplier))
         (password (node-connection-password supplier))
         (authorization (cons user password))
         (content
          (format nil
                  "{                            ~
                     \"jsonrpc\": \"1.0\",      ~
                     \"method\":  \"~a\",       ~
                     \"params\":  [~{~s~^, ~}], ~
                     \"id\":      \"bp\"        ~
                   }"
                  method
                  arguments)))
    (multiple-value-bind (response status)
        (net.aserve.client:do-http-request (node-connection-url supplier)
          :basic-authorization authorization
          :method :post
          :content content
          :content-type "text/plain")
      (if (= status 200)
          (jsown:val (jsown:parse response) "result")
          (error "RPC call status ~a: ~a" status response)))))

(defmethod chain-get-block-hash ((supplier node-connection) height)
  (do-simple-rpc-call supplier "getblockhash" height))

(defmethod chain-get-block ((supplier node-connection) hash)
  ;; Second argument (0) tells Bitcoin RPC handler to return raw
  ;; hex-encoded block.
  (let ((hash (if (stringp hash) hash (to-hex (reverse hash)))))
    (decode 'block-header (do-simple-rpc-call supplier "getblock" hash 0))))

(defmethod chain-get-transaction ((supplier node-connection) id)
  (let ((id (if (stringp id) id (to-hex (reverse id)))))
   (decode 'tx (do-simple-rpc-call supplier "getrawtransaction" id))))



(defvar *chain-supplier* nil
  "Global chain supplier bound by the WITH-CHAIN-SUPPLIER context manager.")

(defmacro with-chain-supplier ((&key network
                                     url
                                     username
                                     password)
                               &body body)
  `(let ((*chain-supplier* (make-instance 'node-connection
                                          :network ,network
                                          :url ,url
                                          :username ,username
                                          :password ,password)))
     ,@body))

(defun get-block-hash (height)
  (chain-get-block-hash *chain-supplier* height))

(defun get-block (hash)
  (chain-get-block *chain-supplier* hash))

(defun get-transaction (id)
  (chain-get-transaction *chain-supplier* id))
