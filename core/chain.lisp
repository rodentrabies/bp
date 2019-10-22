(uiop:define-package :bp/core/chain (:use :cl)
  (:import-from :aserve)
  (:import-from :jsown)
  (:use :bp/core/block
        :bp/core/transaction
        :bp/core/encoding)
  (:export
   ;; Chain supplier API:
   #:with-chain-supplier
   #:chain-get-block-hash
   #:chain-get-block
   #:chain-get-transaction
   #:get-block-hash
   #:get-block
   #:get-transaction
   ;; Available chain suppliers:
   #:node-connection))

(in-package :bp/core/chain)

(defclass chain-supplier ()
  ((network
    :accessor chain-supplier-network
    :initarg :network
    :initform :mainnet
    :documentation "Network marker (one of :MAINNET, :TESTNET, :REGTEST).")))

(defgeneric chain-get-block-hash (supplier height)
  (:documentation "Get the hash of the block from SUPPLIER by its
HEIGHT in the chain. HEIGHT must be an integer."))

(defgeneric chain-get-block (supplier hash &key encoded)
  (:documentation "Get raw block data from SUPPLIER by its HASH. HASH
can be either a hex-encoded string or a byte array. If ENCODED is
non-NIL, returns a hex-encoded string, otherwise returns CBLOCK
object."))

(defgeneric chain-get-transaction (supplier id &key encoded)
  (:documentation "Get raw transaction data from SUPPLIER by its
ID. ID can be either a hex-encoded string or a byte array. If ENCODED
is non-NIL, returns a hex-encoded string, otherwise returns TX
object."))


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

(defmethod chain-get-block ((supplier node-connection) hash &key encoded)
  ;; Second argument (0) tells Bitcoin RPC handler to return raw
  ;; hex-encoded block.
  (let* ((hash (if (stringp hash) hash (to-hex (reverse hash))))
         (hex-block (do-simple-rpc-call supplier "getblock" hash 0)))
    (if encoded
        hex-block
        (decode 'cblock hex-block))))

(defmethod chain-get-transaction ((supplier node-connection) id &key encoded)
  (let* ((id (if (stringp id) id (to-hex (reverse id))))
         (hex-tx (do-simple-rpc-call supplier "getrawtransaction" id)))
    (if encoded
        hex-tx
        (decode 'tx hex-tx))))



(defvar *chain-supplier* nil
  "Global chain supplier bound by the WITH-CHAIN-SUPPLIER context manager.")

(defmacro with-chain-supplier ((type &rest args &key &allow-other-keys) &body body)
  `(let ((*chain-supplier* (make-instance ',type ,@args)))
     ,@body))

(defun get-block-hash (height)
  (chain-get-block-hash *chain-supplier* height))

(defun get-block (hash &key encoded)
  (chain-get-block *chain-supplier* hash :encoded encoded))

(defun get-transaction (id &key encoded)
  (chain-get-transaction *chain-supplier* id :encoded encoded))
