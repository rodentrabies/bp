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
   ;; Chain supplier conditions:
   #:unknown-entity-error
   #:unknown-block-hash-error
   #:unknown-block-error
   #:unknown-transaction-error
   ;; Available chain suppliers/mixins:
   #:chain-supplier
   #:chain-supplier-encoded-mixin
   #:node-connection))

(in-package :bp/core/chain)


;;;-----------------------------------------------------------------------------
;;; Generic declarations

(defclass chain-supplier ()
  ((network
    :accessor chain-supplier-network
    :initarg :network
    :initform :mainnet
    :documentation "Network marker (one of :MAINNET, :TESTNET, :REGTEST).")))

(define-condition unknown-entity-error (simple-error)
  ())

(define-condition unknown-block-hash-error (unknown-entity-error)
  ((height
    :initarg :height
    :accessor unknown-block-height))
  (:report
   (lambda (e s)
     (format s "Unknown block at height ~a." (unknown-block-height e)))))

(define-condition unknown-block-error (unknown-entity-error)
  ((hash
    :initarg :hash
    :accessor unknown-block-hash))
  (:report
   (lambda (e s)
     (format s "Unknown block ~a." (unknown-block-hash e)))))

(define-condition unknown-transaction-error (unknown-entity-error)
  ((id
    :initarg :id
    :accessor unknown-transaction-id))
  (:report
   (lambda (e s)
     (format s "Unknown transaction ~a." (unknown-transaction-id e)))))

(defgeneric chain-get-block-hash (supplier height &key errorp)
  (:documentation "Get the hash of the block from SUPPLIER by its
HEIGHT in the chain. HEIGHT must be an integer. If there is no known
block at the given HEIGHT, return NIL or signal an
UNKNOWN-BLOCK-HASH-ERROR error, depending on the ERRORP value."))

(defgeneric chain-get-block (supplier hash &key encoded errorp)
  (:documentation "Get raw block data from SUPPLIER by its HASH. HASH
can be either a hex-encoded string or a byte array. If ENCODED is
non-NIL, returns a hex-encoded string, otherwise returns CBLOCK
object. If there is no block with the given HASH, return NIL or signal
an UNKNOWN-BLOCK-ERROR error, depending on the ERRORP value."))

(defgeneric chain-get-transaction (supplier id &key encoded errorp)
  (:documentation "Get raw transaction data from SUPPLIER by its
ID. ID can be either a hex-encoded string or a byte array. If ENCODED
is non-NIL, returns a hex-encoded string, otherwise returns TX
object. If there is no transaction with a given ID, return NIL or
signal an UNKNOWN-TRANSACTION-ERROR error, depending on the ERRORP
value."))


;;;-----------------------------------------------------------------------------
;;; Hex-encoded chain supplier mixin

(defclass chain-supplier-encoded-mixin ()
  ()
  (:documentation "A mixin that provides a common normalization,
encoding and decoding logic for chain suppliers that are handling
hex-encoded input/output."))

(defmethod chain-get-block-hash :around ((supplier chain-supplier-encoded-mixin)
                                         height &key errorp)
  (or (call-next-method supplier height)
      (and errorp (error 'unknown-block-hash-error :height height))))

(defmethod chain-get-block :around ((supplier chain-supplier-encoded-mixin)
                                    hash &key encoded errorp)
  (let* ((hash (if (stringp hash) hash (to-hex (reverse hash))))
         (hex-block (call-next-method supplier hash :encoded t)))
    (cond ((and hex-block encoded)
           hex-block)
          (hex-block
           (decode 'cblock hex-block))
          (errorp
           (error 'unknown-block-error :hash hash)))))

(defmethod chain-get-transaction :around ((supplier chain-supplier-encoded-mixin)
                                          id &key encoded errorp)
  (let* ((id (if (stringp id) id (to-hex (reverse id))))
         (hex-tx (call-next-method supplier id :encoded t)))
    (cond ((and hex-tx encoded)
           hex-tx)
          (hex-tx
           (decode 'tx hex-tx))
          (errorp
           (error 'unknown-transaction-error :id id)))))


;;;-----------------------------------------------------------------------------
;;; Node-connection chain supplier implementation

(defclass node-connection (chain-supplier chain-supplier-encoded-mixin)
  ((url
    :accessor node-connection-url
    :initarg :url)
   (username
    :accessor node-connection-username
    :initarg :username)
   (password
    :accessor node-connection-password
    :initarg :password)))

(define-condition node-connection-error (simple-error)
  ((code
    :initarg :code
    :reader node-connection-error-code)
   (message
    :initarg :message
    :reader node-connection-error-message))
  (:report
   (lambda (e s)
     (let ((code (node-connection-error-code e))
           (message (node-connection-error-message e)))
       (format s "Node connection error: HTTP status ~a~@[ (~a)~]"
               code
               (when (plusp (length message)) message))))))

(define-condition rpc-error (node-connection-error)
  ()
  (:report
   (lambda (e s)
     (let ((code (node-connection-error-code e))
           (message (node-connection-error-message e)))
       (format s "Node connection error: RPC code ~a (~a)"
               code message)))))

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
      (cond ((= status 200)
             (jsown:val (jsown:parse response) "result"))
            ((= status 500)
             (let* ((errorinfo (jsown:val (jsown:parse response) "error"))
                    (code (jsown:val errorinfo "code"))
                    (message (jsown:val errorinfo "message")))
               (error 'rpc-error :code code :message message)))
            (t
             (error 'node-connection-error :code status :message response))))))

(defmacro ignore-rpc-errors (&body body)
  `(handler-case
       (progn ,@body)
     (rpc-error (e)
       (values nil e))))

(defmethod chain-get-block-hash ((supplier node-connection) height &key errorp)
  (declare (ignore errorp)) ;; handled by CHAIN-SUPPLIER-ENCODED-MIXIN
  (ignore-rpc-errors
    (do-simple-rpc-call supplier "getblockhash" height)))

(defmethod chain-get-block ((supplier node-connection) hash &key encoded errorp)
  (declare (ignore encoded errorp)) ;; handled by CHAIN-SUPPLIER-ENCODED-MIXIN
  (ignore-rpc-errors
    ;; Second argument (0) tells Bitcoin RPC handler to return raw
    ;; hex-encoded block.
    (do-simple-rpc-call supplier "getblock" hash 0)))

(defmethod chain-get-transaction ((supplier node-connection) id &key encoded errorp)
  (declare (ignore encoded errorp)) ;; handled by CHAIN-SUPPLIER-ENCODED-MIXIN
  (ignore-rpc-errors
    (do-simple-rpc-call supplier "getrawtransaction" id)))


;;;-----------------------------------------------------------------------------
;;; Context-dependent API

(defvar *chain-supplier* nil
  "Global chain supplier bound by the WITH-CHAIN-SUPPLIER context manager.")

(defmacro with-chain-supplier ((type &rest args &key &allow-other-keys) &body body)
  `(let ((*chain-supplier* (make-instance ',type ,@args)))
     ,@body))

(defun get-block-hash (height &key errorp)
  (chain-get-block-hash *chain-supplier* height :errorp errorp))

(defun get-block (hash &key encoded errorp)
  (chain-get-block *chain-supplier* hash :encoded encoded :errorp errorp))

(defun get-transaction (id &key encoded errorp)
  (chain-get-transaction *chain-supplier* id :encoded encoded :errorp errorp))
