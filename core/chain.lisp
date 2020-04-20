(uiop:define-package :bp/core/chain (:use :cl)
  (:import-from :aserve)
  (:import-from :jsown)
  (:use :bp/core/block
        :bp/core/transaction
        :bp/core/encoding)
  (:export
   ;; Chain supplier API:
   #:with-chain-supplier
   #:chain-testnet-p
   #:chain-get-block-hash
   #:chain-get-block
   #:chain-get-transaction
   #:testnet-p
   #:get-block-hash
   #:get-block
   #:get-transaction
   ;; Chain supplier conditions:
   #:unknown-entity-error
   #:unknown-block-hash-error
   #:unknown-block-height
   #:unknown-block-error
   #:unknown-block-hash
   #:unknown-transaction-error
   #:unknown-transaction-id
   ;; Available chain suppliers/helpers:
   #:chain-supplier
   #:node-connection
   #:with-chain-supplier-normalization))

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

(defgeneric chain-testnet-p (supplier)
  (:documentation "Return NIL if SUPPLIER's network is :MAINNET and T
otherwise.")
  (:method (supplier)
    (not (eq (chain-supplier-network supplier) :mainnet))))

(defgeneric chain-get-block-hash (supplier height &key encoded errorp)
  (:documentation "Get the hash of the block from SUPPLIER by its
HEIGHT in the chain. HEIGHT must be an integer. If ENCODED is non-NIL,
returns a hex-encoded string, otherwise returns a raw id represented
as byte array. If there is no known block at the given HEIGHT, return
NIL or signal an UNKNOWN-BLOCK-HASH-ERROR error, depending on the
ERRORP value."))

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
;;; Helper macros

(defmacro with-chain-supplier-normalization ((id-var encoded-var errorp-var
                                                     &key entity-type id-type
                                                     body-type error-type)
                                             &body body)
  "Helper macro for generating the normalization if the entity
identifier (block height, block hash and transaction id) and
post-processing (encoding, decoding and error signalling) for the
chain supplier API implementations.  

ID-VAR is an entity identifier variable, which will be normalized to a
hex-string, byte array or left unchanged if the value of ID-TYPE is
:ENCODED, :DECODED or :AS-IS respectively.

ENCODED-VAR corresponds to ENCODED chain supplier parameter - it will
be used in combination with BODY-TYPE argument to determine if the
result of the BODY should be encoded, decoded (as an ENTITY-TYPE
entity in the latter case) or left as-is.

ERROPR-VAR corresponds to the ERRORP chain supplier parameter - it
will be used to either return NIL or signal a corresponding error if
the body returns NIL. If ERROR-TYPE is non-NIL, it will be used
instead of the default error type."
  (let* ((result (gensym "chain-supplier-result"))
         (id-form
          (ecase id-type
            (:encoded `(if (stringp ,id-var)
                           ,id-var
                           (to-hex (reverse ,id-var))))
            (:decoded `(if (stringp ,id-var)
                           (reverse (from-hex ,id-var))
                           ,id-var))
            (:as-is   `,id-var)))
         (encode-form
          (ecase entity-type
            (:block-hash           `(to-hex (reverse ,result)))
            ((:block :transaction) `(encode ,result))))
         (decode-form
          (ecase entity-type
            (:block-hash  `(reverse (from-hex ,result)))
            (:block       `(decode 'cblock ,result))
            (:transaction `(decode 'tx ,result))))
         (error-form
          (ecase entity-type
            (:block-hash  `(error ',(or error-type 'unknown-block-hash-error)
                                  :height ,id-var))
            (:block       `(error ',(or error-type 'unknown-block-error)
                                  :hash ,id-var))
            (:transaction `(error ',(or error-type 'unknown-transaction-error)
                                  :id ,id-var)))))
    `(let* ((,id-var ,id-form)
            (,result (progn ,@body)))
       (or ,(ecase body-type
              (:encoded
               `(cond ((and ,result ,encoded-var) ,result)
                      (,result                    ,decode-form)))
              (:decoded
               `(cond ((and ,result ,encoded-var) ,encode-form)
                      (,result                    ,result)))
              (:as-is
               result))
           (and ,errorp-var ,error-form)))))


;;;-----------------------------------------------------------------------------
;;; Node-connection chain supplier implementation

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

(defmethod chain-get-block-hash ((supplier node-connection) height &key (encoded t) errorp)
  (with-chain-supplier-normalization (height encoded errorp
                                      :entity-type :block-hash
                                      :id-type     :as-is
                                      :body-type   :encoded)
    (ignore-rpc-errors
      (do-simple-rpc-call supplier "getblockhash" height))))

(defmethod chain-get-block ((supplier node-connection) hash &key encoded errorp)
  (with-chain-supplier-normalization (hash encoded errorp
                                      :entity-type :block
                                      :id-type     :encoded
                                      :body-type   :encoded)
    (ignore-rpc-errors
      ;; Second argument (0) tells Bitcoin RPC handler to return raw
      ;; hex-encoded block.
      (do-simple-rpc-call supplier "getblock" hash 0))))

(defmethod chain-get-transaction ((supplier node-connection) id &key encoded errorp)
  (with-chain-supplier-normalization (id encoded errorp
                                      :entity-type :transaction
                                      :id-type     :encoded
                                      :body-type   :encoded)
    (ignore-rpc-errors
      (do-simple-rpc-call supplier "getrawtransaction" id))))


;;;-----------------------------------------------------------------------------
;;; Context-dependent API

(defvar *chain-supplier* nil
  "Global chain supplier bound by the WITH-CHAIN-SUPPLIER context manager.")

(defmacro with-chain-supplier ((type &rest args &key &allow-other-keys) &body body)
  `(let ((*chain-supplier* (make-instance ',type ,@args)))
     ,@body))

(defun testnet-p ()
  (chain-testnet-p *chain-supplier*))

(defun get-block-hash (height &key errorp)
  (chain-get-block-hash *chain-supplier* height :errorp errorp))

(defun get-block (hash &key encoded errorp)
  (chain-get-block *chain-supplier* hash :encoded encoded :errorp errorp))

(defun get-transaction (id &key encoded errorp)
  (chain-get-transaction *chain-supplier* id :encoded encoded :errorp errorp))
