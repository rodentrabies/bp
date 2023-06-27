;;; Copyright (c) 2019-2023 BP Developers & Contributors
;;; See the accompanying file LICENSE for the full license governing this code.

(uiop:define-package :bp/rpc/all (:use :cl)
  (:nicknames :bprpc)
  (:import-from :aserve)
  (:import-from :jsown)
  (:use :bp/core/all)
  (:export
   ;; Classes and conditions:
   #:node-connection ;; will be removed soon
   #:node-rpc-connection
   #:rpc-error
   ;; Node RPC methods:
   #:getblockhash
   #:getblock
   #:getrawtransaction
   #:getchaintxstats))

(in-package :bp/rpc/all)


;;;-----------------------------------------------------------------------------
;;; Conditions

(define-condition connection-error (simple-error)
  ((code
    :initarg :code
    :reader connection-error-code)
   (message
    :initarg :message
    :reader connection-error-message)
   (format-string
    :allocation :class
    :initform "Connection error: code ~a~@[ (~a)~]"))
  (:report
   (lambda (e s)
     (let* ((code (connection-error-code e))
            (message (connection-error-message e))
            (message/nil (when (plusp (length message)) message))
            (format-string (slot-value e 'format-string)))
       (format s format-string code message/nil)))))

(define-condition http-error (connection-error)
  ((format-string :initform "HTTP connection error: HTTP status ~a (~a)")))

(define-condition rpc-error (http-error)
  ((format-string :initform "RPC connection error: RPC code ~a (~a)")))


;;;-----------------------------------------------------------------------------
;;; RPC connection
(defclass rpc-connection ()
  ((url
    :accessor rpc-connection-url
    :initarg :url)
   (username
    :accessor rpc-connection-username
    :initarg :username
    :initform nil)
   (password
    :accessor rpc-connection-password
    :initarg :password
    :initform nil))
  (:documentation "RPC-CONNECTION is a simple generic client for the
RPC server."))

;;; Generic RPC utilities

(defun do-simple-rpc-call (connection method &rest arguments)
  (let* ((user (rpc-connection-username connection))
         (password (rpc-connection-password connection))
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
        (net.aserve.client:do-http-request (rpc-connection-url connection)
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
             (error 'http-error :code status :message response))))))

(defmacro ignore-rpc-errors (&body body)
  `(handler-case
       (progn ,@body)
     (rpc-error (e)
       (values nil e))))


;;;-----------------------------------------------------------------------------
;;; Node RPC connection

(defclass node-rpc-connection (chain-supplier rpc-connection) ())

;;; Key RPC method implementations

(defun getblockhash (connection height)
  (do-simple-rpc-call connection "getblockhash" height))

(defun getblock (connection hash)
  ;; Second argument (0) tells Bitcoin RPC handler to return raw
  ;; hex-encoded block.
  (do-simple-rpc-call connection "getblock" hash 0))

(defun getrawtransaction (connection id)
  (do-simple-rpc-call connection "getrawtransaction" id))

(defun getchaintxstats (connection)
  (do-simple-rpc-call connection "getchaintxstats"))

;;; CHAIN-SUPPLIER interface implementation for NODE-RPC-CONNECTION

(defmethod chain-get-block-hash ((supplier node-rpc-connection) height &key (encoded t) errorp)
  (with-chain-supplier-normalization (height encoded errorp
                                      :entity-type :block-hash
                                      :id-type     :as-is
                                      :body-type   :encoded)
    (ignore-rpc-errors (getblockhash supplier height))))

(defmethod chain-get-block ((supplier node-rpc-connection) hash &key encoded errorp)
  (with-chain-supplier-normalization (hash encoded errorp
                                      :entity-type :block
                                      :id-type     :encoded
                                      :body-type   :encoded)
    (ignore-rpc-errors (getblock supplier hash))))

(defmethod chain-get-transaction ((supplier node-rpc-connection) id &key encoded errorp)
  (with-chain-supplier-normalization (id encoded errorp
                                      :entity-type :transaction
                                      :id-type     :encoded
                                      :body-type   :encoded)
    (ignore-rpc-errors (getrawtransaction supplier id))))

;;; Redefine BP:NODE-CONNECTION here for backward compatibility.
;;; These will be removed in one of the upcoming 0.0.* releases.
(in-package :bp/core/all)

(defclass node-connection (bprpc:node-rpc-connection) ())

(defmethod initialize-instance :after ((object node-connection) &rest args)
  (declare (ignore args))
  (warn "BP:NODE-CONNECTION has been deprecated in favor of ~
         BPRPC:NODE-RPC-CONNECTION."))
