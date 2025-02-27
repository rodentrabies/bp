;;; Copyright (c) 2019-2023 BP Developers & Contributors
;;; See the accompanying file LICENSE for the full license governing this code.

(uiop:define-package :bp.net.message (:nicknames :bp/net/message)
  (:use :cl)
  (:use :bp.core
        :bp.net.address)
  ;; TODO: this symbol was left non-exported intentionally; remove
  ;;       when no longer relevant.
  (:import-from :bp.core.encoding
                #:ascii-string-to-byte-array)
  (:import-from :usocket)
  ;; Messages and their field accessors are automatically exported by
  ;; the DEFMESSAGE macro. Non-message structures and other utils are
  ;; exported below.
  (:export
   #:packet
   #:make-packet
   #:packet-magic
   #:packet-command
   #:packet-checksum
   #:packet-payload
   #:network-address
   #:make-network-address
   #:network-address-timestamp
   #:network-address-services
   #:network-address-address
   #:network-address-port
   #:inventory-vector
   #:make-inventory-vector
   #:inventory-vector-type
   #:inventory-vector-hash
   #:+iv-error+
   #:+iv-msg-tx+
   #:+iv-msg-block+
   #:+iv-msg-filtered-block+
   #:+iv-msg-cmpct-block+
   #:command-from-message-type
   #:message-type-from-command))


(in-package :bp.net.message)


;;;-----------------------------------------------------------------------------
;;; Structures

(defstruct packet
  magic
  command
  length
  checksum
  payload)

(defun command-to-bytes (command)
  (let ((bytes (make-byte-array 12))
        (command-bytes (ascii-string-to-byte-array command)))
    (loop :for i :below (length command-bytes) :do (setf (aref bytes i) (aref command-bytes i)))
    bytes))

(defun command-from-bytes (bytes)
  (let ((index (position 0 bytes)))
    (map 'string #'code-char (subseq bytes 0 index))))

(defmethod serialize ((message packet) stream)
  (let* ((magic (packet-magic message))
         (command-bytes (command-to-bytes (packet-command message)))
         (length (packet-length message))
         (checksum (packet-checksum message))
         (payload (packet-payload message)))
    (write-int magic stream :size 4 :byte-order :little)
    (write-bytes command-bytes stream 12)
    (write-int length stream :size 4 :byte-order :little)
    (write-int checksum stream :size 4 :byte-order :little)
    (write-bytes payload stream length)))

(defmethod parse ((packet-class (eql 'packet)) stream)
  (let* ((magic (read-int stream :size 4 :byte-order :little))
         (command (command-from-bytes (read-bytes stream 12)))
         (length (read-int stream :size 4 :byte-order :little))
         (checksum (read-int stream :size 4 :byte-order :little))
         (payload (read-bytes stream length)))
    (make-packet
     :magic magic
     :command command
     :length length
     :checksum checksum
     :payload payload)))

(defstruct network-address
  timestamp
  services
  address
  port)

(defmethod serialize ((struct network-address) stream)
  (let* ((services (network-address-services struct))
         (address (network-address-address struct))
         (address-bytes (address-to-bytes address))
         (port (network-address-port struct)))
    (write-int services stream :size 8 :byte-order :little)
    (write-bytes address-bytes stream 16)
    (write-int port stream :size 2 :byte-order :big)))

(defmethod parse ((struct-class (eql 'network-address)) stream)
  (let* ((services (read-int stream :size 8 :byte-order :little))
         (address-bytes (read-bytes stream 16))
         (address (address-from-bytes address-bytes))
         (port (read-int stream :size 2 :byte-order :big)))
    (make-network-address
     :services services
     :address address
     :port port)))

(defstruct inventory-vector
  type
  hash)

(defconstant +iv-error+ 0
  "Any data of with this number may be ignored.")

(defconstant +iv-msg-tx+ 1
  "Hash is related to a transaction.")

(defconstant +iv-msg-block+ 2
  "Hash is related to a data block.")

(defconstant +iv-msg-filtered-block+ 3
  "Hash of a block header; identical to MSG_BLOCK. Only to be used in
getdata message. Indicates the reply should be a merkleblock message
rather than a block message; this only works if a bloom filter has
been set.")

(defconstant +iv-msg-cmpct-block+ 4
  "Hash of a block header; identical to MSG_BLOCK. Only to be used in
getdata message. Indicates the reply should be a cmpctblock
message. See BIP-0152 for more info.")

(defmethod serialize ((struct inventory-vector) stream)
  (let ((type (inventory-vector-type struct))
        (hash (inventory-vector-hash struct)))
    (write-int type stream :size 4 :byte-order :little )
    (write-bytes hash stream 32)))

(defmethod parse ((struct-class (eql 'inventory-vector)) stream)
  (let ((type (read-int stream :size 4 :byte-order :little))
        (hash (read-bytes stream 32)))
    (make-inventory-vector :type type :hash hash)))


;;;-----------------------------------------------------------------------------
;;; Messages declaration utils

(defvar *message-commands* (make-hash-table)
  "Mapping from message types (symbols) to message commands (strings).")

(defun command-from-message-type (message-type)
  "Return a string command for a given message struct."
  (or (gethash message-type *message-commands*)
      (error "Unknown message type: ~a." message-type)))

(defvar *message-types* (make-hash-table :test #'equal)
  "Mapping from commands (strings) to message types (symbols).")

(defun message-type-from-command (command)
  "Return a message type symbol for a given string command."
  (or (gethash command *message-types*)
      (error "Unknown message command: ~s" command)))

(defmacro defmessage (name (&rest options) &body slots)
  (destructuring-bind (&key not-implemented) options
    (flet ((combine-symbols (&rest symbols)
             (intern (format nil "~{~a~}" (mapcar #'symbol-name symbols)))))
      (let* ((name-string (string-downcase (symbol-name name)))
             (split-index (position #\- name-string :test #'char-equal))
             (command (subseq name-string 0 split-index))
             (constructor (combine-symbols 'make- name)))
        `(progn
           (setf (gethash ',name *message-commands*) ,command)
           (setf (gethash ,command *message-types*) ',name)
           (defstruct ,name ,@slots)
           (eval-when (:compile-toplevel :load-toplevel)
             (export ',name)
             (export ',constructor)
             ,@(loop
                :for slot :in slots
                :for accessor := (combine-symbols name '- slot)
                :collect `(export ',accessor)))

           ;; Additional utils depending on OPTIONS values.
           ,@(when not-implemented
               `(;; BP:SERIALIZE method for non-implemented messages
                 ;; should just return an error.
                 (defmethod serialize ((message ,name) stream)
                   (declare (ignore stream))
                   (error "~a serialization is not implemented." ,(string-upcase command)))
                 ;; BP:PARSE method for non-implemented messages
                 ;; should not fail - such messages will usually be
                 ;; silently ignored.
                 (defmethod parse ((message-class (eql ',name)) stream)
                   (declare (ignore stream))
                   (,constructor)))))))))


;;;-----------------------------------------------------------------------------
;;; Message declarations

;;; VERSION

(defmessage version-message ()
  version
  services
  timestamp
  receiver-address
  sender-address
  nonce
  user-agent
  height
  relayp)

(defmethod serialize ((message version-message) stream)
  (let* ((version (version-message-version message))
         (services (version-message-services message))
         (timestamp (version-message-timestamp message))
         (receiver-address (version-message-receiver-address message))
         (sender-address (version-message-sender-address message))
         (nonce (version-message-nonce message))
         (user-agent (version-message-user-agent message))
         (user-agent-bytes (ascii-string-to-byte-array user-agent))
         (user-agent-length (length user-agent-bytes))
         (height (version-message-height message))
         (relayp (version-message-relayp message)))
    (write-int version stream :size 4 :byte-order :little)
    (write-int services stream :size 8 :byte-order :little)
    (write-int timestamp stream :size 8 :byte-order :little)
    (serialize receiver-address stream)
    (serialize sender-address stream)
    (write-int nonce stream :size 8 :byte-order :little)
    (write-varint user-agent-length stream)
    (write-bytes user-agent-bytes stream user-agent-length)
    (write-int height stream :size 4 :byte-order :little)
    (write-byte (if relayp 1 0) stream)))

(defmethod parse ((message-class (eql 'version-message)) stream)
  (let* ((version (read-int stream :size 4 :byte-order :little))
         (services (read-int stream :size 8 :byte-order :little))
         (timestamp (read-int stream :size 8 :byte-order :little))
         (receiver-address (parse 'network-address stream))
         (sender-address (parse 'network-address stream))
         (nonce (read-int stream :size 8 :byte-order :little))
         (user-agent-length (read-varint stream))
         (user-agent-bytes (read-bytes stream user-agent-length))
         (user-agent (map 'string #'code-char user-agent-bytes))
         (height (read-int stream :size 4 :byte-order :little))
         (relay-byte (read-byte stream)))
    (make-version-message
     :version version
     :services services
     :timestamp timestamp
     :receiver-address receiver-address
     :sender-address sender-address
     :nonce nonce
     :user-agent user-agent
     :height height
     :relayp (ecase relay-byte (0 nil) (1 t)))))


;; VERACK

(defmessage verack-message ())

(defmethod serialize ((message verack-message) stream)
  (declare (ignore stream)))

(defmethod parse ((message-class (eql 'verack-message)) stream)
  (declare (ignore stream))
  (make-verack-message))


(defmessage addr-message (:not-implemented t))


;; INV

(defmessage inv-message ()
  inventory)

(defmethod serialize ((message inv-message) stream)
  (let* ((inventory (inv-message-inventory message))
         (inventory-size (length inventory)))
    (write-varint inventory-size stream)
    (loop
       :for inventory-vector :on inventory
       :do (serialize inventory-vector stream))))

(defmethod parse ((message-class (eql 'inv-message)) stream)
  (let* ((inventory-size (read-varint stream))
         (inventory (make-array inventory-size :element-type 'inventory-vector)))
    (loop
       :for i :below inventory-size
       :do (setf (aref inventory i) (parse 'inventory-vector stream)))
    (make-inv-message :inventory inventory)))


;;; GETDATA

(defmessage getdata-message ()
  inventory)

(defmethod serialize ((message getdata-message) stream)
  (let* ((inventory (getdata-message-inventory message))
         (inventory-size (length inventory)))
    (write-varint inventory-size stream)
    (loop
       :for inventory-vector :across inventory
       :do (serialize inventory-vector stream))))

(defmethod parse ((message-class (eql 'getdata-message)) stream)
  (let* ((inventory-size (read-varint stream))
         (inventory (make-array inventory-size :element-type 'inventory-vector)))
    (loop
       :for i :below inventory-size
       :do (setf (aref inventory i) (parse 'inventory-vector stream)))
    (make-getdata-message :inventory inventory)))


;; NOTFOUND

(defmessage notfound-message ()
  inventory)

(defmethod serialize ((message notfound-message) stream)
  (let* ((inventory (notfound-message-inventory message))
         (inventory-size (length inventory)))
    (write-varint inventory-size stream)
    (loop
       :for inventory-vector :on inventory
       :do (serialize inventory-vector stream))))

(defmethod parse ((message-class (eql 'notfound-message)) stream)
  (let* ((inventory-size (read-varint stream))
         (inventory (make-array inventory-size :element-type 'inventory-vector)))
    (loop
       :for i :below inventory-size
       :do (setf (aref inventory i) (parse 'inventory-vector stream)))
    (make-notfound-message :inventory inventory)))

(defmessage getblocks-message (:not-implemented t))
(defmessage getheaders-message (:not-implemented t))


;; BLOCK

(defmessage tx-message ()
  tx)

(defmethod serialize ((message tx-message) stream)
  (serialize (tx-message-tx message) stream))

(defmethod parse ((message-class (eql 'tx-message)) stream)
  (make-tx-message :tx (parse 'tx stream)))


;; BLOCK

(defmessage block-message ()
  block)

(defmethod serialize ((message block-message) stream)
  (serialize (block-message-block message) stream))

(defmethod parse ((message-class (eql 'block-message)) stream)
  (make-block-message :block (parse 'cblock stream)))

(defmessage headers-message (:not-implemented t))
(defmessage getaddr-message (:not-implemented t))
(defmessage mempool-message (:not-implemented t))
(defmessage checkorder-message (:not-implemented t))
(defmessage submitorder-message (:not-implemented t))
(defmessage reply-message (:not-implemented t))


;; PING

(defmessage ping-message ()
  nonce)

(defmethod serialize ((message ping-message) stream)
  (write-int (ping-message-nonce message) stream :size 8 :byte-order :little))

(defmethod parse ((message-class (eql 'ping-message)) stream)
  (make-ping-message :nonce (read-int stream :size 8 :byte-order :little)))


;; PONG

(defmessage pong-message ()
  nonce)

(defmethod serialize ((message pong-message) stream)
  (write-int (pong-message-nonce message) stream :size 8 :byte-order :little))

(defmethod parse ((message-class (eql 'pong-message)) stream)
  (make-pong-message :nonce (read-int stream :size 8 :byte-order :little)))


(defmessage reject-message (:not-implemented t))
(defmessage filterload-message (:not-implemented t))
(defmessage filteradd-message (:not-implemented t))
(defmessage filterclear-message (:not-implemented t))
(defmessage merkleblock-message (:not-implemented t))
(defmessage alert-message (:not-implemented t))
(defmessage sendheaders-message (:not-implemented t))
(defmessage feefilter-message (:not-implemented t))
(defmessage sendcmpct-message (:not-implemented t))
(defmessage cmpctblock-message (:not-implemented t))
(defmessage getblocktxn-message (:not-implemented t))
(defmessage blocktxn-message (:not-implemented t))
