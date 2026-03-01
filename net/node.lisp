;;; Copyright (c) BP Developers & Contributors
;;; See the accompanying file LICENSE for the full license governing this code.

(uiop:define-package :bp.net.node (:nicknames :bp/net/node)
  (:use :cl)
  (:use :bp.core
        :bp.crypto
        :bp.net.parameters
        :bp.net.address
        :bp.net.message)
  (:import-from :usocket)
  (:export
   ;; Node API:
   #:node
   #:node-network
   #:connect-peer
   #:disconnect-peer
   #:send-message
   #:receive-message
   #:handle-message
   #:seek-message
   ;; Simple node API:
   #:simple-node
   #:node-host
   #:node-port))

(in-package :bp.net.node)


;;;-----------------------------------------------------------------------------
;;; API

(defclass node ()
  ((network
    :accessor node-network
    :initarg :network
    :initform :mainnet)))

(defgeneric connect-peer (node &key host port))
(defgeneric disconnect-peer (node peer))
(defgeneric send-message (node peer message))
(defgeneric receive-message (node peer))
(defgeneric handle-message (node peer message))
(defgeneric seek-message (node peer message-type))


;;;-----------------------------------------------------------------------------
;;; Peer utilities

(defstruct peer
  host
  port
  connection
  version
  services
  timestamp
  user-agent
  height)

(defun write-message (network message stream)
  (let* ((magic (ecase network
                  (:mainnet +network-magic+)
                  (:testnet +testnet-network-magic+)
                  (:regtest +regtest-network-magic+)))
         (payload-bytes
          (with-output-to-byte-array (stream) (serialize message stream)))
         (checksum
          (byte-array-to-integer (subseq (hash256 payload-bytes) 0 4) :big-endian nil))
         (packet
          (make-packet
           :magic magic
           :command (command-from-message-type (type-of message))
           :length (length payload-bytes)
           :checksum checksum
           :payload payload-bytes)))
    (serialize packet stream)))

(defun read-message (network stream)
  (let* ((packet (parse 'packet stream))
         (magic (packet-magic packet))
         (expected-magic
          (ecase network
            (:mainnet +network-magic+)
            (:testnet +testnet-network-magic+)
            (:regtest +regtest-network-magic+)))
         (payload (packet-payload packet))
         (checksum
          (with-input-from-byte-array (stream (sha256 payload))
            (read-int stream :size 4 :byte-order :little)))
         (expected-checksum (packet-checksum packet)))
    (assert (= (packet-magic packet) expected-magic)
            (magic expected-magic)
            "Unexpected packet magic: ~x (expected ~x)."
            magic expected-magic)
    (assert (= (packet-checksum packet) expected-checksum)
            (checksum expected-checksum)
            "Packet checksum mismatch: ~x (expected ~x)."
            checksum expected-checksum)
    (with-input-from-byte-array (stream payload)
      (parse (message-type-from-command (packet-command packet)) stream))))

(defun perform-handshake (node peer)
  ;; Construct our `VERSION` message.
  (let ((version-message (make-version-message
                          :receiver-address (make-network-address
                                             :timestamp (get-universal-time)
                                             :services 0
                                             :address (peer-host peer)
                                             :port (peer-port peer))
                          :sender-address (make-network-address
                                           :timestamp (get-universal-time)
                                           :services 0
                                           :address (node-host node)
                                           :port (node-port node))
                          :version *protocol-version*
                          :services 0
                          :timestamp (get-universal-time)
                          :nonce (random most-positive-fixnum)
                          :user-agent *user-agent*
                          :height 0
                          :relayp nil)))
    ;; Send our `VERSION` message.
    (send-message node peer version-message)
    ;; Receive peer's `VERSION` message.
    (let ((peer-version-message (receive-message node peer)))
      ;; Exchange `VERACK` messages.
      (send-message node peer (make-verack-message))
      (assert (typep (receive-message node peer) 'verack-message))
      ;; Populate `peer` structure.
      (setf (peer-version peer) (version-message-version peer-version-message))
      (setf (peer-services peer) (version-message-services peer-version-message))
      (setf (peer-timestamp peer) (version-message-timestamp peer-version-message))
      (setf (peer-user-agent peer) (version-message-user-agent peer-version-message))
      (setf (peer-height peer) (version-message-height peer-version-message)))))



;;;-----------------------------------------------------------------------------
;;; Simple p2p node

(defclass simple-node (node)
  ((host
    :accessor node-host
    :initarg :host
    :initform nil)
   (port
    :accessor node-port
    :initarg :port
    :initform +bp-network-port+)
   (peer
    :accessor node-peer
    :initform nil))
  (:documentation "Simple Bitcoin network node communicating with a
single peer via peer-2-peer gossip protocol."))

(defmethod initialize-instance :after ((node simple-node) &key peer)
  (let ((network (node-network node)))
    ;; Initialize local port.
    (setf (node-port node)
          (ecase network
            (:mainnet +bp-network-port+)
            (:testnet +bp-testnet-network-port+)
            (:regtest +bp-regtest-network-port+)))
    ;; Connect to a discovered peer or to a provided address.
    (multiple-value-bind (peer-host peer-port)
        (cond ((eq peer :discover)
               (unless (eq network :mainnet)
                 (error "Peer discovery currently only supported for mainnet."))
               (values (random-peer-address) nil))
              ((stringp peer)
               (split-host/port-string peer))
              (t
               (values nil nil)))
      (when peer-host
        (connect-peer node :host peer-host :port peer-port)))))

;;; Network interface implementation

(defmethod connect-peer ((node simple-node) &key host port)
  ;; Open a connection to the peer and construct a new `peer` structure.
  (let* ((host (or host "127.0.0.1"))
         (port (or port (ecase (node-network node)
                          (:mainnet +network-port+)
                          (:testnet +testnet-network-port+)
                          (:regtest +regtest-network-port+))))
         (original-node-host (node-host node))
         (original-node-port (node-port node))
         (connection (usocket:socket-connect
                      host port
                      :element-type '(unsigned-byte 8)
                      :local-host original-node-host
                      :local-port original-node-port))
         (peer (make-peer :host host :port port :connection connection)))
    ;; Update node's `host` and `port` slots before handshake to be able
    ;; to construct correct `network-address` structs.
    (setf (node-host node) (usocket:get-local-address connection))
    (setf (node-port node) (usocket:get-local-port connection))
    ;; Perform a handshake, but make sure the connection is closed if
    ;; handshake fails.
    (handler-case
        (perform-handshake node peer)
      (error (e)
        (usocket:socket-close (peer-connection peer))
        (error e)))
    ;; Only update node's `host` and `peer` slots if successfully
    ;; connected and shook hands.
    (setf (node-host node) original-node-host)
    (setf (node-port node) original-node-port)
    (setf (node-peer node) peer)))

(defmethod disconnect-peer ((node simple-node) (peer (eql :all)))
  (usocket:socket-close (peer-connection (node-peer node)))
  (setf (node-peer node) nil))

(defmethod disconnect-peer ((node simple-node) (peer peer))
  (unless (eq (node-peer node) peer)
    (error "Unable to disconnect a foreign peer."))
  (disconnect-peer node :all))

(defmethod send-message ((node simple-node) (peer peer) message)
  (let ((stream (usocket:socket-stream (peer-connection peer))))
    (write-message (node-network node) message stream)
    (force-output stream)))

(defmethod receive-message ((node simple-node) (peer peer))
  (let ((stream (usocket:socket-stream (peer-connection peer))))
    (read-message (node-network node) stream)))

(defmethod seek-message ((node simple-node) peer message-type)
  (loop
     :for message := (receive-message node peer)
     :while (not (typep message message-type))
     :do (handle-message node peer message)
     :finally (return message)))

(defmethod handle-message ((node simple-node) (peer peer) message)
  (declare (ignore message)))

(defmethod handle-message ((node simple-node) (peer peer) (message ping-message))
  (send-message node peer (make-pong-message :nonce (ping-message-nonce message))))

;;; Chain supplier interface implementation

(defmethod chain-get-block-hash ((node simple-node) height &key encoded errorp)
  (declare (ignore height encoded errorp))
  (error "SIMPLE-NODE chain supplier does not support retrieving block hashes by height."))

(defmethod chain-get-block ((node simple-node) hash &key encoded errorp)
  (with-chain-supplier-normalization (hash encoded errorp
                                      :entity-type :block
                                      :id-type     :decoded
                                      :body-type   :decoded)
    (let* ((block-iv (make-inventory-vector :type +iv-msg-block+ :hash hash))
           (inventory
            (make-array 1 :element-type 'inventory-vector :initial-contents (list block-iv)))
           (request (make-getdata-message :inventory inventory))
           (response
            (progn
              (send-message node (node-peer node) request)
              (seek-message node (node-peer node) '(or block-message notfound-message)))))
      (when (typep response 'block-message)
        (block-message-block response)))))

(define-condition transaction-not-available-error (unknown-transaction-error)
  ()
  (:report
   (lambda (e s)
     (format s "Transaction ~a is not in mempool or relay set." (unknown-transaction-id e))))
  (:documentation "`notfound` response to `+iv-msg-tx+` `getdata` message
means that the transaction that was requested is either unknown or is
not present in mempool or relay-set, so this error is more precise
than `unknown-transaction-error`."))

(defmethod chain-get-transaction ((node simple-node) id &key encoded errorp)
  (with-chain-supplier-normalization (id encoded errorp
                                      :entity-type :transaction
                                      :id-type     :decoded
                                      :body-type   :decoded
                                      :error-type  transaction-not-available-error)
    (let* ((tx-iv (make-inventory-vector :type +iv-msg-tx+ :hash id))
           (inventory
            (make-array 1 :element-type 'inventory-vector :initial-contents (list tx-iv)))
           (request (make-getdata-message :inventory inventory))
           (response
            (progn
              (send-message node (node-peer node) request)
              (seek-message node (node-peer node) '(or tx-message notfound-message)))))
      (when (typep response 'tx-message)
        (tx-message-tx response)))))
