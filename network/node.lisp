(uiop:define-package :bp/network/node (:use :cl)
  (:use :bp/core/all
        :bp/crypto/all
        :bp/network/parameters
        :bp/network/message)
  (:import-from :ironclad)
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

(in-package :bp/network/node)


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
          (ironclad:with-octet-output-stream (stream) (serialize message stream)))
         (checksum
          (ironclad:octets-to-integer (subseq (hash256 payload-bytes) 0 4) :big-endian nil))
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
          (ironclad:with-octet-input-stream (stream (sha256 payload))
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
    (ironclad:with-octet-input-stream (stream payload)
      (parse (message-type-from-command (packet-command packet)) stream))))

(defun perform-handshake (node peer)
  ;; Construct our VERSION message.
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
    ;; Send our VERSION message.
    (send-message node peer version-message)
    ;; Receive peer's VERSION message.
    (let ((peer-version-message (receive-message node peer)))
      ;; Exchange VERACK messages.
      (send-message node peer (make-verack-message))
      (assert (typep (receive-message node peer) 'verack-message))
      ;; Populate PEER structure.
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
    :initform "127.0.0.1")
   (port
    :accessor node-port
    :initarg :port
    :initform +bp-network-port+)
   (peer
    :accessor node-peer
    :initarg :peer
    :initform nil))
  (:documentation "Simple Bitcoin network node communicating with a
single peer via peer-2-peer gossip protocol."))

(defmethod initialize-instance :after ((node simple-node) &key)
  (setf (node-port node)
        (ecase (node-network node)
          (:mainnet +bp-network-port+)
          (:testnet +bp-testnet-network-port+)
          (:regtest +bp-regtest-network-port+))))

;;; Network interface implementation

(defmethod connect-peer ((node simple-node)
                         &key
                           (host "127.0.0.1")
                           (port (ecase (node-network node)
                                   (:mainnet +network-port+)
                                   (:testnet +testnet-network-port+)
                                   (:regtest +regtest-network-port+))))
  ;; Open a connection to the peer and construct a new PEER structure.
  (let* ((connection (usocket:socket-connect
                      host port :element-type '(unsigned-byte 8)
                      :local-host (node-host node)
                      :local-port (node-port node)))
         (peer (make-peer :host host :port port :connection connection)))
    ;; Perform a shake hands, but make sure the connection is closed
    ;; if handshake fails.
    (handler-case
        (perform-handshake node peer)
      (error (e)
        (usocket:socket-close (peer-connection peer))
        (error e)))
    ;; Only add peer to the node if successfully connected and shook
    ;; hands.
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

(defmethod handle-message ((node simple-node) (peer peer) message))

(defmethod handle-message ((node simple-node) (peer peer) (message ping-message))
  (send-message node peer (make-pong-message :nonce (ping-message-nonce message))))
