(uiop:define-package :bp/core/transaction (:use :cl)
  (:use
   :bp/core/encoding
   :bp/core/script
   :bp/crypto/hash)
  (:export
   ;; Transaction API:
   #:tx
   #:tx-version
   #:tx-inputs
   #:tx-input
   #:tx-outputs
   #:tx-output
   #:tx-locktime
   #:tx-hash
   #:tx-id
   ;; Transaction input API:
   #:txin
   #:txin-previous-tx-id
   #:txin-previous-tx-index
   #:txin-script-sig
   #:txin-sequence
   ;; Transaction output API:
   #:txout
   #:txout-amount
   #:txout-script-pubkey))

(in-package :bp/core/transaction)

(defstruct tx
  version
  inputs
  outputs
  locktime)

(defmethod serialize ((tx tx) stream)
  (let* ((version (tx-version tx))
         (inputs (tx-inputs tx))
         (num-inputs (length inputs))
         (outputs (tx-outputs tx))
         (num-outputs (length outputs))
         (locktime (tx-locktime tx)))
    (write-int version stream :size 4 :byte-order :little)
    (write-varint num-inputs stream)
    (loop
       :for i :below num-inputs
       :do (serialize (aref inputs i) stream))
    (write-varint num-outputs stream)
    (loop
       :for i :below num-outputs
       :do (serialize (aref outputs i) stream))
    (write-int locktime stream :size 4 :byte-order :little)))

(defmethod deserialize ((entity-type (eql 'tx)) stream)
  (let* ((version (read-int stream :size 4 :byte-order :little))
         (num-inputs (read-varint stream))
         (inputs
          (loop
             :with input-array := (make-array num-inputs :element-type 'txin)
             :for i :below num-inputs
             :do (setf (aref input-array i) (deserialize 'txin stream))
             :finally (return input-array)))
         (num-outputs (read-varint stream))
         (outputs
          (loop
             :with output-array := (make-array num-outputs :element-type 'txout)
             :for i :below num-outputs
             :do (setf (aref output-array i) (deserialize 'txout stream))
             :finally (return output-array)))
         (locktime (read-int stream :size 4 :byte-order :little)))
    (make-tx
     :version version
     :inputs inputs
     :outputs outputs
     :locktime locktime)))

(defun tx-hash (tx)
  "Raw transaction ID is a double SHA256 of its binary serialization."
  (hash256
   (ironclad:with-octet-output-stream (stream)
     (serialize tx stream))))

(defun tx-id (tx)
  "Return hex-encoded little-endian representation of raw transaction ID."
  (to-hex (reverse (tx-hash tx))))

(defun tx-output (tx index)
  (aref (tx-outputs tx) index))

(defun tx-input (tx index)
  (aref (tx-inputs tx) index))

(defmethod print-object ((tx tx) stream)
  (print-unreadable-object (tx stream :type t)
    (format stream "~a" (tx-id tx))))

(defstruct txin
  previous-tx-id
  previous-tx-index
  script-sig
  sequence)

(defmethod serialize ((txin txin) stream)
  (let ((previous-tx-id (txin-previous-tx-id txin))
        (previous-tx-index (txin-previous-tx-index txin))
        (script-sig (txin-script-sig txin))
        (sequence (txin-sequence txin)))
    (write-sequence previous-tx-id stream)
    (write-int previous-tx-index stream :size 4 :byte-order :little)
    (serialize script-sig stream)
    (write-int sequence stream :size 4 :byte-order :little)))

(defmethod deserialize ((entity-type (eql 'txin)) stream)
  (let ((previous-tx-id (read-bytes stream 32))
        (previous-tx-index (read-int stream :size 4 :byte-order :little))
        (script-sig (deserialize 'script stream))
        (sequence (read-int stream :size 4 :byte-order :little)))
    (make-txin
     :previous-tx-id previous-tx-id
     :previous-tx-index previous-tx-index
     :script-sig script-sig
     :sequence sequence)))

(defmethod print-object ((txin txin) stream)
  (print-unreadable-object (txin stream :type t)
    (format
     stream "~a:~a"
     (to-hex (reverse (txin-previous-tx-id txin)))
     (txin-previous-tx-index txin))))

(defstruct txout
  amount
  script-pubkey)

(defmethod serialize ((txout txout) stream)
  (let ((amount (txout-amount txout))
        (script-pubkey (txout-script-pubkey txout)))
    (write-int amount stream :size 8 :byte-order :little)
    (serialize script-pubkey stream)))

(defmethod deserialize ((entity-type (eql 'txout)) stream)
  (let ((amount (read-int stream :size 8 :byte-order :little))
        (script-pubkey (deserialize 'script stream)))
    (make-txout
     :amount amount
     :script-pubkey script-pubkey)))

(defmethod print-object ((txout txout) stream)
  (print-unreadable-object (txout stream :type t)
    (format stream "amount: ~a" (txout-amount txout))))

#+test
(defvar *test-transaction*
  "0100000002f8615378c58a7d7dc1712753d7f45b865fc7326b646183086794127919deee40010000006b48304502210093ab819638f72130d3490f54d50bde8e43fabaa5d58ed6d52a57654f64fc1c25022032ed6e8979d00f723c457fae90fe03fb4d06ee6976472118ab21914c6d9fd3f0012102a7f272f55f142e7dcfdb5baa7e25a26ff6046f1e6c5e107416cc76ac8fb44614ffffffffec41ac4571774182a96b4b2df0a259a37f9a8d61bc5b591646e6ebcc850c18c3010000006b483045022100ab1068c922894dfc9347bf38a6c295da43d4b8428d6fdeb23fdbcabe7a5368110220375fbc1ecac27dbf7b3b3601c903a572f38ed1f81af58294625be74988090d0d012102a7f272f55f142e7dcfdb5baa7e25a26ff6046f1e6c5e107416cc76ac8fb44614ffffffff01ec270500000000001976a9141a963939a331975bfd5952e55528662c11e097a988ac00000000")

#+test
(equal (encode (decode 'tx *test-transaction*)) *test-transaction*)
