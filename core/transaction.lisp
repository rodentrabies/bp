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
   #:tx-witnesses
   #:tx-witness
   #:tx-locktime
   #:tx-hash
   #:tx-id
   #:tx-wid
   ;; Transaction input API:
   #:txin
   #:txin-previous-tx-id
   #:txin-previous-tx-index
   #:txin-script-sig
   #:txin-sequence
   ;; Transaction output API:
   #:txout
   #:txout-amount
   #:txout-script-pubkey
   ;; Witness API:
   #:witness
   #:witness-items))

(in-package :bp/core/transaction)

(defstruct tx
  version
  inputs
  outputs
  witnesses
  locktime)

(defmethod serialize ((tx tx) stream)
  (let* ((version (tx-version tx))
         (inputs (tx-inputs tx))
         (num-inputs (length inputs))
         (outputs (tx-outputs tx))
         (num-outputs (length outputs))
         (witnesses (tx-witnesses tx))
         (locktime (tx-locktime tx)))
    (write-int version stream :size 4 :byte-order :little)
    (when witnesses
      (write-byte #x00 stream)  ;; write SegWit marker
      (write-byte #x01 stream)) ;; write SegWit flag
    (write-varint num-inputs stream)
    (loop
       :for i :below num-inputs
       :do (serialize (aref inputs i) stream))
    (write-varint num-outputs stream)
    (loop
       :for i :below num-outputs
       :do (serialize (aref outputs i) stream))
    (when witnesses
      (loop
         ;; Witness array length equals to input array length.
         :for i :below num-inputs
         :do (serialize (aref witnesses i) stream)))
    (write-int locktime stream :size 4 :byte-order :little)))

(defun read-num-inputs-or-segwit-flag (stream)
  "If currently parsed transaction is a SegWit one, it will have SegWit marker
and flag fields (0x00 0x01) bytes after its version field instead of the number
of inputs, so this function reads a varint and if it is 0x00, verifies that the
next byte is 0x01. Returns list (<number-of-inputs> <segwit-flag>), where
<segwit-flag> is the value of the flag (0x01) if transaction is SegWit, or NIL
otherwise."
  (let ((v (read-varint stream)))
    (if (= v #x00)
        ;; SegWit marker found, read flag and then the actual number
        ;; of inputs.
        (let ((flag (read-byte stream)))
          ;; Currently flag *must* be 0x01.
          (ecase flag
            (#x01 (list (read-varint stream) flag))))
        (list v nil))))

(defmethod parse ((entity-type (eql 'tx)) stream)
  (let* ((version (read-int stream :size 4 :byte-order :little))
         (num-inputs/segwit-flag (read-num-inputs-or-segwit-flag stream))
         (num-inputs (first num-inputs/segwit-flag))
         (segwit-flag (second num-inputs/segwit-flag))
         (inputs
          (loop
             :with input-array := (make-array num-inputs :element-type 'txin)
             :for i :below num-inputs
             :do (setf (aref input-array i) (parse 'txin stream))
             :finally (return input-array)))
         (num-outputs (read-varint stream))
         (outputs
          (loop
             :with output-array := (make-array num-outputs :element-type 'txout)
             :for i :below num-outputs
             :do (setf (aref output-array i) (parse 'txout stream))
             :finally (return output-array)))
         (witnesses
          ;; Check if not NIL, ignore the value for now.
          (when segwit-flag
            (loop
               :with witnesses := (make-array num-inputs :element-type 'witness)
               :for i :below num-inputs
               :do (setf (aref witnesses i) (parse 'witness stream))
               :finally (return witnesses))))
         (locktime (read-int stream :size 4 :byte-order :little)))
    (make-tx
     :version version
     :inputs inputs
     :outputs outputs
     :witnesses witnesses
     :locktime locktime)))

(defun tx-hash (tx)
  "Raw transaction ID is a double SHA256 of its binary serialization."
  (hash256
   (ironclad:with-octet-output-stream (stream)
     (serialize tx stream))))

(defun tx-id (tx)
  "Return hex-encoded txid - little-endian hash of the transaction serialization
without witness structures."
  (let ((legacy-tx (copy-tx tx)))
    (setf (tx-witnesses legacy-tx) nil)
    (to-hex (reverse (tx-hash legacy-tx)))))

(defun tx-wid (tx)
  "Return hex-encoded wtxid - little-endian hash of the transaction
serialization including witness structures."
  (to-hex (reverse (tx-hash tx))))

(defun tx-output (tx index)
  "Return INDEXth output of the given transaction."
  (aref (tx-outputs tx) index))

(defun tx-input (tx index)
  "Return INDEXth input of the given transaction."
  (aref (tx-inputs tx) index))

(defun tx-witness (tx index)
  "Return INDEXth witness of the given transaction, if it is a SegWit
transaction, otherwise return NIL."
  (when (tx-witnesses tx)
    (aref (tx-witnesses tx) index)))

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

(defmethod parse ((entity-type (eql 'txin)) stream)
  (let ((previous-tx-id (read-bytes stream 32))
        (previous-tx-index (read-int stream :size 4 :byte-order :little))
        (script-sig (parse 'script stream))
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

(defmethod parse ((entity-type (eql 'txout)) stream)
  (let ((amount (read-int stream :size 8 :byte-order :little))
        (script-pubkey (parse 'script stream)))
    (make-txout
     :amount amount
     :script-pubkey script-pubkey)))

(defmethod print-object ((txout txout) stream)
  (print-unreadable-object (txout stream :type t)
    (format stream "amount: ~a" (txout-amount txout))))

(defstruct witness
  items)

(defmethod serialize ((witness witness) stream)
  (let* ((items (witness-items witness))
         (num-items (length items)))
    (write-varint num-items stream)
    (loop
       :for i :below num-items
       :for item      := (aref items i)
       :for item-size := (length item)
       :do
         (write-varint item-size stream)
         (write-bytes item stream item-size))))

(defmethod parse ((entity-type (eql 'witness)) stream)
  (let* ((num-items (read-varint stream))
         (items
          (loop
             :with items
               := (make-array num-items :element-type '(array (unsigned-byte 8) *))
             :for i :below num-items
             :do (setf (aref items i) (read-bytes stream (read-varint stream)))
             :finally (return items))))
    (make-witness :items items)))

(defmethod print-object ((witness witness) stream)
  (print-unreadable-object (witness stream :type t)
    (format stream "items: ~a" (length (witness-items witness)))))
