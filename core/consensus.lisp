(uiop:define-package :bp/core/consensus (:use :cl)
  (:use :bp/core/encoding
        :bp/core/chain
        :bp/core/block
        :bp/core/transaction
        :bp/core/script
        :bp/crypto/hash)
  (:export
   #:validate
   #:validp
   #:validation-context))

(in-package :bp/core/consensus)


;;; The definitions in this file contain Bitcoin consensus rules. The
;;; top-level consensus API consists of two functions: VALIDATE, which
;;; returns T if an entity from the model is valid, and signals an
;;; explanatory error otherwise, and a wrapping VALIDP predicate,
;;; which ignores the errors and retuns NIL in the latter case.
;;;
;;; Bitcoin Consensus rules are particularly hard to reimplement,
;;; since there is a lot of corner cases (caused by engineering
;;; decisions, errors and semantic peculiarities of the C++, etc),
;;; some of which are known, and some are not, and failure to
;;; reproduce these corner cases may easily put this implementation
;;; out of sync with the network.
;;;
;;; Hence, THIS BITCOIN CONSENSUS RULES IMPLEMENTATION IS NOT, AND
;;; WILL PROBABLY NEVER BE FULLY COMPLIANT WITH BITCOIN CORE
;;; IMPLEMENTATION. DO NOT RELY ON IT FOR VALIDATING YOUR MAINNET
;;; TRANSACTIONS.


;;;-----------------------------------------------------------------------------
;;; Validation API

(defgeneric validate (entity &key context)
  (:documentation "Validate entity according to the Bitcoin Protocol
consensus rules, throw an error if an entity is invalid for any reason."))

(defun validp (entity &key context)
  "Return T if the ENTITY is valid, NIL otherwise."
  (ignore-errors (apply #'validate entity context)))

(defclass validation-context ()
  ((height      :initarg :height      :accessor @height      :initform nil)
   (cblock      :initarg :block       :accessor @block       :initform nil)
   (tx          :initarg :tx          :accessor @tx          :initform nil)
   (tx-index    :initarg :tx-index    :accessor @tx-index    :initform nil)
   (txin        :initarg :txin        :accessor @txin        :initform nil)
   (txin-index  :initarg :txin-index  :accessor @txin-index  :initform nil)
   (txout       :initarg :txout       :accessor @txout       :initform nil)
   (txout-index :initarg :txout-index :accessor @txout-index :initform nil))
  (:documentation "Structure for storing additional information needed
during entity validation."))

(defun ensure-validation-context (context)
  (or context (make-instance 'validation-context)))

(defun extend-validation-context (context &key height block tx tx-index txin
                                            txin-index txout txout-index)
  "Create a new VALIDATION-CONTEXT object from the given one and
extend it with additional data if supplied."
  (make-instance
   'validation-context
   :height      (or height      (@height context))
   :block       (or block       (@block context))
   :tx          (or tx          (@tx context))
   :tx-index    (or tx-index    (@tx-index context))
   :txin        (or txin        (@txin context))
   :txin-index  (or txin-index  (@txin-index context))
   :txout       (or txout       (@txout context))
   :txout-index (or txout-index (@txout-index context))))


;;;-----------------------------------------------------------------------------
;;; Blocks

(defun bits-to-target (bits)
  (let* ((f (ironclad:octets-to-integer bits :start 1))
         (e (aref bits 0)))
    (ironclad:integer-to-octets
     (* f (expt 2 (* 8 (- e 3))))
     :n-bits 256
     :big-endian nil)))

(defun block-target (block)
  (bits-to-target (block-bits block)))

(defun block-difficulty (block)
  (let ((current-target (bits-to-target (block-bits block)))
        (max-target
         (bits-to-target
          (make-array
           4 :element-type '(unsigned-byte 8)
           :initial-contents #(#x1d #x00 #xff #xff)))))
    (float
     (/ (ironclad:octets-to-integer max-target :big-endian nil)
        (ironclad:octets-to-integer current-target :big-endian nil)))))

(defmethod validate ((block-header block-header) &key context)
  (declare (ignore context))
  (unless (< (ironclad:octets-to-integer
              (block-hash block-header) :big-endian nil)
             (ironclad:octets-to-integer
              (block-target block-header) :big-endian nil))
    (error "Block hash does not satisfy Proof-of-Work target."))
  t)

(defmethod validate ((cblock cblock) &key context)
  (declare (ignore context))
  ;; TODO: validate transactions and merkle root
  (validate (block-header cblock))
  t)


;;;-----------------------------------------------------------------------------
;;; Transactions

(defconstant +sighash-all+          #x01)
(defconstant +sighash-none+         #x02)
(defconstant +sighash-single+       #x03)
(defconstant +sighash-anyonecanpay+ #x80)

(defun tx-sighash-base (tx txin-index script-code sighash-type)
  (let* ((tx (decode 'tx (encode tx))) ;; copy
         (txin (tx-input tx txin-index)))
    ;; SIGHASH_ALL: sign ALL of the outputs.
    (loop
       :for i :below (length (tx-inputs tx))
       :do (setf (script-commands (txin-script-sig (tx-input tx i))) #()))
    (setf (script-commands (txin-script-sig txin))
          (script-commands script-code))
    ;; SIGHASH_NONE: sign NONE of the outputs.
    (when (= (logand sighash-type #x1f) +sighash-none+)
      ;; Empty output vector.
      (setf (tx-outputs tx) (make-array 0 :element-type 'txout))
      ;; Set each input's (except current one) sequence to 0.
      (loop
         :for i :below (length (tx-inputs tx))
         :if (/= i txin-index)
         :do (setf (txin-sequence (tx-input tx i)) 0)))
    ;; SIGHASH_SINGLE: sign ONE of the outputs.
    (when (= (logand sighash-type #x1f) +sighash-single+)
      ;; Bitcoin Core's edge case; see
      ;;    https://bitcointalk.org/index.php?topic=260595.0
      ;; for an explanation.
      (when (< (length (tx-outputs tx)) (length (tx-inputs tx)))
        (let ((fhash (make-array 32 :element-type '(unsigned-byte 8)
                                 :initial-element 0)))
          (setf (aref fhash 31) 1)
          (return-from tx-sighash-base fhash)))
      ;; Resize output vector to TXIN-INDEX + 1 outputs.
      (setf (tx-outputs tx) (subseq (tx-outputs tx) 0 (1+ txin-index)))
      ;; Set each output's (except the TXIN-INDEXth one) to empty
      ;; script and value of -1.
      (loop
         :for i :below (length (tx-outputs tx))
         :if (/= i txin-index)
         :do
           (let ((txout (tx-output tx i)))
             (setf (script-commands (txout-script-pubkey txout)) #())
             (setf (txout-amount txout) -1)))
      ;; Set each input's (except current one) sequence to 0.
      (loop
         :for i :below (length (tx-inputs tx))
         :if (/= i txin-index)
         :do (setf (txin-sequence (tx-input tx i)) 0)))
    ;; SIGHASH_ANYONECANPAY: anyone can add inputs to this
    ;; transaction.
    (when (/= (logand sighash-type +sighash-anyonecanpay+) 0)
      ;; Set input vector to single (current) input.
      (setf (tx-inputs tx)
            (make-array 1 :element-type 'txin :initial-element txin)))
    (hash256
     (ironclad:with-octet-output-stream (stream)
       (serialize tx stream)
       (write-int sighash-type stream :size 4 :byte-order :little)))))

(defun tx-previous-outputs-hash (tx sighash-type)
  (if (zerop (logand sighash-type +sighash-anyonecanpay+))
      (hash256
       (ironclad:with-octet-output-stream (stream)
         (loop
            :for txin :across (tx-inputs tx)
            :for prev-id := (txin-previous-tx-id txin)
            :for prev-index := (txin-previous-tx-index txin)
            :do
              (write-bytes prev-id stream 32)
              (write-int prev-index stream :size 4 :byte-order :little))))
      (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))

(defun tx-sequence-hash (tx sighash-type)
  (if (and (zerop (logand sighash-type +sighash-anyonecanpay+))
           (/= (logand sighash-type #x1f) +sighash-single+)
           (/= (logand sighash-type #x1f) +sighash-none+))
      (hash256
       (ironclad:with-octet-output-stream (stream)
         (loop
            :for txin :across (tx-inputs tx)
            :for sequence := (txin-sequence txin)
            :do (write-int sequence stream :size 4 :byte-order :little))))
      (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))

(defun tx-outputs-hash (tx txin-index sighash-type)
  (cond
    ((and (/= (logand sighash-type #x1f) +sighash-single+)
          (/= (logand sighash-type #x1f) +sighash-none+))
     (hash256
      (ironclad:with-octet-output-stream (stream)
        (loop
           :for txout :across (tx-outputs tx)
           :do (serialize txout stream)))))
    ((and (= (logand sighash-type #x1f) +sighash-single+)
          (< txin-index (length (tx-outputs tx))))
     (hash256
      (ironclad:with-octet-output-stream (stream)
        (serialize (tx-output tx txin-index) stream))))
    (t
     (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))))

(defun tx-sighash-witness-v0 (tx txin-index amount script-code sighash-type)
  "Compute sighash for version 0 witness transactions in BIP-0143 (see the
spec at https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki)."
  (let ((previous-outputs-hash (tx-previous-outputs-hash tx sighash-type))
        (sequence-hash         (tx-sequence-hash tx sighash-type))
        (outputs-hash          (tx-outputs-hash tx txin-index sighash-type))
        (txin                  (tx-input tx txin-index)))
    (hash256
     (ironclad:with-octet-output-stream (stream)
       (write-int (tx-version tx) stream :size 4 :byte-order :little)
       (write-bytes previous-outputs-hash stream 32)
       (write-bytes sequence-hash stream 32)
       (write-bytes (txin-previous-tx-id txin) stream 32)
       (write-int (txin-previous-tx-index txin) stream :size 4 :byte-order :little)
       (serialize script-code stream)
       (write-int amount stream :size 8 :byte-order :little)
       (write-int (txin-sequence txin) stream :size 4 :byte-order :little)
       (write-bytes outputs-hash stream 32)
       (write-int (tx-locktime tx) stream :size 4 :byte-order :little)
       (write-int sighash-type stream :size 4 :byte-order :little)))))

(defun tx-sighash (tx txin-index amount script-code sighash-type sigversion)
  (ecase sigversion
    (:base
     (tx-sighash-base tx txin-index script-code sighash-type))
    (:witness-v0
     (tx-sighash-witness-v0 tx txin-index amount script-code sighash-type))))

(defun get-transaction-output (id index)
  "TODO: maybe make this part of chain supplier API."
  (let ((prev-tx (get-transaction id :errorp t)))
    (when prev-tx
      (if (>= index (length (tx-outputs prev-tx)))
          (error "Unknown previous output ~a:~a." (tx-id prev-tx) index)
          (tx-output prev-tx index)))))

(defmethod validate ((tx tx) &key context)
  (let ((context (ensure-validation-context context)))
    (flet ((%txin-amount (input)
             (txout-amount
              (get-transaction-output
               (txin-previous-tx-id input)
               (txin-previous-tx-index input)))))
      (unless (>= (apply #'+ (map 'list #'%txin-amount (tx-inputs tx)))
                  (apply #'+ (map 'list #'txout-amount (tx-outputs tx))))
        (error "Output total is larger then input total."))
      (loop
         :for txout-index :below (length (tx-outputs tx))
         :for txout-context
           := (extend-validation-context context :tx tx :txout-index txout-index)
         :do (validate (tx-output tx txout-index) :context txout-context))
      (loop
         :for txin-index :below (length (tx-inputs tx))
         :for txin-context
           := (extend-validation-context context :tx tx :txin-index txin-index)
         :do (validate (tx-input tx txin-index) :context txin-context))
      t)))

(defmethod validate ((txin txin) &key context)
  (let* ((context (ensure-validation-context context))
         (prev-out
          (get-transaction-output
           (txin-previous-tx-id txin)
           (txin-previous-tx-index txin)))
         (script-pubkey (txout-script-pubkey prev-out))
         (amount (txout-amount prev-out))
         (script-sig (txin-script-sig txin))
         (witness (tx-witness (@tx context) (@txin-index context)))
         (sighashf
          (lambda (script-code sighash-type sigversion)
            (tx-sighash (@tx context)
                        (@txin-index context)
                        amount
                        script-code
                        sighash-type
                        sigversion)))
         (script-state
          (make-script-state
           :witness (when witness (witness-items witness))
           :sighashf sighashf)))
    (unless (execute-scripts script-sig script-pubkey :state script-state)
      (error "Script execution failed."))
    t))

(defmethod validate ((txout txout) &key context)
  (declare (ignore context))
  ;; Assume all txouts are valid for now.
  t)

#+test
(defvar *non-p2sh-tx*
  "6a26d2ecb67f27d1fa5524763b49029d7106e91e3cc05743073461a719776192")
