(uiop:define-package :bp/core/consensus (:use :cl)
  (:use :bp/core/encoding
        :bp/core/chain
        :bp/core/block
        :bp/core/transaction
        :bp/core/script
        :bp/crypto/hash)
  (:export
   #:validate
   #:validp))

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

(defgeneric validate (entity &key &allow-other-keys)
  (:documentation "Validate entity according to the Bitcoin Protocol
consensus rules, throw an error if an entity is invalid for any reason."))

(defun validp (entity &rest context &key &allow-other-keys)
  "Return T if the ENTITY is valid, NIL otherwise."
  (ignore-errors (apply #'validate entity context)))


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

(defmethod validate ((block-header block-header) &key)
  (unless (< (ironclad:octets-to-integer
              (block-hash block-header) :big-endian nil)
             (ironclad:octets-to-integer
              (block-target block-header) :big-endian nil))
    (error "Block hash does not satisfy Proof-of-Work target."))
  t)

(defmethod validate ((cblock cblock) &key)
  ;; TODO: validate transactions and merkle root
  (validate (block-header cblock))
  t)


;;;-----------------------------------------------------------------------------
;;; Transactions

(defconstant +sighash-all+          #x01)
(defconstant +sighash-none+         #x02)
(defconstant +sighash-single+       #x03)
(defconstant +sighash-anyonecanpay+ #x80)

(defun tx-sighash (tx txin-index txout-script-pubkey hashtype)
  (let* ((tx (decode 'tx (encode tx))) ;; copy
         (txin (tx-input tx txin-index)))
    ;; SIGHASH_ALL: sign ALL of the outputs.
    (loop
       :for i :below (length (tx-inputs tx))
       :do (setf (script-commands (txin-script-sig (tx-input tx i))) #()))
    (setf (script-commands (txin-script-sig txin))
          (script-commands txout-script-pubkey))
    ;; SIGHASH_NONE: sign NONE of the outputs.
    (when (= (logand hashtype 31) +sighash-none+)
      ;; Empty output vector.
      (setf (tx-outputs tx) (make-array 0 :element-type 'txout))
      ;; Set each input's (except current one) sequence to 0.
      (loop
         :for i :below (length (tx-inputs tx))
         :if (/= i txin-index)
         :do (setf (txin-sequence (tx-input tx i)) 0)))
    ;; SIGHASH_SINGLE: sign ONE of the outputs.
    (when (= (logand hashtype 31) +sighash-single+)
      ;; Bitcoin Core's edge case; see
      ;;    https://bitcointalk.org/index.php?topic=260595.0
      ;; for an explanation.
      (when (< (length (tx-outputs tx)) (length (tx-inputs tx)))
        (let ((fhash (make-array 32 :element-type '(unsigned-byte 8)
                                 :initial-element 0)))
          (setf (aref fhash 31) 1)
          (return-from tx-sighash )))
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
    (when (/= (logand hashtype +sighash-anyonecanpay+) 0)
      ;; Set input vector to single (current) input.
      (setf (tx-inputs tx)
            (make-array 1 :element-type 'txin :initial-element txin)))
    (hash256
     (ironclad:with-octet-output-stream (stream)
       (serialize tx stream)
       (write-int hashtype stream :size 4 :byte-order :little)))))

(defmethod validate ((tx tx) &key)
  (flet ((%txin-amount (input)
           (let ((prev-tx (get-transaction (txin-previous-tx-id input)))
                 (prev-tx-index (txin-previous-tx-index input)))
             (unless prev-tx
               (error "Unknown previous transaction."))
             (unless (< prev-tx-index (length (tx-outputs prev-tx)))
               (error "Unknown previous output."))
             (txout-amount (tx-output prev-tx prev-tx-index)))))
    (unless (>= (apply #'+ (map 'list #'%txin-amount (tx-inputs tx)))
                (apply #'+ (map 'list #'txout-amount (tx-outputs tx))))
      (error "Output total is larger then input total."))
    (loop
       :for txout-index :below (length (tx-outputs tx))
       :do (validate (tx-output tx txout-index)))
    (loop
       :for txin-index :below (length (tx-inputs tx))
       :do (validate
            (tx-input tx txin-index)
            :tx tx :txin-index txin-index))
    t))

(defmethod validate ((txin txin) &key tx txin-index)
  (let ((prev-tx (get-transaction (txin-previous-tx-id txin)))
        (prev-tx-index (txin-previous-tx-index txin)))
    (unless prev-tx
      (error "Unknown previous transaction."))
    (unless (< prev-tx-index (length (tx-outputs prev-tx)))
      (error "Unknown previous output."))
    (let* ((script-pubkey (txout-script-pubkey (tx-output prev-tx prev-tx-index)))
           (script-sig (txin-script-sig txin))
           (sighashf
            (lambda (hashcode hashtype)
              (tx-sighash tx txin-index hashcode hashtype)))
           (script-state (make-script-state :sighashf sighashf)))
      (unless (execute-scripts script-sig script-pubkey :state script-state)
        (error "Script execution failed.")))
    t))

(defmethod validate ((txout txout) &key)
  ;; Assume all txouts are valid for now.
  t)

#+test
(defvar *non-p2sh-tx*
  "6a26d2ecb67f27d1fa5524763b49029d7106e91e3cc05743073461a719776192")
