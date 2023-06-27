;;; Copyright (c) 2019-2023 BP Developers & Contributors
;;; See the accompanying file LICENSE for the full license governing this code.

(uiop:define-package :bp/core/block (:use :cl)
  (:use :bp/core/encoding
        :bp/core/transaction
        :bp/crypto/hash)
  (:export
   ;; Block header API:
   #:block-header
   #:block-version
   #:block-previous-block-hash
   #:block-merkle-root
   #:block-timestamp
   #:block-bits
   #:block-nonce
   #:block-hash
   #:block-id
   ;; Complete block API:
   #:cblock
   #:block-transactions
   #:block-transaction))

(in-package :bp/core/block)


;;;-----------------------------------------------------------------------------
;;; Generic API

(defgeneric block-version (block))

(defgeneric block-previous-block-hash (block))

(defgeneric block-merkle-root (block))

(defgeneric block-timestamp (block))

(defgeneric block-bits (block))

(defgeneric block-nonce (block))

(defgeneric block-hash (block))

(defun block-id (block)
  (hex-encode (reverse (block-hash block))))


;;;-----------------------------------------------------------------------------
;;; Data structures and API implementation

(defstruct block-header
  version
  previous-block-hash
  merkle-root
  timestamp
  bits
  nonce)

(defmethod serialize ((block-header block-header) stream)
  (let ((version (block-version block-header))
        (previous-block-hash (block-previous-block-hash block-header))
        (merkle-root (block-merkle-root block-header))
        (timestamp (block-timestamp block-header))
        (bits (block-bits block-header))
        (nonce (block-nonce block-header)))
    (write-int version stream :size 4 :byte-order :little)
    (write-bytes previous-block-hash stream 32)
    (write-bytes merkle-root stream 32)
    (write-int timestamp stream :size 4 :byte-order :little)
    (write-bytes (reverse bits) stream 4)
    (write-bytes nonce stream 4)))

(defmethod parse ((entity-type (eql 'block-header)) stream)
  (let ((version (read-int stream :size 4 :byte-order :little))
        (previous-block-hash (read-bytes stream 32 ))
        (merkle-root (read-bytes stream 32))
        (timestamp (read-int stream :size 4 :byte-order :little))
        (bits (reverse (read-bytes stream 4)))
        (nonce (read-bytes stream 4)))
    (make-block-header
     :version version
     :previous-block-hash previous-block-hash
     :merkle-root merkle-root
     :timestamp timestamp
     :bits bits
     :nonce nonce)))

(defmethod print-object ((block-header block-header) stream)
  (print-unreadable-object (block-header stream :type t)
    (format
     stream "~&  id:   ~a~&  prev: ~a"
     (block-id block-header)
     (hex-encode (reverse (block-previous-block-hash block-header))))))

(defmethod block-version ((block-header block-header))
  (block-header-version block-header))

(defmethod block-previous-block-hash ((block-header block-header))
  (block-header-previous-block-hash block-header))

(defmethod block-merkle-root ((block-header block-header))
  (block-header-merkle-root block-header))

(defmethod block-timestamp ((block-header block-header))
  (block-header-timestamp block-header))

(defmethod block-bits ((block-header block-header))
  (block-header-bits block-header))

(defmethod block-nonce ((block-header block-header))
  (block-header-nonce block-header))

(defmethod block-hash ((block-header block-header))
  (hash256
   (ironclad:with-octet-output-stream (stream)
     (serialize block-header stream))))


(defstruct (cblock (:conc-name block-))
  header
  transactions)

(defun block-transaction (cblock index)
  (aref (block-transactions cblock) index))

(defmethod serialize ((cblock cblock) stream)
  (let* ((header (block-header cblock))
         (transactions (block-transactions cblock))
         (num-transactions (length transactions)))
    (serialize header stream)
    (write-varint num-transactions stream)
    (loop
       :for i :below num-transactions
       :do (serialize (aref transactions i) stream))))

(defmethod parse ((entity-type (eql 'cblock)) stream)
  (let* ((header (parse 'block-header stream))
         (num-transactions (read-varint stream))
         (transactions
          (loop
             :with transaction-array
               := (make-array num-transactions :element-type 'tx)
             :for i :below num-transactions
             :do (setf (aref transaction-array i) (parse 'tx stream))
             :finally (return transaction-array))))
    (make-cblock
     :header header
     :transactions transactions)))

(defmethod print-object ((cblock cblock) stream)
  (print-unreadable-object (cblock stream :type t)
    (format
     stream "(~a txs)~&  id:   ~a~&  prev: ~a"
     (length (block-transactions cblock))
     (block-id (block-header cblock))
     (hex-encode (reverse (block-previous-block-hash cblock))))))

(defmethod block-version ((cblock cblock))
  (block-version (block-header cblock)))

(defmethod block-previous-block-hash ((cblock cblock))
  (block-previous-block-hash (block-header cblock)))

(defmethod block-merkle-root ((cblock cblock))
  (block-merkle-root (block-header cblock)))

(defmethod block-timestamp ((cblock cblock))
  (block-timestamp (block-header cblock)))

(defmethod block-bits ((cblock cblock))
  (block-bits (block-header cblock)))

(defmethod block-nonce ((cblock cblock))
  (block-nonce (block-header cblock)))

(defmethod block-hash ((cblock cblock))
  (block-hash (block-header cblock)))
