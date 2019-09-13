(uiop:define-package :bp/core/block (:use :cl)
  (:use :bp/core/encoding
        :bp/crypto/hash)
  (:export
   #:block-header
   #:merkle-block))

(in-package :bp/core/block)

(defstruct (block-header (:conc-name block-))
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
    (write-bytes bits stream 4)
    (write-bytes nonce stream 4)))

(defmethod deserialize ((entity-type (eql 'block-header)) stream)
  (let ((version (read-int stream :size 4 :byte-order :little))
        (previous-block-hash (read-bytes stream 32 ))
        (merkle-root (read-bytes stream 32))
        (timestamp (read-int stream :size 4 :byte-order :little))
        (bits (read-bytes stream 4))
        (nonce (read-bytes stream 4)))
    (make-block-header
     :version version
     :previous-block-hash previous-block-hash
     :merkle-root merkle-root
     :timestamp timestamp
     :bits bits
     :nonce nonce)))

(defun blockid (block-header)
  (hash256
   (ironclad:with-octet-output-stream (stream)
     (serialize block-header stream))))

(defun block-id (block-header)
  (to-hex (reverse (blockid block-header))))

(defmethod print-object ((block-header block-header) stream)
  (print-unreadable-object (block-header stream :type t)
    (format
     stream "~&  id:   ~a~&  prev: ~a"
     (block-id block-header)
     (to-hex (reverse (block-previous-block-hash block-header))))))

;; TODO: :INCLUDE in this case might be a bad thing, as we would like
;;       to be able to extract the BLOCK-HEADER structure from the
;;       MERKLE-BLOCK, so maybe just use simple composition and
;;       override accessors.
(defstruct (merkle-block (:include block-header)
                         (:conc-name block-))
  transactions)
