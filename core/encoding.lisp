(uiop:define-package :bp/core/encoding (:use :cl :ironclad)
  (:use :bp/crypto/hash)
  (:export
   ;; Serialization API:
   #:serialize
   #:parse
   #:encode
   #:decode
   ;; Utilities:
   #:read-bytes
   #:write-bytes
   #:read-int
   #:write-int
   #:read-varint
   #:write-varint
   ;; Encoding
   ;; Generic:
   #:checksum-error
   ;; HEX
   #:hex-encode
   #:hex-decode
   ;; BASE58/BASE58CHECK
   #:base58-encode
   #:base58-decode
   #:base58check-encode
   #:base58check-decode
   #:base58check-checksum-error
   #:base58check-bad-checksum-error
   #:base58check-no-checksum-error))

(in-package :bp/core/encoding)


;;;-----------------------------------------------------------------------------
;;; Entity encoding/decoding API

(defgeneric serialize (entity stream)
  (:documentation "Serialize ENTITY into the stream."))

(defgeneric parse (entity-class stream)
  (:documentation "Parse bytes from the STREAM into an instance
  of the class named ENTITY-CLASS."))

(defun encode (entity)
  "Encode Bitcoin Protocol ENTITY into a hex string."
  (hex-encode
   (ironclad:with-octet-output-stream (stream)
     (serialize entity stream))))

(defun decode (entity-class string)
  "Decode Bitcoin Protocol entity given by its class name ENTITY-CLASS
from hex STRING."
  (ironclad:with-octet-input-stream (stream (hex-decode string))
    (parse entity-class stream)))


;;;-----------------------------------------------------------------------------
;;; Parsing/serialization utils

(defun read-bytes (stream size)
  (let ((bytes (make-array size :element-type '(unsigned-byte 8))))
    (read-sequence bytes stream)
    bytes))

(defun write-bytes (bytes stream size)
  (write-sequence bytes stream :start 0 :end size))

(defun read-int (stream &key size byte-order)
  (let ((big-endian-p
         (ecase byte-order
           (:big    t)
           (:little nil)))
        (bytes
         (read-bytes stream size)))
    (ironclad:octets-to-integer bytes :n-bits (* 8 size) :big-endian big-endian-p)))

(defun write-int (i stream &key size byte-order)
  (let* ((big-endian-p
          (ecase byte-order
            (:big    t)
            (:little nil)))
         (bytes
          (ironclad:integer-to-octets i :n-bits (* 8 size) :big-endian big-endian-p)))
    (write-bytes bytes stream size)))

(defun read-varint (stream)
  (let ((tag (read-byte stream)))
    (case tag
      (#xfd (read-int stream :size 2 :byte-order :little))
      (#xfe (read-int stream :size 4 :byte-order :little))
      (#xff (read-int stream :size 8 :byte-order :little))
      (t    tag))))

(defun write-varint (i stream)
  (cond ((< i #xfd)
         (write-byte i stream))
        ((< i #x10000)
         (write-byte #xfd stream)
         (write-int i stream :size 2 :byte-order :little))
        ((< i #x100000000)
         (write-byte #xfe stream)
         (write-int i stream :size 4 :byte-order :little))
        ((< i #x10000000000000000)
         (write-byte #xff stream)
         (write-int i stream :size 8 :byte-order :little))
        (t
         (error "Integer ~a is too large." i))))


(defun make-byte-array (length &optional contents)
  (let ((result (make-array length :element-type '(unsigned-byte 8))))
    (when contents
      (loop
         :for i :below (length contents)
         :do (setf (aref result i) (elt contents i))))
    result))


;;;-----------------------------------------------------------------------------
;;; Encoding formats

;;; Generic declarations
(define-condition checksum-error (error) ())

(defmacro define-alphabet (name &body (charset &key case-insensitive))
  "Define two functions for encoding/decoding digits of a given
encoding scheme named <NAME>-ENCODE-DIGIT and <NAME>-DECODE-DIGIT
respective."
  (assert (symbolp name) (name) "Alphabet name ~s is not a symbol." name)
  (assert (stringp charset) (charset) "Alphabet charset ~s is not a string." charset)
  (flet ((combine-symbols (&rest symbols)
           (intern (format nil "~{~a~}" (mapcar #'symbol-name symbols)))))
    `(progn
       (defun ,(combine-symbols name '-encode-digit) (n)
         (ecase n
           ,@(loop
                :for i    :below (length charset)
                :for char :across charset
                :collect `(,i ,char))))
       (defun ,(combine-symbols name '-decode-digit) (c)
         (ecase c
           ,@(loop
                :for i    :below (length charset)
                :for char :across charset
                ;; Only generate dual cases for characters that are
                ;; different in their up- and downcase forms.
                :for case
                  := (if (and case-insensitive (char/= (char-upcase char) char))
                         `(,char ,(char-upcase char))
                         char)
                :collect `(,case ,i)))))))


;;; HEX

;; TODO: implement our own hex encoding/decoding.
;; (define-alphabet hex "0123456789abcdef" :case-insensitive t)

(defun hex-encode (bytes)
  "Shortcut to avoid using long symbol IRONCLAD:BYTE-ARRAY-TO-HEX-STRING."
  (ironclad:byte-array-to-hex-string (make-byte-array (length bytes) bytes)))

(defun hex-decode (string)
  "Shortcut to avoid using long symbol IRONCLAD:HEX-STRING-TO-BYTE-ARRAY."
  (ironclad:hex-string-to-byte-array string))

;;; BASE58CHECK
(define-alphabet base58 "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

(define-condition base58check-checksum-error (checksum-error) ())

(define-condition base58check-bad-checksum-error (base58check-checksum-error) ()
  (:report "BASE58CHECK checksum does not match."))

(define-condition base58check-no-checksum-error (base58check-checksum-error) ()
  (:report "BASE58CHECK checksum is missing."))

(defun base58-encode (bytes)
  "Encode a byte array with BASE58 and return a resulting string."
  (let* ((start (loop :for b :across bytes :while (zerop b) :counting b))
         ;; Compute a rounded log(256)/log(58) to allocate enough
         ;; space for a big-endian base58 number representation.
         (base58-length (1+ (truncate (* 138 (- (length bytes) start)) 100)))
         (base58 (make-byte-array base58-length)))
    ;; Convert base256 number to a base58 number.
    (loop ;; for every base256 digit carry = bytes[i]
       :for i :from start :below (length bytes)
       :for carry := (aref bytes i)
       :do
         (loop ;; base58 = base58 * 256 + carry
            :for j :from (1- base58-length) :downto 0
            :do
              (multiple-value-bind (new-carry base58-elt)
                  (truncate (+ carry (* 256 (aref base58 j))) 58)
                (setf carry new-carry)
                (setf (aref base58 j) base58-elt)))
         (assert (zerop carry)))
    ;; Convert result to a string.
    (let* ((base58-start (loop :for b :across base58 :while (zerop b) :counting b))
           (base58-string-length (+ start (- base58-length base58-start)))
           (base58-string (make-string base58-string-length :initial-element #\1)))
      (loop
         :for i :below (- base58-length base58-start)
         :for base58-char := (base58-encode-digit (aref base58 (+ i base58-start)))
         :do (setf (aref base58-string (+ start i)) base58-char))
      base58-string)))

(defun base58-decode (string)
  "Decode a BASE58-encoded string and return a byte array."
  (let* ((start (loop :for c :across string :while (char= c #\1) :counting c))
         ;; Computed a rounded log(58)/log(256) to allocate enough
         ;; space for a big-endian base256 number representation.
         (base256-length (1+ (truncate (* 733 (- (length string) start)) 1000)))
         (base256 (make-byte-array base256-length)))
    ;; Convert base58 number to a base256 number.
    (loop ;; for every base58 digit carry = string[i]
       :for i :from start :below (length string)
       :for carry := (base58-decode-digit (aref string i))
       :do
         (loop ;; base256 = base256 * 58 + carry
            :for j :from (1- base256-length) :downto 0
            :do
              (multiple-value-bind (new-carry base256-elt)
                  (truncate (+ carry (* 58 (aref base256 j))) 256)
                (setf carry new-carry)
                (setf (aref base256 j) base256-elt)))
         (assert (zerop carry)))
    ;; Construct resulting byte array.
    (let* ((base256-start (loop :for b :across base256 :while (zerop b) :counting b))
           (bytes-length (+ start (- base256-length base256-start)))
           (bytes (make-byte-array bytes-length)))
      (loop
         :for i :below (- base256-length base256-start)
         :for byte := (aref base256 (+ i base256-start))
         :do (setf (aref bytes (+ start i)) byte))
      bytes)))

(defun base58check-encode (bytes)
  "BASE58-encode a byte array BYTES (payload) followed by the checksum
computed as first 4 bytes of the double-SHA256 hash of the payload."
  (let* ((bytes-length (length bytes))
         (bytes/checksum-length (+ 4 bytes-length))
         (bytes/checksum (make-byte-array bytes/checksum-length bytes)))
    (loop
       :with hash := (hash256 (make-byte-array bytes-length bytes))
       :for i :below 4
       :do (setf (aref bytes/checksum (+ bytes-length i)) (aref hash i)))
    (base58-encode bytes/checksum)))

(defun base58check-decode (string)
  "Decode a BASE58-encoded string STRING, verify that the last 4
bytes (checksum part) match the first 4 bytes of the double-SHA256
hash of all but the last 4 bytes of the original sequence (payload
part) and return the payload part."
  (let* ((bytes/checksum (base58-decode string))
         (bytes/checksum-length (length bytes/checksum))
         (bytes-length (if (>= bytes/checksum-length 4)
                           (- bytes/checksum-length 4)
                           (error 'base58check-no-checksum-error)))
         (bytes (subseq bytes/checksum 0 bytes-length)))
    (loop
       :with hash := (hash256 (make-byte-array bytes-length bytes))
       :for i :below 4
       :if (/= (aref bytes/checksum (+ bytes-length i)) (aref hash i))
       :do (error 'base58check-bad-checksum-error))
    (make-byte-array bytes-length bytes)))
