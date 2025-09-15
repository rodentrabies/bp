;;; Copyright (c) BP Developers & Contributors
;;; See the accompanying file LICENSE for the full license governing this code.

(uiop:define-package :bp.core.encoding (:nicknames :bp/core/encoding)
  (:use :cl)
  (:use :bp.crypto.hash)
  (:import-from :ironclad)
  (:export
   ;; Ironclad wrappers:
   #:with-output-to-byte-array
   #:with-input-from-byte-array
   #:byte-array-to-integer
   #:integer-to-byte-array
   ;; Utilities:
   #:read-bytes
   #:write-bytes
   #:read-int
   #:write-int
   #:read-varint
   #:write-varint
   #:make-byte-array
   ;; Serialization API:
   #:serialize
   #:parse
   #:encode
   #:decode
   ;; Generic encoding utilities:
   #:checksum-error
   ;; HEX encoding:
   #:hex-encode
   #:hex-decode
   ;; BASE58/BASE58CHECK encoding:
   #:base58-encode
   #:base58-decode
   #:base58check-encode
   #:base58check-decode
   #:base58check-checksum-error
   #:base58check-bad-checksum-error
   #:base58check-no-checksum-error
   ;; BECH32/BECH32M encoding:
   #:bech32-encode
   #:bech32-decode
   #:bech32-checksum-error
   #:bech32-bad-checksum-error
   #:bech32-no-checksum-error
   #:bech32-no-hrp-error
   #:bech32-invalid-hrp-character-error
   #:bech32-mixed-case-characters-error
   #:bech32-no-separator-character-error))

(in-package :bp.core.encoding)


;;; ----------------------------------------------------------------------------
;;; Wrappers around Ironclad's utilities. All Ironclad dependencies
;;; should be limited to here and bp.crypto package.

;;; TODO: maybe these should be moved to a dedicated place (like
;;;       bp.crypto.bytes package).

(defmacro with-output-to-byte-array ((var) &body body)
  #+allegro
  `(excl:with-output-to-buffer (,var) ,@body)
  #-allegro
  `(ironclad:with-octet-output-stream (,var) ,@body))

(defmacro with-input-from-byte-array ((var bytes &optional (start 0) end) &body body)
  #+allegro
  `(excl:with-input-from-buffer (,var ,bytes :start ,start :end ,end) ,@body)
  #-allegro
  `(ironclad:with-octet-input-stream (,var ,bytes ,start ,end) ,@body))

(defun byte-array-to-integer (bytes &key (start 0) end (big-endian t) n-bits)
  (ironclad:octets-to-integer
   bytes
   :start start
   :end end
   :n-bits n-bits
   :big-endian big-endian))

(defun integer-to-byte-array (integer &key n-bits (big-endian t))
  (ironclad:integer-to-octets
   integer
   :n-bits n-bits
   :big-endian big-endian))

(defun ascii-string-to-byte-array (string &key (start 0) end)
  ;; TODO: this is only used in bp.net.message; do we really need it?
  ;;       I'm leaving it non-exported for now.
  (ironclad:ascii-string-to-byte-array string :start start :end end))


;;;-----------------------------------------------------------------------------
;;; Parsing/serialization utils

(defun read-bytes (stream size)
  (let ((bytes (make-byte-array size)))
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
    (byte-array-to-integer bytes :n-bits (* 8 size) :big-endian big-endian-p)))

(defun write-int (i stream &key size byte-order)
  (let* ((big-endian-p
          (ecase byte-order
            (:big    t)
            (:little nil)))
         (bytes
          (integer-to-byte-array i :n-bits (* 8 size) :big-endian big-endian-p)))
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
  (let ((result (make-array length :element-type '(unsigned-byte 8) :initial-element 0)))
    (when contents
      (loop
         :for i :below (length contents)
         :do (setf (aref result i) (elt contents i))))
    result))

(defun make-adjustable-byte-array (length)
  (make-array length :element-type '(unsigned-byte 8) :adjustable t :fill-pointer t))

(defun make-displaced-byte-array (bytes)
  (make-array (length bytes) :element-type '(unsigned-byte 8) :displaced-to bytes))


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
   (with-output-to-byte-array (stream)
     (serialize entity stream))))

(defun decode (entity-class string)
  "Decode Bitcoin Protocol entity given by its class name ENTITY-CLASS
from hex STRING."
  (with-input-from-byte-array (stream (hex-decode string))
    (parse entity-class stream)))


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
  (ironclad:byte-array-to-hex-string (make-byte-array (length bytes) bytes)))

(defun hex-decode (string)
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

;;; BECH32/BECH32M
(define-alphabet bech32 "qpzry9x8gf2tvdw0s3jn54khce6mua7l")

(define-condition bech32-error () ())

(define-condition bech32-checksum-error (bech32-error checksum-error) ())

(define-condition bech32-bad-checksum-error (bech32-checksum-error) ()
  (:report "Bech32 checksum does not match."))

(define-condition bech32-no-checksum-error (bech32-checksum-error) ()
  (:report "Bech32 checksum is missing."))

(define-condition bech32-no-hrp-error (bech32-error) ()
  (:report "Bech32 HRP is missing."))

(define-condition bech32-invalid-hrp-character-error (bech32-error)
  ((character
    :initarg :character))
  (:report
   (lambda (c s)
     (format s "Invalid Bech32 HRP character: 0x~x."
             (char-code (slot-value c 'character))))))

(define-condition bech32-mixed-case-characters-error (bech32-error) ()
  (:report "Bech32 string must be lowercase or uppercase but not mixed."))

(define-condition bech32-no-separator-character-error (bech32-error) ()
  (:report "Missing Bech32 separator character."))

(defconstant +bech32-encoding-constant+           1)
(defconstant +bech32m-encoding-constant+ #x2bc830a3)

(defun bech32-polymod (values)
  (let ((gen #(#x3b6a57b2 #x26508e6d #x1ea119fa #x3d4233dd #x2a1462b3))
        (c 1))
    (loop
      :for v :across values
      :for c0 := (ash c -25)
      :do
         (setf c (logxor (ash (logand c #x1ffffff) 5) v))
         (loop
           :for i :below 5
           :if (not (zerop (logand c0 (ash 1 i))))
             :do (setf c (logxor c (aref gen i)))))
    c))

(defun bech32-hrp-expand (s)
  (let ((left  (map 'vector (lambda (c) (ash    (char-code c) -5)) s))
        (right (map 'vector (lambda (c) (logand (char-code c) 31)) s)))
    (concatenate 'vector left #(0) right)))

(defun bech32-verify-checksum (hrp data)
  "Verify checksum using the both Bech32 and Bech32m constants.
Return the detected encoding or NIL if neither match."
  (let ((polymod (bech32-polymod (concatenate 'vector (bech32-hrp-expand hrp) data))))
    (cond ((= polymod +bech32-encoding-constant+)
           :bech32)
          ((= polymod +bech32m-encoding-constant+)
           :bech32m)
          (t
           nil))))

(defun bech32-compute-checksum (encoding hrp data)
  (let* ((values (concatenate 'vector (bech32-hrp-expand hrp) data #(0 0 0 0 0 0)))
         (constant (ecase encoding
                     (:bech32  +bech32-encoding-constant+)
                     (:bech32m +bech32m-encoding-constant+)))
         (polymod (logxor (bech32-polymod values) constant)))
    (loop :for i :below 6 :collect (logand (ash polymod (- (* 5 (- 5 i)))) 31))))

(defun convert-bits (values from-bits to-bits padp output-fn)
  "Convert from one power-of-2 number base to another. Feed each digit
to the function OUTPUT-FN. We only need this to work for octets for
now. A direct translation from Bitcoin Core's `ConvertBits` function
in `util/strencoding.h`."
  (assert (and (typep from-bits 'integer) (<= 1 from-bits 8))
          () "FROM-BITS must be an integer from 1 to 8.")
  (assert (and (typep to-bits 'integer) (<= 1 from-bits 8))
          () "TO-BITS must be an integer from 1 to 8.")
  (let* ((maxv    (1- (ash 1 to-bits)))
         (maxacc  (1- (ash 1 (+ from-bits to-bits -1))))
         (acc     0)
         (bits    0))
    (loop
      :for i  :below (length values)
      :for vi := (aref values i)
      :do
         (setf acc (logand (logior (ash acc from-bits) vi) maxacc))
         (incf bits from-bits)
         (loop
           :while (>= bits to-bits)
           :do
              (decf bits to-bits)
              (funcall output-fn (logand (ash acc (- bits)) maxv))))
    (if padp
        (when (not (zerop bits))
          (funcall output-fn (logand (ash acc (- to-bits bits)) maxv)))
        (when (or (>= bits from-bits)
                  (not (zerop (logand (ash acc (- to-bits bits)) maxv))))
          (error "Unable to convert without using padding.")))
    t))

(defun bech32*-encode (encoding hrp data)
  (let* ((data-offset (1+ (length hrp)))
         (checksum (bech32-compute-checksum encoding hrp data))
         (bech32 (concatenate 'vector data checksum))
         (bech32-string-length (+ data-offset (length bech32)))
         (bech32-string (make-string bech32-string-length)))
    (loop
      :for i :below (length hrp)
      :do (setf (aref bech32-string i) (aref hrp i))
      :finally (setf (aref bech32-string i) #\1))
    (loop
      :for i :below (length bech32)
      :for c := (bech32-encode-digit (aref bech32 i))
      :do (setf (aref bech32-string (+ data-offset i)) c))
    bech32-string))

(defun bech32*-decode (string)
  (loop
    :with lower := nil :with upper := nil
    :for c :across string
    :do (cond ((<= (char-code #\a) (char-code c) (char-code #\z))
               (setf lower t))
              ((<= (char-code #\A) (char-code c) (char-code #\Z))
               (setf upper t)))
    :finally (and lower upper (error 'bech32-mixed-case-characters-error)))
  (let ((pos (position #\1 string :test #'char= :from-end t)))
    (when (not pos)
      (error 'bech32-no-separator-character-error))
    (when (zerop pos)
      (error 'bech32-no-hrp-error))
    (when (not (< pos (- (length string) 6)))
      (error 'bech32-no-checksum-error))
    (let* ((values-length (- (length string) pos 1))
           (values (make-byte-array values-length))
           (hrp (string-downcase (subseq string 0 pos))))
      (loop
        :for c :across hrp
        :do (when (or (< (char-code c) 33) (> (char-code c) 126))
              (error 'bech32-invalid-hrp-character-error :character c)))
      (loop
        :for i :below values-length
        :do (let ((c (aref string (+ pos i 1))))
              (setf (aref values i) (bech32-decode-digit (char-downcase c)))))
      (let ((detected-encoding (bech32-verify-checksum hrp values)))
        (unless detected-encoding
          (error 'bech32-bad-checksum-error))
        (values detected-encoding hrp values values-length)))))

(defun bech32-encode (hrp bytes &key versionp bech32m-p)
  (let ((data (make-adjustable-byte-array 0))
        (version (when versionp (aref bytes 0)))
        (bytes (if versionp (subseq bytes 1) bytes)))
    (when version (vector-push-extend version data))
    (convert-bits bytes 8 5 t (lambda (n) (vector-push-extend n data)))
    (bech32*-encode (if bech32m-p :bech32m :bech32) hrp data)))

(defun bech32-decode (string &key versionp)
  (multiple-value-bind (encoding hrp values values-length)
      (bech32*-decode string)
    (let ((version (when versionp (aref values 0)))
          (data (subseq values (if versionp 1 0) (- values-length 6)))
          (bytes (make-adjustable-byte-array 0)))
      (when version (vector-push-extend version bytes))
      (convert-bits data 5 8 nil (lambda (n) (vector-push-extend n bytes)))
      (values (make-displaced-byte-array bytes) hrp encoding))))
