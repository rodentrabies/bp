(uiop:define-package :bp/core/encoding
    (:use :cl :ironclad)
  (:export
   ;; Serialization API:
   #:serialize
   #:deserialize
   #:encode
   #:decode
   ;; Utilities:
   #:to-hex
   #:from-hex
   #:read-bytes
   #:write-bytes
   #:read-int
   #:write-int
   #:read-varint
   #:write-varint))

(in-package :bp/core/encoding)

(defgeneric serialize (entity stream)
  (:documentation "Serialize ENTITY into the stream."))

(defgeneric deserialize (entity-class stream)
  (:documentation "Deserialize bytes from the STREAM into an instance
  of the class named ENTITY-CLASS."))

(defun encode (entity)
  "Encode Bitcoin Protocol ENTITY into a hex string."
  (ironclad:byte-array-to-hex-string
   (ironclad:with-octet-output-stream (stream)
     (serialize entity stream))))

(defun decode (entity-class string)
  "Decode Bitcoin Protocol entity given by its class name ENTITY-CLASS from hex STRING."
  (ironclad:with-octet-input-stream (stream (ironclad:hex-string-to-byte-array string))
    (deserialize entity-class stream)))

(defun to-hex (bytes)
  "Shortcut to avoid using long symbol IRONCLAD:BYTE-ARRAY-TO-HEX-STRING."
  (ironclad:byte-array-to-hex-string bytes))

(defun from-hex (string)
  "Shortcut to avoid using long symbol IRONCLAD:HEX-STRING-TO-BYTE-ARRAY."
  (ironclad:hex-string-to-byte-array string))

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
