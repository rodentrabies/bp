(uiop:define-package :bp/core/encoding
    (:use :cl :ironclad)
  (:export
   #:serialize
   #:deserialize
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

(defun to-hex (entity)
  (ironclad:with-octet-output-stream (stream)
    (serialize entity stream)
    (ironclad:byte-array-to-hex-string (ironclad:get-output-stream-octets stream))))

(defun from-hex (entity-class string)
  (ironclad:with-octet-input-stream (stream (ironclad:hex-string-to-byte-array string))
    (deserialize entity-class stream)))

(defun read-bytes (stream size)
  (let ((bytes (make-array size :element-type '(unsigned-byte 8))))
    (read-sequence bytes stream)
    bytes))

(defun write-bytes (bytes stream size)
  (write-sequence bytes stream :start 0 :end size))

(defun read-int (stream &key size byte-order)
  (let ((bytes (read-bytes stream size)))
    (ironclad:octets-to-integer
     (ecase byte-order
       (:big    bytes)
       (:little (reverse bytes))))))

(defun write-int (i stream &key size byte-order)
  (let ((bytes (ironclad:integer-to-octets i)))
    (write-bytes
     (ecase byte-order
       (:big    bytes)
       (:little (reverse bytes)))
     stream
     size)))

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
