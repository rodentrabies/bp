(uiop:define-package :bp/core/encoding
    (:use :cl :ironclad)
  (:export
   #:serialize
   #:deserialize
   #:to-hex
   #:from-hex))

(in-package :bp/core/encoding)

(defgeneric serialize (entity stream)
  (:documentation "Serialize ENTITY into the stream."))

(defgeneric deserialize (entity-class stream)
  (:documentation "Deserialize bytes from the STREAM into an instance
  of the class named ENTITY-CLASS."))

(defun to-hex (entity)
  (ironclad:with-octet-output-stream (stream)
    (serialize enity stream)
    (ironclad:byte-array-to-hex-string (ironclad:get-output-stream-octets stream))))

(defun from-hex (entity-class string)
  (deserialize entity-class (ironclad:hex-string-to-byte-array string)))
