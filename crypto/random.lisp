(uiop:define-package :bp/crypto/random (:use :cl)
  (:export
   #:random-bytes))

(in-package :bp/crypto/random)

(defun random-bytes (size)
  (let ((buffer (make-array size :element-type '(unsigned-byte 8))))
    (with-open-file (urandom "/dev/urandom" :element-type '(unsigned-byte 8))
      (read-sequence buffer urandom))
    buffer))
