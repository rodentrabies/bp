(uiop:define-package :bp/crypto/hash
    (:use :cl :ironclad)
  (:export
   #:sha1
   #:ripemd160
   #:sha256
   #:hash256
   #:hash160))

(in-package :bp/crypto/hash)

(defun sha1 (bytes)
  (let ((digester (ironclad:make-digest 'ironclad:sha1)))
    (ironclad:update-digest digester bytes)
    (ironclad:produce-digest digester)))

(defun sha256 (bytes)
  (let ((digester (ironclad:make-digest 'ironclad:sha256)))
    (ironclad:update-digest digester bytes)
    (ironclad:produce-digest digester)))

(defun ripemd160 (bytes)
  (let ((digester (ironclad:make-digest 'ironclad:ripemd-160)))
    (ironclad:update-digest digester bytes)
    (ironclad:produce-digest digester)))

(defun hash256 (bytes)
  (sha256 (sha256 bytes)))

(defun hash160 (bytes)
  (ripemd160 (sha256 bytes)))
