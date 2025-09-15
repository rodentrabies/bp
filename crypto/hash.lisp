;;; Copyright (c) BP Developers & Contributors
;;; See the accompanying file LICENSE for the full license governing this code.

(uiop:define-package :bp.crypto.hash (:nicknames :bp/crypto/hash)
  (:use :cl)
  (:import-from :ironclad)
  (:export
   #:sha1
   #:ripemd160
   #:sha256
   #:hash256
   #:hash160))

(in-package :bp.crypto.hash)

(defun sha1 (bytes)
  #+allegro
  (let ((digest (excl:sha1-init)))
    (excl:sha1-update digest bytes)
    (excl:sha1-final digest :return :usb8))
  #-allegro
  (let ((digester (ironclad:make-digest 'ironclad:sha1)))
    (ironclad:update-digest digester bytes)
    (ironclad:produce-digest digester)))

(defun sha256 (bytes)
  #+allegro
  (let ((digest (excl:sha256-init)))
    (excl:sha256-update digest bytes)
    (excl:sha256-final digest :return :usb8))
  #-allegro
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
