;;; Copyright (c) 2019-2023 BP Developers & Contributors
;;; See the accompanying file LICENSE for the full license governing this code.

(uiop:define-package :bp.tests.crypto
  (:use :cl :fiveam)
  (:use :bp.crypto))

(in-package :bp.tests.crypto)

(def-suite crypto-tests
  :description "Tests for crypto tools.")

(in-suite crypto-tests)

(defun scale-key (scalar seckey)
  (bp.crypto.secp256k1::%make-key
   :bytes
   (ironclad:integer-to-octets
    (mod
     (* scalar (ironclad:octets-to-integer (bp.crypto.secp256k1::key-bytes seckey)))
     #xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141)
    :n-bits #.(* 8 32))))

(test pubkey-combination
  (for-all ((scalar (gen-integer :min 1 :max 10)))
    (let* ((seckey (make-key))
           (pubkey (make-pubkey seckey))
           (combined pubkey)
           (scaled-sec (scale-key scalar seckey))
           (scaled-pub (make-pubkey scaled-sec)))
      (dotimes (_ (1- scalar))
        (setq combined (combine-pubkeys combined pubkey)))
      (is (equalp scaled-pub combined))
      ;; using reduce vector
      (is (equalp scaled-pub
                  (apply #'combine-pubkeys (make-list scalar :initial-element pubkey)))))))
