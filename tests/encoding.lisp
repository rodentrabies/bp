(uiop:define-package :bp/tests/encoding (:use :cl :fiveam)
  (:use :bp/core/all)
  (:import-from :bp/crypto/random
                #:random-bytes))

(in-package :bp/tests/encoding)

(def-suite base58-tests
    :description "Tests for BASE58/BASE58-CHECK encoding.")

(in-suite base58-tests)

(test base58-isomorphism
  :description "Randomized test that verifies that the BASE58-ENCODE
and BASE58-DECODE functions form an isomorphism."
  (loop
     :for i :below 1000
     :for original-bytes := (random-bytes 100)
     :for bytes := (base58-decode (base58-encode original-bytes))
     :if (not (equalp original-bytes bytes))
     :do (fail "encode(decode(~s)) = ~s" original-bytes bytes))
  (pass "Success."))

(test base58check-isomorphism
  :description "Randomized test that verifies that the
BASE58CHECK-ENCODE and BASE58CHECK-DECODE functions form an
isomorphism."
  (loop
     :for i :below 1000
     :for original-bytes := (random-bytes 100)
     :for bytes := (base58check-decode (base58check-encode original-bytes))
     :if (not (equalp original-bytes bytes))
     :do (fail "encode(decode(~s)) = ~s" original-bytes bytes))
  (pass "Success."))

(test base58-corner-cases
  :description ""
  (is (string= (base58-encode #()) ""))
  (is (string= (base58-encode #(0)) "1"))
  (is (string= (base58-encode #(0 0 0 0)) "1111"))
  (is (string= (base58-encode #(255)) "5Q")))

(test base58check-corner-cases
  :description ""
  (is (string= (base58check-encode #()) "3QJmnh"))
  (is (string= (base58check-encode #(0)) "1Wh4bh"))
  (is (string= (base58check-encode #(0 0 0 0)) "11114bdQda"))
  (is (string= (base58check-encode #(255)) "VrZDWwe")))

(test base58-decode-errors
  :description ""
  (signals t (base58-decode "0"))) ;; bad character

(test base58check-decode-errors
  :description ""
  (signals base58check-no-checksum-error (base58check-decode ""))
  (signals base58check-bad-checksum-error (base58check-decode "1Wh4bm")))
