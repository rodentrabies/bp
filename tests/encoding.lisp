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
  :description "Corner cases for BASE58 encoding."
  (is (string= (base58-encode #()) ""))
  (is (string= (base58-encode #(0)) "1"))
  (is (string= (base58-encode #(0 0 0 0)) "1111"))
  (is (string= (base58-encode #(255)) "5Q")))

(test base58check-corner-cases
  :description "Corner cases for BASE58-CHECK encoding."
  (is (string= (base58check-encode #()) "3QJmnh"))
  (is (string= (base58check-encode #(0)) "1Wh4bh"))
  (is (string= (base58check-encode #(0 0 0 0)) "11114bdQda"))
  (is (string= (base58check-encode #(255)) "VrZDWwe")))

(test base58-decode-errors
  :description "Encoding bad BASE58 strings."
  (signals t (base58-decode "0"))) ;; bad character

(test base58check-decode-errors
  :description "Encoding bad BASE58-CHECK strings."
  (signals base58check-no-checksum-error (base58check-decode ""))
  (signals base58check-bad-checksum-error (base58check-decode "1Wh4bm")))


(def-suite bech32-tests
  :description "Tests for Bech32 encoding.")

(test bech32-isomorphism
  :description "Randomized test that verifies that the BECH32-ENCODE
and BECH32-DECODE functions form an isomorphism."
  (loop
     :for i :below 1000
     :for original-bytes := (random-bytes 100)
     :for bytes := (bech32-decode (bech32-encode "iso" original-bytes))
     :if (not (equalp original-bytes bytes))
     :do (fail "encode(decode(~s)) = ~s" original-bytes bytes))
  (pass "Success."))

(defvar *bech32-valid-test-vectors*
  '(("a" "" "A12UEL5L")
    ("a" "" "a12uel5l")
    ("an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio" ""
     "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs")
    ("abcdef" "00443214c74254b635cf84653a56d7c675be77df" "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw")
    ("1" "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
     "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j")
    ("split" "c5f38b70305f519bf66d85fb6cf03058f3dde463ecd7918f2dc743918f2d"
     "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w")
    ("?" "" "?1ezyfcl")))

(test bech32-valid-test-vectors-encode
  :description "Encoding test for valid Bech32 test vectors from
BIP-0173 document."
  (loop
    :for (hrp hex-data bech32) :in (rest *bech32-valid-test-vectors*)
    :do (is (string= (bech32-encode hrp (hex-decode hex-data)) bech32))))

(test bech32-valid-test-vectors-decode
  :description "Decoding test for valid Bech32 test vectors from
BIP-0173 document."
  (loop
    :for (hrp hex-data bech32) :in *bech32-valid-test-vectors*
    :do (multiple-value-bind (actual-data actual-hrp) (bech32-decode bech32)
          (is (string= (hex-encode actual-data) hex-data))
          (is (string= actual-hrp hrp)))))

(test bech32-invalid-test-vectors-decode
  :description "Decoding test for invalid Bech32 test vectors from
BIP-0173 document."
  ;; (signals bech32-overall-max-length-exceeded-error
  ;;   (bech32-decode "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx"))
  (signals bech32-invalid-hrp-character-error (bech32-decode (format nil "~c1nwldj5" (code-char #x20))))
  (signals bech32-invalid-hrp-character-error (bech32-decode (format nil "~c1axkwrx" (code-char #x7f))))
  (signals bech32-invalid-hrp-character-error (bech32-decode (format nil "~c1eym55h" (code-char #x80))))
  (signals bech32-no-separator-character-error (bech32-decode "pzry9x0s0muk"))
  (signals bech32-no-hrp-error (bech32-decode "1pzry9x0s0muk"))
  (signals bech32-no-hrp-error (bech32-decode "10a06t8"))
  (signals bech32-no-hrp-error (bech32-decode "1qzzfhee"))
  (signals bech32-no-checksum-error (bech32-decode "li1dgmt3"))
  (signals bech32-bad-checksum-error (bech32-decode "A1G7SGD8"))
  (signals bech32-mixed-case-characters-error (bech32-decode "A12ueL5L"))
  (signals error (bech32-decode "x1b4n0q5v"))
  (signals error (bech32-decode (format nil "de1lg7wt~c" (code-char 255)))))
