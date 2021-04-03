(uiop:define-package :bp/tests/encoding (:use :cl :fiveam)
  (:use :bp/core/all)
  (:import-from :bp/crypto/random
                #:random-bytes))

(in-package :bp/tests/encoding)

(def-suite encoding-tests
  :description "Tests for various encoding formats used by Bitcoin
Protocol.")

(def-suite base58-tests
  :description "Tests for BASE58/BASE58-CHECK encoding."
  :in encoding-tests)

(in-suite base58-tests)

(test base58-isomorphism
  :description "Randomized test that verifies that the BASE58-ENCODE
and BASE58-DECODE functions form an isomorphism."
  (loop
    :for i :below 1000
    :for original-bytes := (random-bytes 100)
    :for bytes := (base58-decode (base58-encode original-bytes))
    :if (not (equalp original-bytes bytes))
      :do (fail "base58-decode(base58-encode(~s)) = ~s" original-bytes bytes))
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
     :do (fail "base58check-decode(base58check-encode(~s)) = ~s" original-bytes bytes))
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
  :description "Tests for Bech32/Bech32m encoding."
  :in encoding-tests)

(in-suite bech32-tests)

(defun bech32-assert-decode (string &key versionp)
  (multiple-value-bind (bytes hrp encoding)
      (bech32-decode string :versionp versionp)
    (assert (eq encoding :bech32) () "Got Bech32m instead of Bech32.")
    (values bytes hrp encoding)))

(defun bech32m-assert-decode (string &key versionp)
  (multiple-value-bind (bytes hrp encoding)
      (bech32-decode string :versionp versionp)
    (assert (eq encoding :bech32m) () "Got Bech32 instead of Bech32m.")
    (values bytes hrp encoding)))

(defun segwit-version-opcode (number)
  ;; TODO: maybe make this a more general utility in BP/CORE/SCRIPT.
  (if (<= 0 number 16)
      (intern (format nil "~a_~a" 'op number) :keyword)
      (error "Segwit version must be in between 0 and 16.")))

(test bech32-isomorphism
      :description "Randomized test that verifies that the BECH32-ENCODE
and BECH32-DECODE functions form an isomorphism."
      (loop
        :for i :below 1000
        :for original-bytes := (random-bytes 100)
        :for bytes := (bech32-assert-decode (bech32-encode "iso" original-bytes))
        :if (not (equalp original-bytes bytes))
          :do (fail "bech32-decode(bech32-encode(~s)) = ~s" original-bytes bytes))
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
    :do (multiple-value-bind (actual-data actual-hrp actual-encoding)
            (bech32-decode bech32)
          (is (and (eq actual-encoding :bech32)
                   (string= (hex-encode actual-data) hex-data)
                   (string= actual-hrp hrp))))))

(test bech32-invalid-test-vectors-decode
  :description "Decoding test for invalid Bech32 test vectors from
BIP-0173 document."
  ;; (signals bech32-overall-max-length-exceeded-error
  ;;   (bech32-assert-decode "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx"))
  (signals bech32-invalid-hrp-character-error (bech32-assert-decode (format nil "~c1nwldj5" (code-char #x20))))
  (signals bech32-invalid-hrp-character-error (bech32-assert-decode (format nil "~c1axkwrx" (code-char #x7f))))
  (signals bech32-invalid-hrp-character-error (bech32-assert-decode (format nil "~c1eym55h" (code-char #x80))))
  (signals bech32-no-separator-character-error (bech32-assert-decode "pzry9x0s0muk"))
  (signals bech32-no-hrp-error (bech32-assert-decode "1pzry9x0s0muk"))
  (signals bech32-no-hrp-error (bech32-assert-decode "10a06t8"))
  (signals bech32-no-hrp-error (bech32-assert-decode "1qzzfhee"))
  (signals bech32-no-checksum-error (bech32-assert-decode "li1dgmt3"))
  (signals bech32-bad-checksum-error (bech32-assert-decode "A1G7SGD8"))
  (signals bech32-mixed-case-characters-error (bech32-assert-decode "A12ueL5L"))
  (signals error (bech32-assert-decode "x1b4n0q5v"))
  (signals error (bech32-assert-decode (format nil "de1lg7wt~c" (code-char 255)))))

(defvar *bech32-valid-address-test-vectors*
  '(("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4" "bc"
     "160014751e76e8199196d454941c45d1b3a323f1433bd6")
    ("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7" "tb"
     "2200201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262")
    ("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx" "bc"
     "2a5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6")
    ("BC1SW50QA3JX3S" "bc"
     "046002751e")
    ("bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj" "bc"
     "125210751e76e8199196d454941c45d1b3a323")
    ("tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy" "tb"
     "220020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433")))

(test bech32-valid-address-test-vectors-decode
  :description "Decoding test for valid Bech32 address test vectors
from BIP-0173 document."
  (loop
    :for (address expected-hrp expected-script) :in *bech32-valid-address-test-vectors*
    :do (multiple-value-bind (actual-data actual-hrp actual-encoding)
            (bech32-decode address :versionp t)
          (let ((actual-version (aref actual-data 0))
                (actual-script (subseq actual-data 1)))
           (is (and (eq actual-encoding :bech32)
                    (string= actual-hrp expected-hrp)
                    (string=
                     (encode (script (segwit-version-opcode actual-version) actual-script))
                     expected-script)))))))

(test bech32m-isomorphism
  :description "Randomized test that verifies that Bech32m variants of
the BECH32-ENCODE and BECH32-DECODE functions form an isomorphism."
  (loop
    :for i :below 1000
    :for original-bytes := (random-bytes 100)
    :for bytes := (bech32m-assert-decode (bech32-encode "iso" original-bytes :bech32m-p t))
    :if (not (equalp original-bytes bytes))
    :do (fail "bech32m-decode(bech32m-encode(~s)) = ~s" original-bytes bytes))
  (pass "Success."))

(defvar *bech32m-valid-test-vectors*
  '(("a" "" "A1LQFN3A")
    ("a" "" "a1lqfn3a")
    ("an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber1" ""
     "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6")
    ("abcdef" "ffbbcdeb38bdab49ca307b9ac5a928398a418820" "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx")
    ;; ("1" "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    ;;  "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8")
    ("split" "c5f38b70305f519bf66d85fb6cf03058f3dde463ecd7918f2dc743918f2d"
     "split1checkupstagehandshakeupstreamerranterredcaperredlc445v")
    ("?" "" "?1v759aa")))

(test bech32m-valid-test-vectors-encode
  :description "Encoding test for valid Bech32m test vectors from
BIP-0350 document."
  (loop
    :for (hrp hex-data bech32m) :in (rest *bech32m-valid-test-vectors*)
    :do (is (string= (bech32-encode hrp (hex-decode hex-data) :bech32m-p t) bech32m))))

(test bech32m-valid-test-vectors-decode
  :description "Decoding test for valid Bech32m test vectors from
BIP-0350 document."
  (loop
    :for (hrp hex-data bech32m) :in *bech32m-valid-test-vectors*
    :do (multiple-value-bind (actual-data actual-hrp actual-encoding) (bech32-decode bech32m)
          (is (and (eq actual-encoding :bech32m)
                   (string= actual-hrp hrp)
                   (string= (hex-encode actual-data) hex-data))))))

(test bech32m-invalid-test-vectors-decode
  :description "Decoding test for invalid Bech32m test vectors from
BIP-0350 document."
  ;; (signals bech32-overall-max-length-exceeded-error
  ;;   (bech32-decode "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4"))
  (signals bech32-invalid-hrp-character-error (bech32m-assert-decode (format nil "~c1xj0phk" (code-char #x20))))
  (signals bech32-invalid-hrp-character-error (bech32m-assert-decode (format nil "~c1g6xzxy" (code-char #x7f))))
  (signals bech32-invalid-hrp-character-error (bech32m-assert-decode (format nil "~c1vctc34" (code-char #x80))))
  (signals bech32-no-separator-character-error (bech32m-assert-decode "qyrz8wqd2c9m"))
  (signals bech32-no-hrp-error (bech32m-assert-decode "1qyrz8wqd2c9m"))
  (signals bech32-no-hrp-error (bech32m-assert-decode "16plkw9"))
  (signals bech32-no-hrp-error (bech32m-assert-decode "1p2gdwpf"))
  (signals bech32-no-checksum-error (bech32m-assert-decode "in1muywd"))
  (signals bech32-bad-checksum-error (bech32m-assert-decode "M1VUXWEZ"))
  (signals bech32-mixed-case-characters-error (bech32m-assert-decode "A1LqfN3A"))
  (signals error (bech32m-assert-decode "y1b0jsk6g"))
  (signals error (bech32m-assert-decode "lt1igcx5c0")))


(defvar *bech32/bech32m-valid-address-test-vectors*
  '(("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4" "bc"
     "160014751e76e8199196d454941c45d1b3a323f1433bd6"
     :bech32)
    ("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7" "tb"
     "2200201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"
     :bech32)
    ("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y" "bc"
     "2a5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"
     :bech32m)
    ("BC1SW50QGDZ25J" "bc"
     "046002751e"
     :bech32m)
    ("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs" "bc"
     "125210751e76e8199196d454941c45d1b3a323"
     :bech32m)
    ("tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy" "tb"
     "220020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"
     :bech32)
    ("tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c" "tb"
     "225120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"
     :bech32m)
    ("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0" "bc"
     "22512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
     :bech32m)))

(test bech32m-valid-address-test-vectors-decode
  :description "Decoding test for valid Bech32m address test vectors
from BIP-0350 document."
  (loop
    :for (address expected-hrp expected-script expected-encoding)
      :in *bech32/bech32m-valid-address-test-vectors*
    :do (multiple-value-bind (actual-data actual-hrp actual-encoding)
            (bech32-decode address :versionp t)
          (let ((actual-version (aref actual-data 0))
                (actual-script (subseq actual-data 1)))
            (is (and (eq actual-encoding expected-encoding) (string= actual-hrp expected-hrp)
                     (string=
                      (encode (script (segwit-version-opcode actual-version) actual-script))
                      expected-script)))))))
