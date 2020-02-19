(uiop:define-package :bp/tests/block (:use :cl :fiveam)
  (:use :bp/core/all
        :bp/tests/data))

(in-package :bp/tests/block)

(def-suite block-tests
    :description "Tests for block parsing, serialization and
component extraction/computation.")

(in-suite block-tests)

(test parsing/serialization-isomorphism
  :description "Test that the serialization of the parsed hex
block blob is the same as the original blob."
  (with-chain-supplier (test-chain-supplier)
    (loop
       :for height :in *all-test-blocks*
       :for blockhex := (get-block (get-block-hash height) :encoded t)
       :do (is (equal (encode (decode 'cblock blockhex)) blockhex)))))

(test simple-block-validation
  :description "Test that blocks are validated correctly accroding to
implemented consensus rules."
  (with-chain-supplier (test-chain-supplier)
    (let ((blocks (list *block-30* *block-230574*)))
      (loop
         :for block-height :in blocks
         :do (is (validp (get-block (get-block-hash block-height))))))))
