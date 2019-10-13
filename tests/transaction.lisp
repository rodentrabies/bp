(uiop:define-package :bp/tests/transaction (:use :cl :fiveam)
  (:use :bp/core/all
        :bp/tests/data))

(in-package :bp/tests/transaction)

(def-suite transaction-tests
    :description "Tests for transaction parsing, serialization and
component extraction/computation.")

(in-suite transaction-tests)

(test parsing/serialization-isomorphism
  :description "Test that the serialization of the parsed hex
transaction blob is the same as the original blob."
  (loop
     :for txid  :in *all-test-transactions*
     :for txhex := (chain-get-transaction :test-chain-supplier txid)
     :do (is (equal (encode (decode 'tx txhex)) txhex))))
