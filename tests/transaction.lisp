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
  (with-chain-supplier (test-chain-supplier)
    (loop
       :for txid  :in *all-test-transactions*
       :for txhex := (get-transaction txid :encoded t)
       :do (is (equal (encode (decode 'tx txhex)) txhex)))))

(test simple-validation
  :description "Test that the simple validation works for common
transaction types."
  (with-chain-supplier (test-chain-supplier)
    (let ((txs (list *p2pk-tx*
                     *p2ms-tx*
                     *p2pkh-tx*
                     *p2sh-tx*
                     *p2sh-p2wpkh-tx*
                     *p2sh-p2wsh-tx*
                     *p2wpkh-tx*
                     *p2wsh-tx*)))
      (loop
         :for txid :in txs
         :do (is (validp (get-transaction txid)))))))
