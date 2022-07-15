(uiop:define-package :bp/tests/transaction (:use :cl :fiveam)
  (:use :bp/core/all
        :bp/tests/data)
  (:import-from :bp/core/block
                #:block-header-version))

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

(test coinbase-transaction-validation
  :description "Test that both pre- and post-BIP-0034 coinbase
transactions are validated correctly."
  (with-chain-supplier (test-chain-supplier)
    (loop
       :for (txid height) :in (list (list *coinbase-tx-pre-bip34*  *block-30*)
                                    (list *coinbase-tx-post-bip34* *block-230574*))
       :for tx    := (get-transaction txid)
       :for block := (get-block (get-block-hash height))
       :for validation-context
         := (make-instance 'validation-context :height height :block block :tx-index 0)
       :do (is (validate tx :context validation-context)))))

(test coinbase-transaction-bip-0034-fail
  :description "Test that transaction that does not conform to the
BIP-0034 requirement fails validation in v2 block context."
  (with-chain-supplier (test-chain-supplier)
    (let* ((tx (get-transaction *coinbase-tx-pre-bip34*))
           (height *block-30*)
           (block-hash (get-block-hash height))
           (block (decode 'cblock (encode (get-block block-hash))))
           (validation-context
            (make-instance 'validation-context :height height :block block :tx-index 0)))
      ;; Modify v1 block to have version 0x02.
      (setf (block-header-version (block-header block)) #x02)
      ;; Validation must fail for v2 blocks with no height in coinbase.
      (is (not (validp tx :context validation-context))))))

(test standard-transaction-validation
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
                     *p2wsh-tx*
                     *p2tr-tx*
                     *null-data-tx*)))
      (loop
         :for txid :in txs
         :do (is (validp (get-transaction txid)))))))

(test pre-bip-0016-transaction-validation
  :description "Test that pre-BIP-0016 transaction is valid when
BIP-0016 is manually marked as inactive."
  (with-chain-supplier (test-chain-supplier)
    (let ((pre-bip-0016-tx (get-transaction *pre-bip-0016-tx*)))
      ;; Must be valid when BIP-0016 is inactive.
      (let ((*bip-0016-active-p* nil))
        (is (validp pre-bip-0016-tx)))
      ;; Must fail when BIP-0016 is active.
      (let ((*bip-0016-active-p* t))
        (is (not (validp pre-bip-0016-tx)))))))
