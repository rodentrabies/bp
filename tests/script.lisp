(uiop:define-package :bp/tests/script
  (:nicknames :bp.tests.script)
  (:use :cl :fiveam)
  (:use :bp/core/all
        :bp/tests/data))

(in-package :bp.tests.script)

(def-suite script-tests
    :description "Various script tests.")

(in-suite script-tests)

(test standard-script-types
  :description "Test that `bp.core.script:script-standard-p' function recognizes
types of standard scripts."
  (with-chain-supplier (test-chain-supplier)
    (loop
      :for (txid oindex expected-script-type expected-address)
        :in `((,*p2pk-tx*      0 :p2pk      nil)
              (,*p2ms-tx*      0 :p2ms      nil)
              (,*null-data-tx* 0 :null-data nil)
              (,*p2pkh-tx*     0 :p2pkh     "13RaXhhzA5119S3r5VG7r2ajbLWhuYdz1C")
              (,*p2sh-tx*      0 :p2sh      "3JALUHKvqB7NToPA2jALntCUWmvsgYMyGj")
              (,*p2wpkh-tx*    0 :p2wpkh    "bc1qdg63zvel9zrc0jk4n4ajzvum9j2sj3fqzpj8um")
              (,*p2wsh-tx*     0 :p2wsh     "bc1qpuz70spdfsfy2ys9x6wulwp9wfz40d3pse93fxge7h79j0hmyaksum9qtm")
              (,*p2tr-tx*      1 :p2tr      "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297"))
      :for script-pubkey := (txout-script-pubkey (tx-output (get-transaction txid) oindex))
      :do (multiple-value-bind (script-type address)
              (script-standard-p script-pubkey :network (network))
            (is (eq expected-script-type script-type))
            (is (equal expected-address address))))))
