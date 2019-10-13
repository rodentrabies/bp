(uiop:define-package :bp/tests/data (:use :cl)
  (:use :bp/core/all)
  (:export
   #:*test-chain-block-hashes*
   #:*test-chain-blocks*
   #:*all-test-blocks*
   #:*test-chain-transactions*
   #:*all-test-transactions*))

(in-package :bp/tests/data)

;;; Storage for test chain supplier.
(defvar *test-chain-block-hashes* (make-hash-table)
  "Hash table mapping block indexes to block hashes.")

(defvar *test-chain-blocks* (make-hash-table :test #'equal)
  "Hash table mapping block hashes to serialized block blobs.")

(defvar *all-test-blocks* (list)
  "List of all registered test block hashes.")

(defvar *test-chain-transactions* (make-hash-table :test #'equal)
  "Hash table mapping transaction ID to serialized transaction blobs.")

(defvar *all-test-transactions* (list)
  "List of all registered test transactions.")


;;; Implementation of chain supplier API for test supplier.
(defmethod chain-get-block-hash ((s (eql :test-chain-supplier)) height)
  (gethash height *test-chain-block-hashes*))

(defmethod chain-get-block ((s (eql :test-chain-supplier)) hash)
  (gethash hash *test-chain-blocks*))

(defmethod chain-get-transaction ((s (eql :test-chain-supplier)) id)
  (gethash id *test-chain-transactions*))


(defmacro add-test-block (name &body (height hash hex))
  "Define a variable NAME storing test block index HEIGHT; add
provided block data to the corresponding lookup structures."
  `(progn
     (eval-when (:load-toplevel)
       (setf (gethash ,height *test-chain-block-hashes*) ,hash)
       (setf (gethash ,hash *test-chain-blocks*) ,hex)
       (push ,height *all-test-blocks*))
     (defvar ,name ,height)))

(defmacro add-test-transaction (name &body (hash hex))
  "Define a variable NAME storing test transaction hash HASH; add
provided transaction data to the corresponding lookup structures."
  `(progn
     (eval-when (:load-toplevel :execute)
       (setf (gethash ,hash *test-chain-transactions*) ,hex)
       (push ,hash *all-test-transactions*))
     (defvar ,name ,hash)))

(add-test-transaction *legacy-tx*
  "17e590f116d3deeb9b121bbb1c37b7916e6b7859461a3af7edf74e2348a9b347"
  "0100000002f8615378c58a7d7dc1712753d7f45b865fc7326b646183086794127919deee40010000006b48304502210093ab819638f72130d3490f54d50bde8e43fabaa5d58ed6d52a57654f64fc1c25022032ed6e8979d00f723c457fae90fe03fb4d06ee6976472118ab21914c6d9fd3f0012102a7f272f55f142e7dcfdb5baa7e25a26ff6046f1e6c5e107416cc76ac8fb44614ffffffffec41ac4571774182a96b4b2df0a259a37f9a8d61bc5b591646e6ebcc850c18c3010000006b483045022100ab1068c922894dfc9347bf38a6c295da43d4b8428d6fdeb23fdbcabe7a5368110220375fbc1ecac27dbf7b3b3601c903a572f38ed1f81af58294625be74988090d0d012102a7f272f55f142e7dcfdb5baa7e25a26ff6046f1e6c5e107416cc76ac8fb44614ffffffff01ec270500000000001976a9141a963939a331975bfd5952e55528662c11e097a988ac00000000")

(add-test-transaction *legacy-tx-parent-0*
  "40eede1979129467088361646b32c75f865bf4d7532771c17d7d8ac5785361f8"
  "01000000000101474da2c469881088770e6ae1a5cceaf8661902d128907ebe8416dd1eaccf8bb50100000017160014c8df305e12daf469a59e21cf66981ff518ec0cdcffffffff023a160000000000001976a91417699035a05a263befef326c02c30bb691c1418c88ac5f390400000000001976a914f67284c8ccb076b685a8e09e665baa0041fd6eaa88ac02473044022077499cadb2cd54a74e0e55632563253fe74a3f0e9a40394a36f727a2255bc84d022050e7cfeeeb02f09bb933c98fe69b6d328a81fd2b582fa4a4b892699ca6fb2ecd012102be4da2a72b963061a0da617d8040239f9464a60e46282e0d46002c072b71c63d00000000")

(add-test-transaction *legacy-tx-parent-1*
  "c3180c85ccebe64616595bbc618d9a7fa359a2f02d4b6ba98241777145ac41ec"
  "01000000000101d908b3d7d72dfa44f51ed70a51e0bc483a21246279054563082fc6a705962c9100000000171600147baabece4b4dcd00e80193af8e9e463a710897d2ffffffff02f0050000000000001976a91417699035a05a263befef326c02c30bb691c1418c88ac551b0100000000001976a914f67284c8ccb076b685a8e09e665baa0041fd6eaa88ac02483045022100f52cd21b62295dcfc6ac7b9ca06f6f500d901cc796b62b3e610f8067ac521af202205e6e4441ffdde9f9fe129e212b78d1618ffb49b4c885f5623e941b5cb63db7a901210388b90963b5a6d2cb89c08d02e71bbf6c360ade979395190a98714b591012aa4100000000")

(add-test-transaction *segwit-tx*
  "c586389e5e4b3acb9d6c8be1c19ae8ab2795397633176f5a6442a261bbdefc3a"
  "0200000000010140d43a99926d43eb0e619bf0b3d83b4a31f60c176beecfb9d35bf45e54d0f7420100000017160014a4b4ca48de0b3fffc15404a1acdc8dbaae226955ffffffff0100e1f5050000000017a9144a1154d50b03292b3024370901711946cb7cccc387024830450221008604ef8f6d8afa892dee0f31259b6ce02dd70c545cfcfed8148179971876c54a022076d771d6e91bed212783c9b06e0de600fab2d518fad6f15a2b191d7fbd262a3e0121039d25ab79f41f75ceaf882411fd41fa670a4c672c23ffaf0e361a969cde0692e800000000")

(add-test-transaction *segwit-tx-parent-0*
  "42f7d0545ef45bd3b9cfee6b170cf6314a3bd8b3f09b610eeb436d92993ad440"
  "0200000001dab020ee0a80a818e4d20a52aa7ba367a0a2d430d22c26ccb4572527e259e14a000000006b4830450221009af6687ea6dc495adfed761c1f78ac30f97879a3ecea704d62cf0e9e1ee99c990220633f9e0dedce631020b343df922cbae0258969135bf5eb8f8757e41eafb683dd0121027d8c99d7d1fbca70c697c82f7acf0fb19c4768cb6cc6b3537e07e476c2bf4444feffffff02c06ced08000000001976a914b7c28f0906b2ac22b270252d7962668bebf9137188ac40eef8050000000017a9142928f43af18d2d60e8a843540d8086b305341339871f5a0700")
