(uiop:define-package :bp/tests/data (:use :cl)
  (:use :bp/core/all)
  (:export
   #:test-chain-supplier
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


(defclass test-chain-supplier (chain-supplier chain-supplier-encoded-mixin)
  ()
  (:documentation "TEST-CHAIN-SUPPLIER retrieves chain data from a set
of hash tables defined above."))

;;; Implementation of chain supplier API for test supplier.
(defmethod chain-get-block-hash ((s test-chain-supplier) height &key errorp)
  (declare (ignore errorp)) ;; handled by CHAIN-SUPPLIER-ENCODED-MIXIN
  (gethash height *test-chain-block-hashes*))

(defmethod chain-get-block ((s test-chain-supplier) hash &key encoded errorp)
  (declare (ignore encoded errorp)) ;; handled by CHAIN-SUPPLIER-ENCODED-MIXIN
  (gethash hash *test-chain-blocks*))

(defmethod chain-get-transaction ((s test-chain-supplier) id &key encoded errorp)
  (declare (ignore encoded errorp)) ;; handled by CHAIN-SUPPLIER-ENCODED-MIXIN
  (gethash id *test-chain-transactions*))


(defmacro add-test-block (name &body (height hash hex))
  "Define a variable NAME storing test block index HEIGHT; add
provided block data to the corresponding lookup structures."
  `(progn
     (eval-when (:load-toplevel)
       (setf (gethash ,height *test-chain-block-hashes*) ,hash)
       (setf (gethash ,hash *test-chain-blocks*) ,hex)
       (pushnew ,height *all-test-blocks* :test #'equal))
     (defvar ,name ,height)
     (export ',name)))

(defmacro add-test-transaction (name &body (hash hex))
  "Define a variable NAME storing test transaction hash HASH; add
provided transaction data to the corresponding lookup structures."
  `(progn
     (eval-when (:load-toplevel)
       (setf (gethash ,hash *test-chain-transactions*) ,hex)
       (pushnew ,hash *all-test-transactions* :test #'equal))
     (defvar ,name ,hash)
     (export ',name)))



;;;------------------------------------------------------------------------------
;;; Mainnet transaction examples
;;;
;;; Some examples taken from
;;; https://learnmeabitcoin.com/guide/nulldata

;; P2PK
(add-test-transaction *p2pk-tx*
  "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"
  "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000")

(add-test-transaction *p2pk-tx-parent-0*
  "0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9"
  "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0134ffffffff0100f2052a0100000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000")

;; P2MS
(add-test-transaction *p2ms-tx*
  "ac1d9ed701af32ea52fabd0834acfb1ba4e3584cf0553551f1b61b3d7fb05ee7"
  "0100000001ffc0d6d6b592cd2b4160300a278ea5e250b5055b5536dcfb2da5dcc46022765a00000000694630430220575ddd235a989befbf98f43b008666e56af07be89e47e09d18690c75846fb587021f00830605aa09febc51132001e0dbcad860e54d4657b55aaf961b527a935b8a01210281feb90c058c3436f8bc361930ae99fcfb530a699cdad141d7244bfcad521a1fffffffff03204e0000000000002551210281feb90c058c3436f8bc361930ae99fcfb530a699cdad141d7244bfcad521a1f51ae204e0000000000001976a914a988f8039a203cf86136e0d32b9d77eafa5a6bef88ac46f4d501000000001976a914161d7a3d0ee15c793ab300433192f949d8f3566588ac00000000")

(add-test-transaction *p2ms-tx-parent-0*
  "5a762260c4dca52dfbdc36555b05b550e2a58e270a3060412bcd92b5d6d6c0ff"
  "01000000018dba77f9e7528726564b2838b945fc9e3e5039ee6bc7d505a80947da8aa16a7401000000db00483045022100dea2ac942ce84d60d9780c65efd3bfc268fa88a3a2ad5329bbb2e4e664a2782e02207ced4f32c492de28376008ccd5573f77266ed9a10ecea4bf9c00c032729afcd801483045022100851aa99b7c60ecf70f301d16368830c66ae664d41dd4b675c17908d43cc70afe02206ccacf617a6636904339b8be2f82d7f929eea507d4a3de2900f8d89ed2860e4d0147522102c1380816551e0eaf8d0f20f17efb447b2bf447fe14a1ec9e34638b9627ec584121022df113c0a7331ef2e279648fced275d96c460ae90f71a95c913550701392101a52aeffffffff02a6ded601000000001976a914a988f8039a203cf86136e0d32b9d77eafa5a6bef88ac50d8360a0000000017a91400853cce79a1f5dec78dc28e339c2363aba67ee08700000000")

;; P2PKH
(add-test-transaction *p2pkh-tx*
  "17e590f116d3deeb9b121bbb1c37b7916e6b7859461a3af7edf74e2348a9b347"
  "0100000002f8615378c58a7d7dc1712753d7f45b865fc7326b646183086794127919deee40010000006b48304502210093ab819638f72130d3490f54d50bde8e43fabaa5d58ed6d52a57654f64fc1c25022032ed6e8979d00f723c457fae90fe03fb4d06ee6976472118ab21914c6d9fd3f0012102a7f272f55f142e7dcfdb5baa7e25a26ff6046f1e6c5e107416cc76ac8fb44614ffffffffec41ac4571774182a96b4b2df0a259a37f9a8d61bc5b591646e6ebcc850c18c3010000006b483045022100ab1068c922894dfc9347bf38a6c295da43d4b8428d6fdeb23fdbcabe7a5368110220375fbc1ecac27dbf7b3b3601c903a572f38ed1f81af58294625be74988090d0d012102a7f272f55f142e7dcfdb5baa7e25a26ff6046f1e6c5e107416cc76ac8fb44614ffffffff01ec270500000000001976a9141a963939a331975bfd5952e55528662c11e097a988ac00000000")

(add-test-transaction *p2pkh-tx-parent-0*
  "40eede1979129467088361646b32c75f865bf4d7532771c17d7d8ac5785361f8"
  "01000000000101474da2c469881088770e6ae1a5cceaf8661902d128907ebe8416dd1eaccf8bb50100000017160014c8df305e12daf469a59e21cf66981ff518ec0cdcffffffff023a160000000000001976a91417699035a05a263befef326c02c30bb691c1418c88ac5f390400000000001976a914f67284c8ccb076b685a8e09e665baa0041fd6eaa88ac02473044022077499cadb2cd54a74e0e55632563253fe74a3f0e9a40394a36f727a2255bc84d022050e7cfeeeb02f09bb933c98fe69b6d328a81fd2b582fa4a4b892699ca6fb2ecd012102be4da2a72b963061a0da617d8040239f9464a60e46282e0d46002c072b71c63d00000000")

(add-test-transaction *p2pkh-tx-parent-1*
  "c3180c85ccebe64616595bbc618d9a7fa359a2f02d4b6ba98241777145ac41ec"
  "01000000000101d908b3d7d72dfa44f51ed70a51e0bc483a21246279054563082fc6a705962c9100000000171600147baabece4b4dcd00e80193af8e9e463a710897d2ffffffff02f0050000000000001976a91417699035a05a263befef326c02c30bb691c1418c88ac551b0100000000001976a914f67284c8ccb076b685a8e09e665baa0041fd6eaa88ac02483045022100f52cd21b62295dcfc6ac7b9ca06f6f500d901cc796b62b3e610f8067ac521af202205e6e4441ffdde9f9fe129e212b78d1618ffb49b4c885f5623e941b5cb63db7a901210388b90963b5a6d2cb89c08d02e71bbf6c360ade979395190a98714b591012aa4100000000")

;; P2SH
(add-test-transaction *p2sh-tx*
  "d3adb18d5e118bb856fbea4b1af936602454b44a98fc6c823aedc858b491fc13"
  "01000000011b16e4a8af0831da62d8baae47636e49060049948a3d9b8b9b78eafb853b5a2b010000008b48304502204c3da378d8323a7233892b8050f738da69daf765ddc0d9815d9ad352286b70c2022100dff11c19338daa85ec5b124434de3b4378ebe8c56950348d5f66197af1d04f09014104910ae6c9b41b04d366ea54e920663c691843bb83ef7336cd6a0f79b0ac82ee38d2ca23a24adc2348d82c8ca13f0db885712493e89d88551118a7e80ff66ab23cffffffff01604898000000000017a914b4acb9d78d6a6256964a60484c95de490eaaae758700000000")

(add-test-transaction *p2sh-tx-parent-0*
  "2b5a3b85fbea789b8b9b3d8a94490006496e6347aebad862da3108afa8e4161b"
  "0100000002a72dc3b430eb3efac4fa40e4899a5a256d43e719839ff5bbb37d64aa460a139b010000008a473044022029ea39df07021e5bd8e7061ea03e4e0b65a76ff4ee52377590bc91a59a6d4fe60220360c4d139a1df9370a6cffe38effad76eca5cbda362d721870dc99e355ce1ceb01410431d13860725442111d7c34ddb2f72dd520af52abf5c412531fda0c6f2ab8cd1eb723b877d2e8b5d614cee448959908623bd26cf3437828ec578a3f4eb6f446bdffffffff42a453e333bd5cfceb6f5fb2dc21b224259c11a78fcc0339631af4acea300dbc010000008a47304402206330ce8606aed9d6fa232318d937057a33e9ab92fad9a2b93c6d120c8126b1db0220487adf8d47dcf2a1e75e61237954bb70cbee34fc180577f12ec4a001d2a183cd01410431d13860725442111d7c34ddb2f72dd520af52abf5c412531fda0c6f2ab8cd1eb723b877d2e8b5d614cee448959908623bd26cf3437828ec578a3f4eb6f446bdffffffff02f2867a32000000001976a914bc5d344a3d82deebaeb3f417837d7d0fd1cfa89588ac80969800000000001976a914b2def61c9cfcc2e443a783abc453944a3fb6161688ac00000000")

;; P2SH-P2WPKH
(add-test-transaction *p2sh-p2wpkh-tx*
  "c586389e5e4b3acb9d6c8be1c19ae8ab2795397633176f5a6442a261bbdefc3a"
  "0200000000010140d43a99926d43eb0e619bf0b3d83b4a31f60c176beecfb9d35bf45e54d0f7420100000017160014a4b4ca48de0b3fffc15404a1acdc8dbaae226955ffffffff0100e1f5050000000017a9144a1154d50b03292b3024370901711946cb7cccc387024830450221008604ef8f6d8afa892dee0f31259b6ce02dd70c545cfcfed8148179971876c54a022076d771d6e91bed212783c9b06e0de600fab2d518fad6f15a2b191d7fbd262a3e0121039d25ab79f41f75ceaf882411fd41fa670a4c672c23ffaf0e361a969cde0692e800000000")

(add-test-transaction *p2sh-p2wpkh-tx-parent-0*
  "42f7d0545ef45bd3b9cfee6b170cf6314a3bd8b3f09b610eeb436d92993ad440"
  "0200000001dab020ee0a80a818e4d20a52aa7ba367a0a2d430d22c26ccb4572527e259e14a000000006b4830450221009af6687ea6dc495adfed761c1f78ac30f97879a3ecea704d62cf0e9e1ee99c990220633f9e0dedce631020b343df922cbae0258969135bf5eb8f8757e41eafb683dd0121027d8c99d7d1fbca70c697c82f7acf0fb19c4768cb6cc6b3537e07e476c2bf4444feffffff02c06ced08000000001976a914b7c28f0906b2ac22b270252d7962668bebf9137188ac40eef8050000000017a9142928f43af18d2d60e8a843540d8086b305341339871f5a0700")

;; P2SH-P2WSH
(add-test-transaction *p2sh-p2wsh-tx*
  "605bb7b50e6434ebed79a5056bc84dcc46fc5a5ea62bcb5bae8d61b24bb1416e"
  "010000000001015f3d11469fcad94cb30258c6f05458c71c41e4c64c7f8e22385f68ba89b2f92a010000002322002090daa775d40e40abe0ad575f3a57c38f7ff282e01e3d896ec67640c818515b03ffffffff0260d20300000000001976a9141078a40386941be28a3bcde6e66c74c2b95819ce88ac3d57b5000000000017a91429b5cd80a9e3504833c4047cbe79d2f2d765fe1e870400473044022040e6e48e5b0f87ef605c84cdb64ccb8e281235488a5965331e3196d985e1bb3502204f93532947083bb381a77668988dc26a77ddb286b6e75d63802afd94a20363aa0147304402200583f1c477f07c613439edd2f060b0aa1f1a23d9534bbdb72a92ffbc3bd57b1e02201c1b50c0c0004102b01ce08ddc4dad85946324cbf802ee2e99da11e42b34e8970147522103abd014d467f75f5c7c32de0cc099117a12291afa14ffddcefc35b873d3429c7b21037d4514706a6d5f9b5ef8a1e7badef1044f1555fabe28cbbd1205c8bec6b68d5e52ae00000000")

(add-test-transaction *p2sh-p2wsh-tx-parent-0*
  "2af9b289ba685f38228e7f4cc6e4411cc75854f0c65802b34cd9ca9f46113d5f"
  "01000000000101e5b06e08c451375478ec8a2977831814166e9176703c8eaed1824d6cf5382e89010000002322002090daa775d40e40abe0ad575f3a57c38f7ff282e01e3d896ec67640c818515b03ffffffff02f4800300000000001976a91477614a8fe79a8d062f9ba7b6c0a91de4e53f2c0188ac9d6ab9000000000017a91429b5cd80a9e3504833c4047cbe79d2f2d765fe1e87040047304402206dc03eb5ef49d2ac28b93f146e963d924e853957a319f05f2c245613b32b048d02203dddd55b33b2497f0d24187dc0a4bddb442f30d45457ade61a8d50f58cb3c4a501473044022034b98f2bbe89b726c8faf2de7ee90a4571428467a73b074db913d17cdeb11da902207f6fbeb9fbf8316840534d3b7585d507d470336e7ebd36621b697e064f52c3010147522103abd014d467f75f5c7c32de0cc099117a12291afa14ffddcefc35b873d3429c7b21037d4514706a6d5f9b5ef8a1e7badef1044f1555fabe28cbbd1205c8bec6b68d5e52ae00000000")

;; P2WPKH
(add-test-transaction *p2wpkh-tx*
  "cafee3cf4697040c35ec0f3bd3778e47c569bd4afbdc81f179be9333a1c67afb"
  "02000000000101349c42d8ae7a0c466ff82e2d3a28867e2165c006ce3b4f802027465545aa387d0000000000ffffffff02a8fc0000000000001600146a3511333f288787cad59d7b21339b2c95094520f460000000000000160014f6d9d13d3d3595c2de97975505ce0897bccce83a0247304402205a4151a5dae25be5c482e72c3480ec73683b91b841c68dc4bc931ad26d53372b02205f9285bf077bc7a9fce1abd1d62a128870be649136a27a8b14a964cf956ebfdc0121033fed439a1f0a40ccbc3fc839db7a42fe26b2d90eee923b5212067c25c06e033100000000")

(add-test-transaction *p2wpkh-tx-parent-0*
  "7d38aa4555462720804f3bce06c065217e86283a2d2ef86f460c7aaed8429c34"
  "0200000000010403642bb818b59f029208623f2d123f514ba7b11a54b0cddc6439ffa4e8d0b3040100000000ffffffff4b1fb03d15e3f4f4dc53a90d8adb97bc015364a6c6a2adf0ae460822f89b67b80000000000ffffffff674db468d8fdd3e61e83728268166a7ffa9d692f4c491404f7eb2de6c50f68900000000000ffffffffa4fc0c5fd44007a7f1e1d0ca8f141b80a58892bfe8adac50c3f7944011a8ba9e0000000000ffffffff02a0860100000000001600146a3511333f288787cad59d7b21339b2c95094520b0d63b000000000016001467f13dcb5e7310ab98b09549af96207e4a984cb30247304402206d2b8cc28644ef501c61853c2cd25434d4f4487886fd9ef36f1fb6a62ffaf3af02205c1c54d8861a4f76fbabe2f6f99d43e8b717865b58788aef0881a7342fd8786b01210339ae636ca6f91963982b1baf6a70b8ecc6ba6bace6a248f344b486570eabbda10247304402206d560410c257fb0bfa6036f058897addff3a6f0fb2a27a6b934d24753f1cdf0a022040ad5f3e99d39bf8806e253779eda55f8d422568b87446f192451d993015540601210241d4b926b1ca40f142b0143d7c99c6e127c3f49032ab87d7c8ef4eb092dff4b7024730440220573a8138a6cb01ffcd788848bae3bb743e9c9db10dc099f84139399f887f324302202b134c3d7682f52c62ba8bf8076700a7b7cdd46e22547bfb57941b9790e5f8dc012102b2ef04de0ba24623c8586d9f9192128a515a53b305192073d920b60cb7f573f302483045022100f9bac7d8865c978a91849425f5592a0b2a9b05553f6a645d98353c48bc778c5502206e62bddd12e955fe758762597bc06a5fa3c25a8573fa5323bc08737f189b292001210376bd59b92ea8093ca44dcf4be0785f3373b13c1a15c332ba37d4eafc0939630600000000")

;; ;; P2WSH
(add-test-transaction *p2wsh-tx*
  "148879931a771819833019193600960f0b642cdeebb3b792fd3a12d932b63dc3"
  "01000000000101edc09bae9e24da5239b0c8cb768b0c69521a0a302700c0b537c2c02269239e030000000000ffffffff06fe764b07000000002200200f05e7c02d4c12451205369dcfb825724557b621864b149919f5fc593efb276d22d702000000000017a914d2c68f9e4f968c873706aa9b30f392111ff10446878dbd7a01000000001976a9146acdb302e34ee7f83105ac10a677508db52f305f88ac40787d010000000017a9140c8cc94e35b61b2d1a2e3cad25026e231044abb787e26e26000000000017a9141c03e9a7ca10386d63fd6fa1c0469f9dd2d666e98737df25000000000017a914e2e19fe95dd5b0307db90fdedbf63238b92d3d66870400473044022069fe827f9f065209b215fee5b66f81e4647edc95cc85a578200b43a01b3d0f0c02200b5f06866db692e692bf729a48775de035c9df72cf9d2d49fce6bae6e52fca7e0148304502210087a2f5eb48c9fd53d5edba46d57a222fe511c14c3d1a0ca2138308c39be8600102207be6de0d664a00abc2a99784d9b87e3d045f92cc936ff36047b9a2eba917b3ae0169522102c8b794a9c11edd1a634edbc94b749ae9302300435aec10e78059ad3bac1312772103d87a5b65609dc728e689cd5ceaacf12d04e32a985e421715698b4a58170fb34c2102b457ff23546c467484ec5036785805160e77716f5cf409b378a3b7fdc4ae958f53ae00000000")

(add-test-transaction *p2wsh-tx-parent-0*
  "039e236922c0c237b5c00027300a1a52690c8b76cbc8b03952da249eae9bc0ed"
  "010000000001010af9f5698e762be77fd6a093f7bef62613648890f8eeb7e47ac0a5b1f6aed31c0200000000ffffffff045231930a000000002200207546632adfd1e9c8c70c125f81cbb1c43a04fc02baa2c7c5dff61969445668a6590527000000000017a9146e819ef4a6d15ecb686f70ae57710c23524a54f2872c9d0b00000000001976a914da89e6320dea659bd13fe804b914e39cd5dd346788acd8790c000000000017a914fbd051dffbb15069f228101b71454d14d7b09d5a870400473044022042bf9dafa98e59fa47062cca009bdd5d88432a7fc733e695d42146ff33eeb97d02200cf907b258279812854c92247e81025ee2bb1b16c8a71a75d3912968972a206d0147304402202af055cf4e9957205e1bdf7ed7038f1dfd8aaae5b26f0ee87d6577fb4277112902206b00dbda6b1a904e3c960634f66a2d00d27b9fb78fa24b0b5b85879ed72aea2b0169522102c8b4ebb078f7bf2f7601e293445234d1cdaddff133c0757799093272e82963b02102cc6cd2b1355191d3286b94e22f7bacf9e8e4078fa2795e43b55d4ac2d326293b21033e701ca9294277f54aa4ae014dcd8bfd1f31c9a0bf8a930d6981abc86e3a36c653ae00000000")

;; Coinbase
(add-test-transaction *coinbase-tx-pre-bip34*
  "f5e26c8b82401c585235c572ba8265f16f7d9304ed8e31c198eab571754f5331"
  "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0121ffffffff0100f2052a010000004341042cf59fafd089a348c5834283573608e89a305c60a034604c7d22dde50998f1b9bb74681986ca1884a6b1df8ce7f1b79a2277057de855a634626e7a5851c1e716ac00000000")

(add-test-transaction *coinbase-tx-post-bip34*
  "b6186cd14f96336e6e82e8c80402eca6b3efeea81e6ca4cacbd0f7c89fffa1ad"
  "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0e03ae8403028f00062f503253482fffffffff0150bc039500000000232103b6022a5d51c895ada6cb57b6c5ef01d58adaf50df5a9ac519759681dcc1f1752ac00000000")

(add-test-transaction *block-230574-tx-1-parent-0*
  "a06fa6658bdc45279cbdf856482908b0d491f7894777c8907ffff44ecdfd84ab"
  "0100000005d6ec6a7e9de96df1622840888517f80fe8a7d8cc0cfa8aaadd64ad5aaf8497fc000000008b48304502204e1e48f64cc36037561d25a9bf6caac86298886e8ceea3f5718257707358303802210085c4a652be273455db4411f9b9e240b56c277318c83260ca398024e42ef32e9d0141041a6d0673d511463fac83479073dea50228a887522d6d18f448bc6a6a4d326d868a1c1f423dc1e1a466b53ec550c2657f3f34c96b892561b230e7cc9da3fdc01effffffff45ed9d5df4fb9d8ef7da81bf64653b4dcbb9e0a11dfecc6f6262553519c99fb0000000008a47304402202f914a9909c5115b871df07f2c4a5d742dd8e295bedc51cb9871b822a7d10182022026cb4a802bcca90f0f75c84c07e4a3fdd256848c6ba035407b1582874d10495e01410408a7313db51c6f324116f9084544b6f303a331c5a466aa1ebe128cd88f882789e70c91045cb4d8ea9dfe133c1801e008c8f1164c7f9f5a8e896e0024f7c77c46ffffffffd1cf302ee8a2d25c9e5c425ffcf3ce95fa1350583ea5b2777fea0e185c8a2941000000008a473044022068900aa97d2a96baf34b9a727443c76fe67e658c708f3a1be4b2a3328600d85c0220763a6e905d873a29edc652c89e6083eb7b82e4499b6a8b5ff01dc85d7a0960c1014104c37b557e5e1d49cd4f60260c29b4771590a77592df43ebdb801a7b97c5099ed4399a31fe7acbd15e4c04ad1a9a45017692757d71a1e3930f0f13d6b9996e2b5bffffffff5a2db399f9d27246cfbee1e55b9df2e12a6f2ef715250ebcf63650ddf0653c56010000008b483045022053d4b75c4feb16159bf5c06f65efcf7902ae9a3cbdc5f14151bd8accd7f802f1022100fa65f2de44ad7dc4554116217d66108da458038dad7d56c65733812d18c62c19014104c9fa8a74154211d38541aab3dd9489c09c89c5a9b428dadce4e4230df6daecd526ea315fe0f2abad847de20a38935bac988f4f14d67f12917d797a6d635b49dcffffffffcd24f46c87d6a7fe0f18ca935dd6e8c704a28bebd767c96aa9fdfd4b0f4ae885010000008b483045022100ea626c08244a8450af34c187ef8c39f6ad63735a591f59c374729645f6d10f7502204266a1d1d5516a214dbb5a661c9c97c580a67c0b43fde8b42c7f77d7c4289216014104bbc721e0565c7d39e5c19326723057f6641d97342ebc2b631d1beebcd7d39b80824a36413aa1bca38dbbe91d59c0bdccb8697e07c722dd71b78602fe78184da1ffffffff0237fa1000000000001976a914bbde909d8b9f2ebf65a4676a470d01f317bf616988ac00811b2c000000001976a914f40489fec37cfd5ee61a673c0927577116767fca88ac00000000")

(add-test-transaction *block-230574-tx-1-parent-1*
  "50b64f86f5d4d75b3703550114604d7ab4b156304fdc6006657277a43aeea5a2"
  "0100000001a9e82bdcb78449243c04ebabce927ec6cb0e4a912d02e2c3d4adf7e640178b98000000006b48304502203859e4600b5bd2249682d4ef82e443b3a523fa4a64060497f3cc4c1a18a6c70f02210092f93be288e06a46c19d23365e8023bfcdafe61ea57c31cf8830e6aaebf7724d012103d8da213ab0e4da841bb6c6540354c0bf27bf8d9790a4285502fff67a0c0686d7ffffffff028074d21a000000001976a914a7e5e47c94dbaaac3329bffe737026f4ca87164d88ac883bf730000000001976a914b51057d628a6541e66de553639c8ed0be7a0f7db88ac00000000")

(add-test-transaction *coinbase-unexpected-script-end*
  "afb78b1f5dc2d54dab30e8ec289ba9871c8b39d4c6c5f365c17a81de63cfea4f"
  "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5503db85031800547269706c656d696e696e672e636f6d2d32005167336dfabe6d6decd82d42b0130c89d0c3fa2d24d3140d728c32ab2dd041d457b8847a1ed1eab60100000000000000509329020000000000004e54ffffffff0140f4d796000000001976a914d4b8ae9800f6476cc2c0627c79cbf0e9c9c9d17988ac00000000")



;;;------------------------------------------------------------------------------
;;; Mainnet block examples
;;;

;; Pre-BIP-0034 block.
(add-test-block *block-30*
  30
  "00000000bc919cfb64f62de736d55cf79e3d535b474ace256b4fbb56073f64db"
  "01000000cb9ba5a45252b335fe47a099c8935d01ff8eef2e598c2051631b7ac50000000031534f7571b5ea98c1318eed04937d6ff16582ba72c53552581c40828b6ce2f5cac16849ffff001d080315e80101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0121ffffffff0100f2052a010000004341042cf59fafd089a348c5834283573608e89a305c60a034604c7d22dde50998f1b9bb74681986ca1884a6b1df8ce7f1b79a2277057de855a634626e7a5851c1e716ac00000000")

;; Post-BIP-0034 block.
(add-test-block *block-230574*
  230574
  "0000000000000073b67af9d52d64d264655b74d2d00c24c0e4e6fa5c845004d3"
  "02000000e7e1eefec7b53752490e676dec963bde6909509a07449eeb2401000000000000c858bab9978dc3add04665270454b0ebe055fd5c27b554c7f7b76d581585c78248e96451be2f021a2d575f110201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0e03ae8403028f00062f503253482fffffffff0150bc039500000000232103b6022a5d51c895ada6cb57b6c5ef01d58adaf50df5a9ac519759681dcc1f1752ac000000000100000002ab84fdcd4ef4ff7f90c8774789f791d4b008294856f8bd9c2745dc8b65a66fa0000000008b48304502202886e8aff22d4e439500d4df7a287f6840c99259525ab1ad0b1cc14a553629fd022100e979a09e3a6257307fb808ea465d12923d5122dae20ed10b35883ca474eb76ef0141042b06ef1ab8de8914d145f5727f0d846646e574dcda956f574d29a7a21fa0cb4522f24c1e0cf43ec15404a536bd5c4acd950e1c4e3fefae7f2cc818a5c8885de9ffffffffa2a5ee3aa47772650660dc4f3056b1b47a4d6014015503375bd7d4f5864fb650000000008b483045022100b5ba61dbd51c090a1eea93324d2ec15c1c0aa640950e2c4220e654aed77ebfc002207bc2e79d2a7fedda1f1428cddde48ca0b786a0ed01596f6ab6a773b73c9eeb3a0141046edcf77767e632335f9e3c459daafcb78b945e01d4ca2e7a9bbbd5ce364320601e177a5ccb3a07fd7cba8540b4f9b08526e84103dbb8e4c38a5c3f9bf85f51a6ffffffff028074d21a000000001976a914f96368bbedbfb651443beaa128b7bcb5a07010ac88ace7361000000000001976a9145cd7875f2f9fcbfe3681d3f4dcd04e85668115c888ac00000000")
