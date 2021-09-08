;;; BPRDF - Bitcoin chain data represented as RDF

;; Fail here if the Lisp image is not an AllegroCL one.
#-allegro
(error "Direct AllegroGraph interface only works in AllegroCL.")

;; Load `agraph.fasl' dependency unless it's already present.
#-allegrograph
(load "agraph.fasl")

;;; Finally, load external dependencies `jsown' and `bp' using Quicklisp.
(ql:quickload "jsown")
(ql:quickload "bp")



(defpackage :bp/examples/bprdf
  (:use :cl :bp :db.agraph)
  (:import-from :bp/core/script
                #:*print-script-as-assembly*)
  (:import-from :db.agraph.triple-store-spec
                #:parse-triple-store-specification
                #:ground-store-address-p
                #:ground-store-address-scheme
                #:ground-store-address-host
                #:ground-store-address-port
                #:ground-store-address-user
                #:ground-store-address-password
                #:ground-store-address-catalog
                #:ground-store-address-repo)
  (:import-from :db.agraph.part-constants
                #:+rdf-type-uri+
                #:+xsd-string-uri+
                #:+xsd-integer-upi+)
  (:import-from :db.agraph.http.store
                #:@client)
  (:import-from :db.agraph.http.client
                #:define-namespace)
  (:export #:start-load
           #:stop-load))

(in-package :bp/examples/bprdf)

(defvar *workers* nil
  "A place to store loader processes to be able to conveniently stop
them at once.")

(defconstant +bprdf-vocabulary+ (merge-pathnames "bprdf.ttl" *load-truename*))

(defconstant +bprdf-namespace+ "http://rodentrabies.btc/bprdf#")

(define-condition stop-worker () ())

(defun start-worker (src dst from-height to-height step)
  (handler-case
      (with-open-triple-store (db dst :if-does-not-exist :error)
        (unwind-protect
             (with-chain-supplier (bprpc:node-rpc-connection :url src)
               (with-buffered-triple-adds (db :limit 10000)
                 (load-blocks from-height to-height step)))
          (rollback-triple-store :db db)))
    (stop-worker ())))

(defmacro with-open-remote-triple-store ((var spec &rest args) &body body)
  "Hack-macro that forces a triple store specified by SPEC to be
opened as REMOTE-TRIPLE-STORE."
  (let ((parsed-spec (gensym "parsed-spec")))
    `(let ((,parsed-spec (parse-triple-store-specification ,spec)))
       (assert (ground-store-address-p ,parsed-spec))
       (with-open-triple-store (,var (ground-store-address-repo ,parsed-spec)
                                     :triple-store-class 'remote-triple-store
                                     :scheme (ground-store-address-scheme ,parsed-spec)
                                     :server (ground-store-address-host ,parsed-spec)
                                     :port (ground-store-address-port ,parsed-spec)
                                     :user (ground-store-address-user ,parsed-spec)
                                     :password (ground-store-address-password ,parsed-spec)
                                     :catalog (ground-store-address-catalog ,parsed-spec)
                                     ,@args)
         ,@body))))

(defun start-status-checker (src dst period)
  (with-open-triple-store (db dst :if-does-not-exist :error)
    (let ((node-connection (make-instance 'bprpc:node-rpc-connection :url src)))
      (handler-case
          (loop
            (let* ((timestamp (excl:universal-time-to-string (get-universal-time)))
                   (chain-stats (bprpc:getchaintxstats node-connection))
                   (chain-blocks (jsown:val chain-stats "window_final_block_height"))
                   (chain-txs (jsown:val chain-stats "txcount"))
                   (blocks (sparql:run-sparql "SELECT DISTINCT ?b { ?b a bp:Block }"
                                              :results-format :count))
                   (txs (sparql:run-sparql "SELECT DISTINCT ?b { ?b a bp:Tx }"
                                           :results-format :count))
                   (progress (/ txs chain-txs)))
              (format t "[~a] Blocks: ~a/~a, txs: ~a/~a, progress: ~5$)~%"
                      timestamp blocks chain-blocks txs chain-txs progress)
              (sleep period)
              (rollback-triple-store)))
        (stop-worker ())))))

(defun adjust-workers-and-height (workers height)
  "Determine the best block heights for each worker out of total WORKERS to
continue loading data with minimal overlap (duplication). Return a list of
blocks heights ordered by worker index. If HEIGHT is non-NIL, use it as the
start block, but still avoid duplication."
  (let* ((query "SELECT DISTINCT ?h { ?b bp:blockHeight ?h } ORDER BY ?h")
         (result-list (sparql:run-sparql query :results-format :lists))
         (block-list (mapcar (lambda (r) (part->value (first r))) result-list))
         (last-two-blocks (last block-list 2))
         (worker-heights nil)
         (guessed-workers
           (and (first last-two-blocks) (second last-two-blocks)
                (- (second last-two-blocks) (first last-two-blocks)))))
    ;; It's very unlikely that the workers will be working at the same
    ;; pace, so we will almost certainly have a single "leader"
    ;; worker. This allows us to compute the original number of
    ;; workers to and avoid deduplication.
    (if (and guessed-workers (= guessed-workers 1))
        (setf workers (or workers 1))
        (setf workers (or guessed-workers workers 1)))
    ;; Compute worker heights.
    (loop :for (b0 b1) :on block-list :by #'cdr
          :do (when (or (null b1) (/= (1+ b0) b1))
                (let ((incomplete-block-list (member b0 block-list))
                      (start-block (if (and height (> height b0)) height (+ b0 1))))
                  (loop :for i :below workers
                        :do (loop :for j :from (+ start-block i) :by workers
                                  :do (when (not (member j incomplete-block-list))
                                        (push j worker-heights)
                                        (return))))
                  (return))))
    ;; If WORKER-HEIGHTS is NIL, choose consecutive blocks starting
    ;; from HEIGHT.
    (setf worker-heights
          (if worker-heights
              (sort worker-heights #'<)
              (loop :for i :from (or height 0) :below (+ workers (or height 0))
                    :collect i)))
    ;; Return adjusted number of workers and their corresponding
    ;; starting heights.
    (values workers worker-heights)))

(defun start-load (src dst &key workers cleanp from-height to-height)
  ;; Perform clean setup if explicitly requested or repository does not exist.
  (setf cleanp (or cleanp (not (triple-store-exists-p dst))))
  ;; Workers can only be specified when starting with an empty
  ;; repository. If there already is data in the repo, the workers are
  ;; computed to be the same as before to avoid having to delete
  ;; duplicates on restart.
  (with-open-remote-triple-store (db dst :if-does-not-exist :create)
    ;; Set namespaces, both locally (in Lisp client) and persistently (on the server).
    (register-namespace "bp" +bprdf-namespace+)
    (define-namespace (@client db) "bp" +bprdf-namespace+ :type :repository)
    ;; Compute starting blocks and start loading.
    (multiple-value-bind (workers worker-heights)
        (adjust-workers-and-height workers from-height)
      ;; Perform reinitialization if CLEANP.
      (when cleanp
        (delete-triples :db db)
        (drop-index :gposi)
        (drop-index :gspoi)
        (load-turtle +bprdf-vocabulary+ :db db :commit t))
      ;; Print starting heights and number of workers.
      (format t "[~a] Starting load with ~a worker~p from block~p ~{~a~^, ~}~%"
              (excl:universal-time-to-string (get-universal-time))
              workers workers (length worker-heights) worker-heights)
      ;; Start status checker thread.
      (push (mp:process-run-function
             "BPRDF status checker" #'start-status-checker
             src dst 10)
            *workers*)
      ;; Start workers.
      (dotimes (i workers)
        (push (mp:process-run-function
               (format nil "BPRDF worker ~a" i) #'start-worker
               src dst (nth i worker-heights) to-height workers)
              *workers*)))))

(defun stop-load ()
  (dolist (worker *workers*)
    (ignore-errors
     (mp:process-interrupt worker (lambda () (signal 'stop-worker))))
    (mp:process-join worker))
  (setf *workers* nil)
  (remove-namespace "bp"))

(defun unix-to-date-time (timestamp)
  (excl:universal-time-to-string (excl.osi:unix-to-universal-time timestamp) :format :iso8601))

(defun load-blocks (from-height to-height step)
  ;; Load blocks starting from `FROM-HEIGHT'.
  (macrolet ((%r (name) `(resource ,name "bp"))
             (%l (value datatype) `(literal (format nil "~a" ,value) :datatype ,datatype)))
    (loop
      :for block-height :from from-height :by step
      :while (or (not to-height) (and to-height (< block-height to-height)))
      :do
         (tagbody retry-block
            ;; Load block at a height `HEIGHT'.
            (let ((*print-script-as-assembly* t)
                  (block-hash (get-block-hash block-height)))
              (when (null block-hash) ;; no known block at that height
                (go retry-block))
              (let* ((block-hex (get-block block-hash :encoded t))
                     (block (decode 'cblock block-hex))
                     (block-version (block-version block))
                     (block-size (/ (length block-hex) 2))
                     (block-time (unix-to-date-time (block-timestamp block)))
                     (block-transactions (block-transactions block))
                     (block-transactions-count (length block-transactions))
                     (block-resource (%r (format nil "~a" block-height))))
                ;; Add block information triples.
                (add-triple block-resource +rdf-type-uri+      (%r "Block"))
                (add-triple block-resource (%r "blockHeight")  (%l block-height  +xsd-integer-upi+))
                (add-triple block-resource (%r "blockHash")    (%l block-hash    +xsd-string-uri+))
                (add-triple block-resource (%r "blockVersion") (%l block-version +xsd-integer-upi+))
                (add-triple block-resource (%r "blockSize")    (%l block-size +xsd-integer-upi+))
                (add-triple block-resource (%r "blockTime")    (%l block-time "http://www.w3.org/2001/XMLSchema#dateTime"))
                (add-triple block-resource (%r "blockTxCount") (%l block-transactions-count +xsd-integer-upi+))
                ;; Link previous/next blocks.
                (when (plusp block-height)
                  (let ((previous-block-resource (%r (format nil "~a" (1- block-height)))))
                    (add-triple block-resource          (%r "blockPreviousBlock") previous-block-resource)
                    (add-triple previous-block-resource (%r "blockNextBlock")     block-resource)))
                ;; Load block's transactions.
                (loop :for tx-index :below block-transactions-count :do
                  (let* ((tx (aref block-transactions tx-index))
                         (tx-id (tx-id tx))
                         (tx-version (tx-version tx))
                         (tx-size (/ (length (encode tx)) 2))
                         (tx-locktime (tx-locktime tx))
                         (tx-inputs (tx-inputs tx))
                         (tx-inputs-count (length tx-inputs))
                         (tx-outputs (tx-outputs tx))
                         (tx-outputs-count (length tx-outputs))
                         (tx-resource (%r tx-id)))
                    ;; Link transaction with the block.
                    (add-triple block-resource (%r "blockTx") tx-resource)
                    (add-triple tx-resource    (%r "txIndex") (%l tx-index +xsd-integer-upi+))
                    ;; Add transaction data.
                    (add-triple tx-resource +rdf-type-uri+       (%r "Tx"))
                    (add-triple tx-resource (%r "txID")          (%l tx-id +xsd-string-uri+))
                    (add-triple tx-resource (%r "txVersion")     (%l tx-version +xsd-integer-upi+))
                    (add-triple tx-resource (%r "txSize")        (%l tx-size +xsd-integer-upi+))
                    (add-triple tx-resource (%r "txLockTime")    (%l tx-locktime +xsd-integer-upi+))
                    (add-triple tx-resource (%r "txInputCount")  (%l tx-inputs-count +xsd-integer-upi+))
                    (add-triple tx-resource (%r "txOutputCount") (%l tx-outputs-count +xsd-integer-upi+))
                    ;; Load transaction inputs.
                    (loop :for input-index :below tx-inputs-count :do
                      (let* ((input (aref tx-inputs input-index))
                             (input-prevout-id (txin-previous-tx-id input))
                             (input-prevout-index (txin-previous-tx-index input))
                             (input-sequence (txin-sequence input))
                             (input-script-sig (txin-script-sig input))
                             (input-resource (new-blank-node)))
                        ;; Link input with the transaction.
                        (add-triple tx-resource    (%r "txInput")    input-resource)
                        (add-triple input-resource (%r "inputIndex") (%l input-index +xsd-integer-upi+))
                        ;; Add input data.
                        (add-triple input-resource +rdf-type-uri+        (%r "Input"))
                        (add-triple input-resource (%r "inputSequence")  (%l input-sequence +xsd-integer-upi+))
                        (add-triple input-resource (%r "inputScriptSig") (%l input-script-sig +xsd-string-uri+))
                        ;; Link input with the output that it spends unless this is a coinbase transaction.
                        (when (not (every #'zerop input-prevout-id))
                          (let* ((input-prevout-id-hex (hex-encode (reverse input-prevout-id)))
                                 (input-previous-output (format nil "~a:~a" input-prevout-id-hex input-prevout-index)))
                            (add-triple input-resource (%r "inputPreviousOutput") (%r input-previous-output))))))
                    ;; Load transaction outputs.
                    (loop :for output-index :below tx-outputs-count :do
                      (let* ((output (aref tx-outputs output-index))
                             (output-amount (txout-amount output))
                             (output-script-pubkey (txout-script-pubkey output))
                             (output-resource (%r (format nil "~a:~a" tx-id output-index))))
                        ;; Link output with the transaction.
                        (add-triple tx-resource     (%r "txOutput")    output-resource)
                        (add-triple output-resource (%r "outputIndex") (%l output-index +xsd-integer-upi+))
                        ;; Add output data.
                        (add-triple output-resource +rdf-type-uri+            (%r "Output"))
                        (add-triple output-resource (%r "outputAmount")       (%l output-amount +xsd-integer-upi+))
                        (add-triple output-resource (%r "outputScriptPubkey") (%l output-script-pubkey +xsd-string-uri+))
                        ;; Output type will be non-NIL only for standard scripts.
                        (multiple-value-bind (output-type output-address)
                            (script-standard-p output-script-pubkey :network (network))
                          (when output-type
                            (add-triple output-resource (%r "outputType") (%r (format nil "~a" output-type))))
                          (when output-address
                            (add-triple output-resource (%r "outputAddress") (%r output-address)))))))))))
              ;; Commit all the triples for current block and continue to the
              ;; next one.
              (commit-triple-store))))


#+test
;; On first invocation, choose the number of workers that will utilize
;; the underlying machine to the optimum.
(bp/examples/bprdf:start-load "http://user:password@127.0.0.1:8332"
                              "http://user:password@127.0.0.1:10035/repositories/bprdf"
                              :workers 4 :cleanp t)

#+test
;; In order to stop the load, do:
(bp/examples/bprdf:stop-load)

#+test
;; In order to continue load from the point where it was stopped, do
;; the following (notice that the workers and starting height will be
;; computed from the data):
(bp/examples/bprdf:start-load "http://user:password@127.0.0.1:8332"
                              "http://user:password@127.0.0.1:10035/repositories/bprdf")
