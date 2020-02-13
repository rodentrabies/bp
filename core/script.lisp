(uiop:define-package :bp/core/script (:use :cl)
  (:use
   :bp/core/encoding
   :bp/crypto/hash
   :bp/crypto/secp256k1)
  (:export
   #:script
   #:decode-integer
   #:encode-integer
   #:make-script
   #:make-script-state
   #:script-commands
   #:execute-scripts
   #:execute-script
   #:*trace-script-execution*))

(in-package :bp/core/script)

(defstruct script
  commands)

(defvar *opcodes-by-code* (make-hash-table)
  "Table mapping opcodes to pairs (<list of opcode-names> . <function>).")

(defvar *opcodes-by-name* (make-hash-table)
  "Table mapping opcode names to pairs (<code> . <function>).")

(defun opcode (opcode/name)
  "For a given OPCODE/NAME return (VALUES <code> <function>) if
OPCODE/NAME is a keyword, and (VALUES <list of names> <function>)
otherwise."
  (let* ((table (if (typep opcode/name 'symbol)
                    *opcodes-by-name*
                    *opcodes-by-code*))
         (table-entry (gethash opcode/name table)))
    (if table-entry
        (values (car table-entry) (cdr table-entry))
        (error "Unknown opcode ~a." opcode/name))))

(defun register-opcode (code name &optional function)
  (let ((name (intern (string name) :keyword)))
    (if function
        ;; If FUNCTION is present, this is opcode definition.
        (setf (gethash code *opcodes-by-code*) (cons (list name) function)
              (gethash name *opcodes-by-name*) (cons code        function))
        ;; Otherwise, this is an opcode alias definition.
        (push name (car (gethash code *opcodes-by-code*))))))

(defmethod serialize ((script script) stream)
  (let* ((commands (script-commands script))
         (script-bytes
          (ironclad:with-octet-output-stream (script-stream)
            (loop
               :for op :across commands
               :if (and (consp op) (eq (car op) :unexpected_end))
               :do
                 (write-bytes (cdr op) script-stream (length (cdr op)))
               :else
               :if (and (consp op) (<= (opcode :op_push1) (car op) (opcode :op_push75)))
               :do
                 (write-byte (car op) script-stream)
                 (write-bytes (cdr op) script-stream (length (cdr op)))
               :else
               :if (and (consp op) (<= (opcode :op_pushdata1) (car op) (opcode :op_pushdata4)))
               :do
                 (let ((int-size (cond ((= (car op) (opcode :op_pushdata1)) 1)
                                       ((= (car op) (opcode :op_pushdata2)) 2)
                                       ((= (car op) (opcode :op_pushdata4)) 4))))
                   (write-byte (car op) script-stream)
                   (write-int (length (cdr op)) script-stream :size int-size :byte-order :little)
                   (write-bytes (cdr op) script-stream (length (cdr op))))
               :else
               :do
                 (write-byte op script-stream))))
         (script-length (length script-bytes)))
    (write-varint script-length stream)
    (write-bytes script-bytes stream script-length)))

(defmethod parse ((entity-name (eql 'script)) stream)
  (let* ((script-len (read-varint stream))
         (script-bytes (read-bytes stream script-len))
         (commands (list)))
    (ironclad:with-octet-input-stream (script-stream script-bytes)
      (loop
         :with i := 0 :while (< i script-len)
         :for op := (read-byte script-stream)
         :if (<= (opcode :op_push1) op (opcode :op_push75))
         :do
           (let* ((expected-read-size op)
                  (unexpected-end-p (> (+ i 1 expected-read-size) script-len))
                  (read-size (min expected-read-size (- script-len i 1))))
             (if unexpected-end-p
                 (ironclad:with-octet-input-stream (script-stream script-bytes i) ;; hacky way to seek
                   (push (cons :unexpected_end (read-bytes script-stream (1+ read-size))) commands))
                 (push (cons op (read-bytes script-stream read-size)) commands))
             (incf i (+ 1 read-size)))
         :else
         :if (<= (opcode :op_pushdata1) op (opcode :op_pushdata4))
         :do
           (let* ((expected-int-size (cond ((= op (opcode :op_pushdata1)) 1)
                                           ((= op (opcode :op_pushdata2)) 2)
                                           ((= op (opcode :op_pushdata4)) 4)))
                  (unexpected-end-p (> (+ i 1 expected-int-size) script-len))
                  (int-size (min expected-int-size (- script-len i 1))))
             (if unexpected-end-p
                 (ironclad:with-octet-input-stream (script-stream script-bytes i) ;; hacky way to seek
                   (push (cons :unexpected_end (read-bytes script-stream (1+ int-size))) commands))
                 (let* ((expected-read-size (read-int script-stream :size int-size :byte-order :little))
                        (unexpected-end-p (> (+ i 1 int-size expected-read-size) script-len))
                        (read-size (min expected-read-size (- script-len i 1 int-size))))
                   (if unexpected-end-p
                       (ironclad:with-octet-input-stream (script-stream script-bytes i) ;; hacky way to seek
                         (push (cons :unexpected_end (read-bytes script-stream (+ 1 int-size read-size))) commands))
                       (push (cons op (read-bytes script-stream read-size)) commands))
                   (incf i read-size)))
             (incf i (+ 1 int-size)))
         :else
         :do
           (push op commands)
           (incf i)))
    (make-script :commands (coerce (reverse commands) 'vector))))

(defmethod print-object ((script script) stream)
  (flet ((print-command (c)
           (cond ((and (consp c) (eq (car c) :unexpected_end))
                  (format nil "UNEXPECTED_END ~a" (to-hex (cdr c))))
                 ((consp c)
                  (format nil "~{~a~^/~} ~a" (opcode (car c)) (to-hex (cdr c))))
                 (t
                  (format nil "~{~a~^/~}" (opcode c))))))
   (print-unreadable-object (script stream :type t)
     (format stream "<~{~a~^ ~}>"
             (map 'list #'print-command (script-commands script))))))

(defun script (&rest symbolic-commands)
  "Construct a SCRIPT object from a sequence of Lisp objects, doing
the best effort to detect/convert the provided values."
  (flet ((command (symbolic-command)
           (etypecase symbolic-command
             ((or array string)
              (let* ((data
                      (if (stringp symbolic-command)
                          (from-hex symbolic-command)
                          symbolic-command))
                     (data-length (length data)))
                (cons (cond ((> data-length 520)
                             (error "Data element is too long."))
                            ((< data-length 76)
                             data-length)
                            ((< (integer-length data-length) 8)
                             (opcode :op_pushdata1))
                            ((< (integer-length data-length) 16)
                             (opcode :op_pushdata2))
                            #+ignore
                            ((< (integer-length data-length) 32)
                             (opcode :op_pushdata4)))
                      data)))
             (cons
              (let* ((symbolic-op (car symbolic-command))
                     (op (if (symbolp symbolic-op)
                             (first (opcode symbolic-op))
                             symbolic-op)))
               (cons op (cdr symbolic-command))))
             (keyword
              (opcode symbolic-command)))))
    (make-script :commands (map 'vector #'command symbolic-commands))))

(defstruct (script-state (:conc-name @))
  commands
  discard
  stack
  altstack
  conditions
  witness
  sighashf
  sigversion)

(defun @execp (state op)
  "A command is considered executable if current branch is an
executable one (i.e. the current code path does not contain false
conditions), or it is a branching command.

For this purpose, OP_IF pushes its condition to CONDITIONS stack in
script state (OP_NOTIF pushes an inverted condition), OP_ELSE inverts
the top condition in CONDITIONS, while OP_ENDIF simply pops the top
condition. For OP_ELSE/OP_ENDIF commands, empty CONDITIONS stack means
that the branching construction is unbalanced.

This follows the implementation of script interpreter in Bitcoin
Core."
  (or (not (member nil (@conditions state)))
      (<= (opcode :op_if) op (opcode :op_endif))))

(defun @sighash (state hashtype)
  (let* ((prefix     (reverse (@discard state)))
         (suffix     (@commands state))
         (commands   (concatenate 'vector suffix prefix))
         (scriptcode (make-script :commands commands))
         (sigversion (@sigversion state)))
    (funcall (@sighashf state) scriptcode hashtype sigversion)))

(defun decode-integer (bytes)
  (if (not (zerop (length bytes)))
      (let ((rbytes (reverse bytes)))
        (multiple-value-bind (negative-p integer)
            (if (zerop (logand (aref rbytes 0) #x80))
                (values nil (aref rbytes 0))
                (values t (logand (aref rbytes 0) #x7f)))
          (loop
             :for i :from 1 :below (length rbytes)
             :do (setf integer (+ (ash integer 8) (aref rbytes i)))
             :finally (setf integer (if negative-p (- integer) integer)))
          integer))
      0))

(defun encode-integer (integer)
  (if (not (zerop integer))
      (let* ((negative-p (< integer 0))
             (ainteger (abs integer))
             (num-bytes (ceiling (integer-length ainteger) 8))
             (bytes
              (make-array (1+ num-bytes)
                          :element-type '(unsigned-byte 8)
                          :fill-pointer 0)))
        (loop
           :for i :below num-bytes
           :for byte :from 0 :by 8
           :do (vector-push (ldb (byte 8 byte) ainteger) bytes)
           :finally (if (zerop (logand (aref bytes (1- i)) #x80))
                        (when negative-p
                          (setf (aref bytes (1- i))
                                (logior (aref bytes (1- i)) #x80)))
                        (if negative-p
                            (vector-push #x80 bytes)
                            (vector-push #x00 bytes))))
        bytes)
      #()))

(defun command-op (command)
  (if (consp command)
      (car command)
      command))

(defun command-payload (command)
  (if (consp command)
      (cdr command)
      nil))

(defvar *trace-script-execution* nil
  "Dynamic variable to control printing the steps of script execution.")

(defun print-script-execution-state (current-command state)
  (flet ((command-op-name (command)
           (string-upcase (first (opcode (command-op command)))))
         (hex-sequence (bytes)
           (map 'vector (lambda (b) (format nil "~x" b)) bytes)))
    (format
     t "op:       ~a~@
        payload:  ~a~@
        commands: <~{~a~^ ~}>~@
        stack:    ~a~%~%"
     (command-op-name current-command)
     ;; Print hex-encoded payload, if current command is a push
     ;; command, or '-' character otherwise.
     (if (command-payload current-command)
         (hex-sequence (command-payload current-command))
         "-")
     ;; Print command names, omitting payloads.
     (mapcar #'command-op-name (@commands state))
     ;; Print stack or '()' if the stack is empty.
     (if (@stack state)
         (mapcar #'hex-sequence (@stack state))
         "()"))))

(defun execute-script (script &key state)
  "Execute a script using a state that can be provided externally."
  (let ((state (or state (make-script-state))))
    (setf (@commands state) (coerce (script-commands script) 'list))
    (setf (@discard state) nil)
    (setf (@conditions state) nil)
    (loop
       :for command := (pop (@commands state))
       :while command
       :for op := (command-op command)
       :for payload := (command-payload command)
       :for op-function := (nth-value 1 (opcode op))
       ;; Check if current branch is executable.
       :for execp := (@execp state op)
       ;; Save current command in the discard to be able to compute
       ;; the hashcode.
       :do (push command (@discard state))
       ;; When *TRACE-SCRIPT-EXECUTION* dynamic variable is true,
       ;; print the current step of script execution.
       :when (and *trace-script-execution* execp)
       :do (print-script-execution-state command state)
       ;; Execute command only if current branch is executable.
       :when execp
       ;; Non-push command.
       :if (null payload)
       :do
         (unless (funcall op-function state)
           (error "Script error: 0x~2,'0x (~{~a~^/~})." op (opcode op)))
       ;; Push command.
       :else
       :do
         (push payload (@stack state)))
    (values (and (not (@conditions state))
                 (not (zerop (length (@stack state))))
                 (not (equalp (first (@stack state)) #())))
            (mapcar #'decode-integer (@stack state)))))

(defun p2sh-p (script-pubkey)
  "Check if current SCRIPT-PUBKEY indicates the BIP 0016 (p2sh)
pattern:
    <redeem-script>
    OP_HASH160
    <hash160>
    OP_EQUAL"
  ;; TODO: this must also check block timestamp > 1333238400
  (let ((commands (script-commands script-pubkey)))
    (and (= (length commands) 3)
         (= (command-op (aref commands 0)) (opcode :op_hash160))
         (= (command-op (aref commands 1)) (opcode :op_push20))
         (= (command-op (aref commands 2)) (opcode :op_equal)))))

(defun segwit-p (script-pubkey)
  "Check if given SCRIPT-PUBKEY indicates the BIP 0141 (Segregated
Witness) structure:
    <version-byte>    (1 byte, OP_{0..16})
    <witness-program> (2-40 bytes)"
  (let ((commands (script-commands script-pubkey)))
    (when (= (length commands) 2)
      (let ((version (command-op (aref commands 0)))
            (program (command-payload (aref commands 1))))
        (and
         ;; Version byte must be in {OP_0, OP_1, ..., OP_16}.
         (or (= version (opcode :op_0))
             (<= (opcode :op_1) version (opcode :op_16)))
         ;; Witness program must be between 2 and 40 bytes.
         (<= 2 (length program) 40))))))

(defun p2wpkh-p (script-pubkey)
  "Check if given SCRIPT-PUBKEY indicates a Pay to Witness Public Key Hash
script structure:
    <version-byte>
    <20-byte witness-program>"
  (and
   (segwit-p script-pubkey)
   (=  0 (aref (script-commands script-pubkey) 0))
   (= 20 (length (command-payload (aref (script-commands script-pubkey) 1))))))

(defun p2wsh-p (script-pubkey)
  "Check if given SCRIPT-PUBKEY indicates a Pay to Witness Script Hash
script structure:
    <version-byte>
    <20-byte witness-program>"
  (and
   (segwit-p script-pubkey)
   (=  0 (aref (script-commands script-pubkey) 0))
   (= 32 (length (command-payload (aref (script-commands script-pubkey) 1))))))

(defun execute-p2sh (script-pubkey &key state)
  (let ((redeem-data (first (@stack state))))
    ;; Execute SCRIPT-PUBKEY to verify that the hash matches.
    (execute-script script-pubkey :state state)
    ;; Verify that OP_EQUAL returned True.
    (when (equalp (pop (@stack state)) #())
      (error "P2SH error: hash mismatch."))
    ;; Hash matches, so add redeem script to the command set.
    (let* ((redeem-script-length (length redeem-data))
           (redeem-script-bytes
            (ironclad:with-octet-output-stream (stream)
              (write-varint redeem-script-length stream)
              (write-bytes redeem-data stream redeem-script-length))))
      ;; Parse and execute the redeem-script.
      (ironclad:with-octet-input-stream (stream redeem-script-bytes)
        (let ((redeem-script (parse 'script stream)))
          ;; Override the sigversion set in EXECUTE-SCRIPTS.
          (setf (@sigversion state) (script-sigversion redeem-script))
          (cond
            ;; P2SH-P2WPKH (P2WPKH nested in P2SH).
            ((p2wpkh-p redeem-script)
             (execute-p2wpkh redeem-script :state state))
            ;; P2SH-P2WSH (P2WSH nested in P2SH).
            ((p2wsh-p redeem-script)
             (execute-p2wsh redeem-script :state state))
            ;; Regular P2SH.
            (t
             (execute-script redeem-script :state state))))))))

(defun execute-p2wpkh (script-pubkey &key state)
  (let* ((witness (@witness state))
         (witness-stack (coerce witness 'list)))
    (when (execute-script (apply #'script witness-stack) :state state)
      (let ((witness-program (aref (script-commands script-pubkey) 1)))
        (execute-script
         (script
          :op_dup :op_hash160 witness-program :op_equalverify :op_checksig)
         :state state)))))

(defun execute-p2wsh (script-pubkey &key state)
  (let* ((witness (@witness state))
         (witness-length (length witness))
         (witness-stack (coerce (subseq witness 0 (1- witness-length)) 'list)))
    ;; Execute WITNESS-STACK to push data items to stack. We don't
    ;; care if returned value is non-false.
    (execute-script (apply #'script witness-stack) :state state)
    ;; Verify that SHA256(<witness-script>) is equal to
    ;; <witness-program>, decode and execute witness script.
    (let* ((witness-script-data (aref witness (- witness-length 1)))
           (witness-script-length (length witness-script-data))
           (witness-script-bytes
            (ironclad:with-octet-output-stream (stream)
              (write-varint witness-script-length stream)
              (write-bytes witness-script-data stream witness-script-length)))
           (witness-program
            (command-payload (aref (script-commands script-pubkey) 1))))
      (when (not (equalp (sha256 witness-script-data) witness-program))
        (error "P2WSH error: hash mismatch."))
      (ironclad:with-octet-input-stream (stream witness-script-bytes)
        (execute-script (parse 'script stream) :state state)))))

(defun script-sigversion (script)
  "For non-SegWit transactions, signature version is represented as
constant :BASE, and for SegWit ones - :WITNESS-V<N>, where N is the
first op of the witness script pubkey."
  (if (segwit-p script)
      (ecase (command-op (aref (script-commands script) 0))
        (0 :witness-v0))
      :base))

(defun execute-scripts (script-sig script-pubkey &key state)
  "Execute SCRIPT-SIG and SCRIPT-PUBKEY in succession, preserving the
stack and performing the special rule detection (P2SH, SegWit)."
  (let ((state (or state (make-script-state))))
    ;; Execute SCRIPT-SIG - it doen't have to leave the stack in
    ;; non-false state, so we ignore the value.
    (execute-script script-sig :state state)
    ;; This is correct for all types of scripts except P2SH. Will be
    ;; overwritten in EXECUTE-P2SH.
    (setf (@sigversion state) (script-sigversion script-pubkey))
    (cond
      ((p2sh-p script-pubkey)
       (execute-p2sh script-pubkey :state state))
      ((p2wpkh-p script-pubkey)
       (execute-p2wpkh script-pubkey :state state))
      ((p2wsh-p script-pubkey)
       (execute-p2wsh script-pubkey :state state))
      (t
       (execute-script script-pubkey :state state)))))

;;;-----------------------------------------------------------------------------
;;; Operation definitions
;;; Source: https://en.bitcoin.it/wiki/Script

;;; Macros

(defmacro define-opcode (op-name op-code op-hex-code
                         (&rest args)
                         &body (doc &rest body))
  "Define opcode function named OP-NAME for a given OP-CODE.
OP-HEX-CODE is ignored and used only for documentation purposes."
  (declare (ignorable op-hex-code))
  `(progn
     (defun ,op-name ,args
       ,doc
       ,@(or body
             `((declare (ignore state))
               (error "Operation ~a not implemented." ',op-name))))
     (register-opcode ,op-code ',op-name (symbol-function ',op-name))))

(defmacro define-opcode-alias (new-op-name old-op-name)
  `(register-opcode
    (opcode (intern (string ',old-op-name) :keyword))
    ',new-op-name))

(defmacro define-disabled-opcode (op-name op-code op-hex-code
                                  (&rest args)
                                  &body (doc &rest body))
  (declare (ignore body))
  `(define-opcode ,op-name ,op-code ,op-hex-code (,@args)
     ,doc
     (declare (ignore state))
     (error "Opcode is disabled.")))

(defmacro define-opcode-range ((op-name-prefix op-name-start op-name-end)
                               (op-code-start op-code-end)
                               (op-hex-code-start op-hex-code-end)
                               (&rest args) &body body)
  `(progn
     ,@(loop
          :for index :from op-name-start :to op-name-end
          :for code :from op-code-start :to op-code-end
          :for hex-code :from op-hex-code-start :to op-hex-code-end
          :for name := (intern (format nil "~a~a" op-name-prefix index))
          :collect
            `(symbol-macrolet ((range-index ,index))
               (define-opcode ,name ,code ,hex-code (,@args) ,@body)))))

;;; Script: constants

(define-opcode op_0 0 #x00 (state)
  "An empty array of bytes is pushed onto the stack. (This is not a
no-op: an item is added to the stack.)"
  (push (encode-integer 0) (@stack state))
  t)

(define-opcode-alias op_false op_0)

(define-opcode op_1negate 79 #x4f (state)
  "The number -1 is pushed onto the stack."
  (push (encode-integer -1) (@stack state))
  t)

(define-opcode op_1 81 #x51 (state)
  "The number 1 is pushed onto the stack."
  (push (encode-integer 1) (@stack state))
  t)

(define-opcode-alias op_true op_1)

(define-opcode-range (op_ 2 16) (82 96) (#x52 #x60) (state)
  "The number in the word name (2-16) is pushed onto the stack."
  (push (encode-integer range-index) (@stack state))
  t)

;;; Script: push data

(define-opcode-range (op_push 1 75) (1 75) (#x01 #x4b) (state)
  "The next opcode bytes is data to be pushed onto the stack."
  (push (pop (@commands state)) (@stack state)))

(define-opcode op_pushdata1 76 #x4c (state)
  "The next byte contains the number of bytes to be pushed onto the
stack."
  (push (pop (@commands state)) (@stack state)))

(define-opcode op_pushdata2 77 #x4d (state)
  "The next two bytes contain the number of bytes to be pushed onto
the stack in little endian order."
  (push (pop (@commands state)) (@stack state)))

(define-opcode op_pushdata4 78 #x4e (state)
  "The next four bytes contain the number of bytes to be pushed onto
the stack in little endian order."
  (push (pop (@commands state)) (@stack state)))

;;; Script: flow

(define-opcode op_nop 97 #x61 (state)
  "Does nothing."
  (declare (ignore state))
  t)

(define-opcode op_if 99 #x63 (state)
  "If the top stack value is not False, the statements are
executed. The top stack value is removed. See @EXECP for more details
on how branching works."
  (when (>= (length (@stack state)) 1)
    (let ((condition (decode-integer (pop (@stack state)))))
      (push (not (= condition 0)) (@conditions state)))
    t))

(define-opcode op_notif 100 #x64 (state)
  "If the top stack value is False, the statements are executed. The
top stack value is removed. See @EXECP for more details on how
branching works."
  (when (>= (length (@stack state)) 1)
    (let ((condition (decode-integer (pop (@stack state)))))
      (push (= condition 0) (@conditions state)))
    t))

(define-opcode op_else 103 #x67 (state)
  "If the preceding OP_IF or OP_NOTIF or OP_ELSE was not executed then
these statements are and if the preceding OP_IF or OP_NOTIF or OP_ELSE
was executed then these statements are not. See @EXECP for more
details on how branching works."
  (when (@conditions state)
    (push (not (pop (@conditions state))) (@conditions state))
    t))

(define-opcode op_endif 104 #x68 (state)
  "Ends an if/else block. All blocks must end, or the transaction is
invalid. An OP_ENDIF without OP_IF earlier is also invalid. See @EXECP
for more details on how branching works."
  (when (@conditions state)
    (pop (@conditions state))
    t))

(define-opcode op_verify 105 #x69 (state)
  "Marks transaction as invalid if top stack value is not true. The
top stack value is removed."
  (when (>= (length (@stack state)) 1)
    (/= (decode-integer (pop (@stack state))) 0)))

(define-opcode op_return 106 #x6a (state)
  "Marks transaction as invalid. Since bitcoin 0.9, a standard way of
attaching extra data to transactions is to add a zero-value output
with a scriptPubKey consisting of OP_RETURN followed by data. Such
outputs are provably unspendable and specially discarded from storage
in the UTXO set, reducing their cost to the network. Since 0.12,
standard relay rules allow a single output with OP_RETURN, that
contains any sequence of push statements (or OP_RESERVED[1]) after the
OP_RETURN provided the total scriptPubKey length is at most 83
bytes."
  (declare (ignore state))
  nil)

;;; Script: stack

(define-opcode op_toaltstack 107 #x6b (state)
  "Puts the input onto the top of the alt stack. Removes it from the
main stack."
  (when (>= (length (@stack state)) 1)
    (push (pop (@stack state)) (@altstack state))
    t))

(define-opcode op_fromaltstack 108 #x6c (state)
  "Puts the input onto the top of the main stack. Removes it from the
alt stack."
  (when (>= (length (@altstack state)) 1)
    (push (pop (@altstack state)) (@stack state))
    t))

(define-opcode op_ifdup 115 #x73 (state)
  "If the top stack value is not 0, duplicate it."
  (when (>= (length (@stack state)) 1)
    (when (not (zerop (decode-integer (first (@stack state)))))
      (push (first (@stack state)) (@stack state)))
    t))

(define-opcode op_depth 116 #x74 (state)
  "Puts the number of stack items onto the stack."
  (push (encode-integer (length (@stack state))) (@stack state))
  t)

(define-opcode op_drop 117 #x75 (state)
  "Removes the top stack item."
  (when (>= (length (@stack state)) 1)
    (pop (@stack state))
    t))

(define-opcode op_dup 118 #x76 (state)
  "Duplicates the top stack item."
  (when (>= (length (@stack state)) 1)
    (push (first (@stack state)) (@stack state))
    t))

(define-opcode op_nip 119 #x77 (state)
  "Removes the second-to-top stack item."
  (when (>= (length (@stack state)) 2)
    (setf (cdr (@stack state)) (cddr (@stack state)))
    t))

(define-opcode op_over 120 #x78 (state)
  "Copies the second-to-top stack item to the top."
  (when (>= (length (@stack state)) 2)
    (push (second (@stack state)) (@stack state))
    t))

(define-opcode op_pick 121 #x79 (state)
  "The item n back in the stack is copied to the top."
  (when (>= (length (@stack state)) 1)
    (let ((n (decode-integer (pop (@stack state)))))
      (when (>= (length (@stack state)) (1- n))
        (push (nth (1- n) (@stack state)) (@stack state))
        t))))

(define-opcode op_roll 122 #x7a (state)
  "The item n back in the stack is moved to the top."
  (when (>= (length (@stack state)) 1)
    (let ((n (decode-integer (pop (@stack state)))))
      (when (>= (length (@stack state)) (1- n))
        (let ((e (nth (1- n) (@stack state))))
          (setf (cdr (nthcdr (- n 2) (@stack state))) (nthcdr n (@stack state)))
          (push e (@stack state))
          t)))))

(define-opcode op_rot 123 #x7b (state)
  "The top three items on the stack are rotated to the left."
  (when (>= (length (@stack state)) 3)
    (let ((third (third (@stack state))))
      (setf (cddr (@stack state)) (cdddr (@stack state)))
      (push third (@stack state))
      t)))

(define-opcode op_swap 124 #x7c (state)
  "The top two items on the stack are swapped."
  (when (>= (length (@stack state)) 2)
    (let ((b (pop (@stack state)))
          (a (pop (@stack state))))
      (push b (@stack state))
      (push a (@stack state))
      t)))

(define-opcode op_tuck 125 #x7d (state)
  "The item at the top of the stack is copied and inserted before the
second-to-top item."
  (when (>= (length (@stack state)) 2)
    (setf (cddr (@stack state))
          (cons (first (@stack state)) (cddr (@stack state))))
    t))

(define-opcode op_2drop 109 #x6d (state)
  "Removes the top two stack items."
  (when (>= (length (@stack state)) 2)
    (pop (@stack state))
    (pop (@stack state))
    t))

(define-opcode op_2dup 110 #x6e (state)
  "Duplicates the top two stack items."
  (when (>= (length (@stack state)) 2)
    (let ((b (first (@stack state)))
          (a (second (@stack state))))
      (push a (@stack state))
      (push b (@stack state))
      t)))

(define-opcode op_3dup 111 #x6f (state)
  "Duplicates the top three stack items."
  (when (>= (length (@stack state)) 3)
    (let ((c (first (@stack state)))
          (b (second (@stack state)))
          (a (third (@stack state))))
      (push a (@stack state))
      (push b (@stack state))
      (push c (@stack state))
      t)))

(define-opcode op_2over 112 #x70 (state)
  "Copies the pair of items two spaces back in the stack to the front."
  (when (>= (length (@stack state)) 4)
    (let ((b (third (@stack state)))
          (a (fourth (@stack state))))
      (push a (@stack state))
      (push b (@stack state))
      t)))

(define-opcode op_2rot 113 #x71 (state)
  "The fifth and sixth items back are moved to the top of the stack."
  (when (>= (length (@stack state)) 6)
    (let ((b (fifth (@stack state)))
          (a (sixth (@stack state))))
      (setf (cdr (nthcdr 3 (@stack state))) (nthcdr 6 (@stack state)))
      (push a (@stack state))
      (push b (@stack state))
      t)))

(define-opcode op_2swap 114 #x72 (state)
  "Swaps the top two pairs of items."
  (when (>= (length (@stack state)) 4)
    (let ((b0 (pop (@stack state)))
          (a0 (pop (@stack state)))
          (b1 (pop (@stack state)))
          (a1 (pop (@stack state))))
      (push a0 (@stack state))
      (push b0 (@stack state))
      (push a1 (@stack state))
      (push b1 (@stack state))
      t)))

;;; Script: splice

(define-disabled-opcode op_cat 126 #x7e (state)
  "Concatenates two strings.")

(define-disabled-opcode op_substr 127 #x7f (state)
  "Returns a section of a string.")

(define-disabled-opcode op_left 128 #x80 (state)
  "Keeps only characters left of the specified point in a string.")

(define-disabled-opcode op_right 129 #x81 (state)
  "Keeps only characters right of the specified point in a string.")

(define-opcode op_size 130 #x82 (state)
  "Pushes the string length of the top element of the stack (without
popping it)."
  (when (>= (length (@stack state)) 1)
    (push (encode-integer (length (first (@stack state)))) (@stack state))
    t))

;;; Script: bitwise logic

(define-disabled-opcode op_invert 131 #x83 (state)
  "Flips all of the bits in the input."
  (when (>= (length (@stack state)) 1)
    (let ((a (decode-integer (pop (@stack state)))))
      (push (encode-integer (lognot a)) (@stack state))
      t)))

(define-disabled-opcode op_and 132 #x84 (state)
  "Boolean and between each bit in the inputs."
  (when (>= (length (@stack state)) 2)
    (let ((b (decode-integer (pop (@stack state))))
          (a (decode-integer (pop (@stack state)))))
      (push (encode-integer (logand a b)) (@stack state))
      t)))

(define-disabled-opcode op_or 133 #x85 (state)
  "Boolean or between each bit in the inputs."
  (when (>= (length (@stack state)) 2)
    (let ((b (decode-integer (pop (@stack state))))
          (a (decode-integer (pop (@stack state)))))
      (push (encode-integer (logior a b)) (@stack state))
      t)))

(define-disabled-opcode op_xor 134 #x86 (state)
  "Boolean exclusive or between each bit in the inputs."
  (when (>= (length (@stack state)) 2)
    (let ((b (decode-integer (pop (@stack state))))
          (a (decode-integer (pop (@stack state)))))
      (push (encode-integer (logxor a b)) (@stack state))
      t)))

(define-opcode op_equal 135 #x87 (state)
  "Returns 1 if the inputs are exactly equal, 0 otherwise."
  (when (>= (length (@stack state)) 2)
    (let ((b (pop (@stack state)))
          (a (pop (@stack state))))
      (if (equalp a b)
          (push (encode-integer 1) (@stack state))
          (push (encode-integer 0) (@stack state)))
      t)))

(define-opcode op_equalverify 136 #x88 (state)
  "Same as OP_EQUAL, but runs OP_VERIFY afterward."
  (when (op_equal state)
    (op_verify state)))

;;; Script: arithmetic

(define-opcode op_1add 139 #x8b (state)
  "1 is added to the input."
  (when (>= (length (@stack state)) 1)
    (let ((a (decode-integer (pop (@stack state)))))
      (push (encode-integer (1+ a)) (@stack state)))
    t))

(define-opcode op_1sub 140 #x8c (state)
  "1 is subtracted from the input."
  (when (>= (length (@stack state)) 1)
    (let ((a (decode-integer (pop (@stack state)))))
      (push (encode-integer (1- a)) (@stack state)))
    t))

(define-disabled-opcode op_2mul 141 #x8d (state)
  "The input is multiplied by 2."
  (when (>= (length (@stack state)) 1)
    (let ((a (decode-integer (pop (@stack state)))))
      (push (encode-integer (* a 2)) (@stack state)))
    t))

(define-disabled-opcode op_2div 142 #x8e (state)
  "The input is divided by 2."
  (when (>= (length (@stack state)) 1)
    (let ((a (decode-integer (pop (@stack state)))))
      (push (encode-integer (/ a 2)) (@stack state)))
    t))

(define-opcode op_negate 143 #x8f (state)
  "The sign of the input is flipped."
  (when (>= (length (@stack state)) 1)
    (let ((a (decode-integer (pop (@stack state)))))
      (push (encode-integer (- a)) (@stack state)))
    t))

(define-opcode op_abs 144 #x90 (state)
  "The input is made positive."
  (when (>= (length (@stack state)) 1)
    (let ((a (decode-integer (pop (@stack state)))))
      (push (encode-integer (abs a)) (@stack state)))
    t))

(define-opcode op_not 145 #x91 (state)
  "If the input is 0 or 1, it is flipped. Otherwise the output will be 0."
  (when (>= (length (@stack state)) 1)
    (let ((a (decode-integer (pop (@stack state)))))
      (push (encode-integer (if (= a 0) 1 0)) (@stack state)))
    t))

(define-opcode op_0notequal 146 #x92 (state)
  "Returns 0 if the input is 0. 1 otherwise."
  (when (>= (length (@stack state)) 1)
    (let ((a (decode-integer (pop (@stack state)))))
      (push (encode-integer (if (= a 0) 0 1)) (@stack state)))
    t))

(define-opcode op_add 147 #x93 (state)
  "a is added to b."
  (when (>= (length (@stack state)) 2)
    (let ((b (decode-integer (pop (@stack state))))
          (a (decode-integer (pop (@stack state)))))
      (push (encode-integer (+ a b)) (@stack state))
      t)))

(define-opcode op_sub 148 #x94 (state)
  "b is subtracted from a."
  (when (>= (length (@stack state)) 2)
    (let ((b (decode-integer (pop (@stack state))))
          (a (decode-integer (pop (@stack state)))))
      (push (encode-integer (- a b)) (@stack state))
      t)))

(define-disabled-opcode op_mul 149 #x95 (state)
  "a is multiplied by b."
  (when (>= (length (@stack state)) 2)
    (let ((b (decode-integer (pop (@stack state))))
          (a (decode-integer (pop (@stack state)))))
      (push (encode-integer (* a b)) (@stack state))
      t)))

(define-disabled-opcode op_div 150 #x96 (state)
  "a is divided by b."
  (when (>= (length (@stack state)) 2)
    (let ((b (decode-integer (pop (@stack state))))
          (a (decode-integer (pop (@stack state)))))
      (push (encode-integer (/ a b)) (@stack state))
      t)))

(define-disabled-opcode op_mod 151 #x97 (state)
  "Returns the remainder after dividing a by b."
  (when (>= (length (@stack state)) 2)
    (let ((b (decode-integer (pop (@stack state))))
          (a (decode-integer (pop (@stack state)))))
      (push (encode-integer (mod a b)) (@stack state))
      t)))

(define-disabled-opcode op_lshift 152 #x98 (state)
  "Shifts a left b bits, preserving sign."
  (when (>= (length (@stack state)) 2)
    (let ((b (decode-integer (pop (@stack state))))
          (a (decode-integer (pop (@stack state)))))
      (push (encode-integer (ash a b)) (@stack state))
      t)))

(define-disabled-opcode op_rshift 153 #x99 (state)
  "Shifts a right b bits, preserving sign."
  (when (>= (length (@stack state)) 2)
    (let ((b (decode-integer (pop (@stack state))))
          (a (decode-integer (pop (@stack state)))))
      (push (encode-integer (ash a (- b))) (@stack state))
      t)))

(define-opcode op_booland 154 #x9a (state)
  "If both a and b are not 0, the output is 1. Otherwise 0."
  (when (>= (length (@stack state)) 2)
    (let ((b (decode-integer (pop (@stack state))))
          (a (decode-integer (pop (@stack state)))))
      (push (encode-integer (if (and (/= a 0) (/= b 0)) 1 0))
            (@stack state))
      t)))

(define-opcode op_boolor 155 #x9b (state)
  "If a or b is not 0, the output is 1. Otherwise 0."
  (when (>= (length (@stack state)) 2)
    (let ((b (decode-integer (pop (@stack state))))
          (a (decode-integer (pop (@stack state)))))
      (push (encode-integer (if (or (/= a 0) (/= b 0)) 1 0))
            (@stack state))
      t)))

(define-opcode op_numequal 156 #x9c (state)
  "Returns 1 if the numbers are equal, 0 otherwise."
  (when (>= (length (@stack state)) 2)
    (let ((b (decode-integer (pop (@stack state))))
          (a (decode-integer (pop (@stack state)))))
      (push (encode-integer (if (= a b) 1 0)) (@stack state))
      t)))

(define-opcode op_numequalverify 157 #x9d (state)
  "Same as OP_NUMEQUAL, but runs OP_VERIFY afterward."
  (when (op_numequal state)
    (op_verify state)))

(define-opcode op_numnotequal 158 #x9e (state)
  "Returns 1 if the numbers are not equal, 0 otherwise."
  (when (>= (length (@stack state)) 2)
    (let ((b (decode-integer (pop (@stack state))))
          (a (decode-integer (pop (@stack state)))))
      (push (encode-integer (if (/= a b) 1 0)) (@stack state))
      t)))

(define-opcode op_lessthan 159 #x9f (state)
  "Returns 1 if a is less than b, 0 otherwise."
  (when (>= (length (@stack state)) 2)
    (let ((b (decode-integer (pop (@stack state))))
          (a (decode-integer (pop (@stack state)))))
      (push (encode-integer (if (< a b) 1 0)) (@stack state))
      t)))

(define-opcode op_greaterthan 160 #xa0 (state)
  "Returns 1 if a is greater than b, 0 otherwise."
  (when (>= (length (@stack state)) 2)
    (let ((b (decode-integer (pop (@stack state))))
          (a (decode-integer (pop (@stack state)))))
      (push (encode-integer (if (> a b) 1 0)) (@stack state))
      t)))

(define-opcode op_lessthanorequal 161 #xa1 (state)
  "Returns 1 if a is less than or equal to b, 0 otherwise."
  (when (>= (length (@stack state)) 2)
    (let ((b (decode-integer (pop (@stack state))))
          (a (decode-integer (pop (@stack state)))))
      (push (encode-integer (if (<= a b) 1 0)) (@stack state))
      t)))

(define-opcode op_greaterthanorequal 162 #xa2 (state)
  "Returns 1 if a is greater than or equal to b, 0 otherwise."
  (when (>= (length (@stack state)) 2)
    (let ((b (decode-integer (pop (@stack state))))
          (a (decode-integer (pop (@stack state)))))
      (push (encode-integer (if (>= a b) 1 0)) (@stack state))
      t)))

(define-opcode op_min 163 #xa3 (state)
  "Returns the smaller of a and b."
  (when (>= (length (@stack state)) 2)
    (let ((b (decode-integer (pop (@stack state))))
          (a (decode-integer (pop (@stack state)))))
      (push (encode-integer (min a b)) (@stack state))
      t)))

(define-opcode op_max 164 #xa4 (state)
  "Returns the larger of a and b."
  (when (>= (length (@stack state)) 2)
    (let ((b (decode-integer (pop (@stack state))))
          (a (decode-integer (pop (@stack state)))))
      (push (encode-integer (max a b)) (@stack state))
      t)))

(define-opcode op_within 165 #xa5 (state)
  "Returns 1 if x is within the specified range (left-inclusive), 0
otherwise."
  (when (>= (length (@stack state)) 3)
    (let ((b (decode-integer (pop (@stack state))))
          (a (decode-integer (pop (@stack state))))
          (e (decode-integer (pop (@stack state)))))
      (push (encode-integer (if (and (>= e a) (< e b)) 1 0)) (@stack state))
      t)))

;;; Script: crypto

(define-opcode op_ripemd160 166 #xa6 (state)
  "The input is hashed using RIPEMD-160."
  (when (>= (length (@stack state)) 1)
    (push (ripemd160 (pop (@stack state))) (@stack state))
    t))

(define-opcode op_sha1 167 #xa7 (state)
  "The input is hashed using SHA-1."
  (when (>= (length (@stack state)) 1)
    (push (sha1 (pop (@stack state))) (@stack state))
    t))

(define-opcode op_sha256 168 #xa8 (state)
  "The input is hashed using SHA-256."
  (when (>= (length (@stack state)) 1)
    (push (sha256 (pop (@stack state))) (@stack state))
    t))

(define-opcode op_hash160 169 #xa9 (state)
  "The input is hashed twice: first with SHA-256 and then with
RIPEMD-160."
  (when (>= (length (@stack state)) 1)
    (push (hash160 (pop (@stack state))) (@stack state))
    t))

(define-opcode op_hash256 170 #xaa (state)
  "The input is hashed two times with SHA-256."
  (when (>= (length (@stack state)) 1)
    (push (hash256 (pop (@stack state))) (@stack state))
    t))

(define-opcode op_codeseparator 171 #xab (state)
  "All of the signature checking words will only match signatures to
the data after the most recently-executed OP_CODESEPARATOR."
  (setf (@discard state) (list (opcode :op_codeseparator))))

(define-opcode op_checksig 172 #xac (state)
  "The entire transaction's outputs, inputs, and script (from the most
recently-executed OP_CODESEPARATOR to the end) are hashed. The
signature used by OP_CHECKSIG must be a valid signature for this hash
and public key. If it is, 1 is returned, 0 otherwise."
  (when (>= (length (@stack state)) 2)
    (let* ((pubkey (parse-pubkey (pop (@stack state))))
           (sigdata (pop (@stack state)))
           (len (length sigdata))
           (signature (parse-signature (subseq sigdata 0 (1- len))))
           (hashtype (aref sigdata (1- len)))
           (sighash (@sighash state hashtype)))
      (push (encode-integer
             (if (verify-signature pubkey sighash signature) 1 0))
            (@stack state))
      t)))

(define-opcode op_checksigverify 173 #xad (state)
  "Same as OP_CHECKSIG, but OP_VERIFY is executed afterward."
  (when (op_checksig state)
    (op_verify state)))

(define-opcode op_checkmultisig 174 #xae (state)
  "Compares the first signature against each public key until it finds
an ECDSA match. Starting with the subsequent public key, it compares
the second signature against each remaining public key until it finds
an ECDSA match. The process is repeated until all signatures have been
checked or not enough public keys remain to produce a successful
result. All signatures need to match a public key. Because public keys
are not checked again if they fail any signature comparison,
signatures must be placed in the scriptSig using the same order as
their corresponding public keys were placed in the scriptPubKey or
redeemScript. If all signatures are valid, 1 is returned, 0
otherwise. Due to a bug, one extra unused value is removed from the
stack."
  (when (< (length (@stack state)) 1)
    (return-from op_checkmultisig nil))
  (let ((n (decode-integer (pop (@stack state))))
        (pubkeys (list)))
    (when (< (length (@stack state)) (1+ n))
      (return-from op_checkmultisig nil))
    (loop
       :repeat n
       :for pk := (parse-pubkey (pop (@stack state)))
       :do (push pk pubkeys))
    (let ((m (decode-integer (pop (@stack state))))
          (signatures (list)))
      (when (< (length (@stack state)) (1+ m))
        (return-from op_checkmultisig nil))
      (loop
         :repeat m
         :for sigdata  := (pop (@stack state))
         :for len      := (length sigdata)
         :for sig      := (parse-signature (subseq sigdata 0 (1- len)))
         :for hashtype := (aref sigdata (1- len))
         :do (push (list sig hashtype) signatures))
      ;; Off-by-one bug in the Bitcoin's OP_CHECKMULTISIG
      ;; implementation.
      (pop (@stack state))
      (loop
         :while pubkeys
         :for   pubkey         := (pop pubkeys)
         :with  (sig hashtype) := (pop signatures)
         ;; Only proceed to the next signature if ECDSA match was
         ;; found.
         :when (verify-signature pubkey (@sighash state hashtype) sig)
         :do
           (multiple-value-setq (sig hashtype) (values-list (pop signatures))))
      ;; Return 1 if all signatures have been checked, 0 otherwise.
      (push (encode-integer (if (null signatures) 1 0)) (@stack state))
      t)))

(define-opcode op_checkmultisigverify 175 #xaf (state)
  "Same as OP_CHECKMULTISIG, but OP_VERIFY is executed afterward."
  (when (op_checkmultisig state)
    (op_verify state)))

;;; Script: pseudo-words

(define-opcode op_pubkeyhash 253 #xfd (state)
  "Represents a public key hashed with OP_HASH160.")

(define-opcode op_pubkey 254 #xfe (state)
  "Represents a public key compatible with OP_CHECKSIG.")

(define-opcode op_invalidopcode 255 #xff (state)
  "Matches any opcode that is not yet assigned.")

;;; Script: reserved

(define-opcode op_reserved 80 #x50 (state)
  "Transaction is invalid unless occuring in an unexecuted OP_IF
branch.")

(define-opcode op_ver 98 #x62 (state)
  "Transaction is invalid unless occuring in an unexecuted OP_IF
branch.")

(define-opcode op_verif 101 #x65 (state)
  "Transaction is invalid even when occuring in an unexecuted OP_IF
branch.")

(define-opcode op_vernotif 102 #x66 (state)
  "Transaction is invalid even when occuring in an unexecuted OP_IF
branch.")

(define-opcode op_reserved1 137 #x89 (state)
  "Transaction is invalid unless occuring in an unexecuted OP_IF
branch.")

(define-opcode op_reserved2 138 #x8a (state)
  "Transaction is invalid unless occuring in an unexecuted OP_IF
branch.")

(define-opcode op_nop1 176 #xb0 (state)
  "The word is ignored. Does not mark transaction as invalid."
  (declare (ignore state))
  t)

(define-opcode-range (op_nop 4 10) (179 185) (#xb3 #xb9) (state)
  "The word is ignored. Does not mark transaction as invalid."
  (declare (ignore state))
  t)

(define-opcode-range (op_unknown 186 255) (186 255) (#xba #xff) (state)
  "Unknown opcode. Used for handling coinbase input scripts.")

;;; Script: locktime

(define-opcode op_checklocktimeverify 177 #xb1 (state)
               "Marks transaction as invalid if the top stack item is greater than
the transaction's nLockTime field, otherwise script evaluation
continues as though an OP_NOP was executed. Transaction is also
invalid if 1. the stack is empty; or 2. the top stack item is
negative; or 3. the top stack item is greater than or equal to
500000000 while the transaction's nLockTime field is less than
500000000, or vice versa; or 4. the input's nSequence field is equal
to #xffffffff. The precise semantics are described in BIP 0065.")

(define-opcode op_checksequenceverify 178 #xb2 (state)
  "Marks transaction as invalid if the relative lock time of the
input (enforced by BIP 0068 with nSequence) is not equal to or longer
than the value of the top stack item. The precise semantics are
described in BIP 0112.")
