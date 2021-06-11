(uiop:define-package :bp/crypto/secp256k1 (:use :cl :cffi :ironclad)
  (:use :bp/crypto/random)
  (:nicknames :secp256k1)
  (:shadow
   ;; Ironclad's symbols
   #:make-signature
   #:verify-signature)
  (:export
   ;; Signature API
   #:ecdsa-sign
   #:ecdsa-verify
   ;; Key utilities
   #:ec-pubkey-parse
   #:ec-pubkey-serialize
   #:ec-pubkey-create
   #:ec-seckey-verify
   #:ec-privkey-negate
   #:ec-pubkey-negate
   ;; Signature utilities
   #:ecdsa-signature-parse-compact
   #:ecdsa-signature-serialize-compact
   #:ecdsa-signature-parse-der
   #:ecdsa-signature-serialize-der
   #:ecdsa-signature-normalize
   ;; Context
   #:context-create-none
   #:context-create-verify
   #:context-create-sign
   ;; High-level API
   #:key
   #:make-key
   #:pubkey
   #:make-pubkey
   #:parse-pubkey
   #:serialize-pubkey
   #:signature
   #:make-signature
   #:verify-signature
   #:parse-signature
   #:serialize-signature))

(in-package :bp/crypto/secp256k1)

;;; This file contains manual translation of the secp256k1.h file from
;;; libsecp256k1/include directory as well as wrappers around API functions that
;;; accept Lisp values, translated them into foreign values and call C
;;; functions.
;;;
;;; The naming/argument conventions:
;;;
;;;   - foreign functions are named as in C (i.e. have the secp256k1 prefix)
;;;     with the exception that underscores are replaced with dash characters;
;;;     this naming is generated automatically by CFFI;
;;;
;;;   - Lisp-value wrappers have the same names as the CFFI-generated foreign
;;;     functions but the secp256k1 prefix is dropped;
;;;
;;;   - context and out arguments are fixed and omitted in Lisp functions,
;;;     length arguments are dropped, the argument order is preserved.

;;;-----------------------------------------------------------------------------
;;; CFFI utils

;; This is incorrect but fits both 64-bit Linux and 64-bit macOS, so
;; is good enough for now.
(defctype size-t :unsigned-long)

(defmacro bytes-from-foreign (bytes pointer size)
  `(let* ((pointer ,pointer)
          (size ,size)
          (bytes ,(or bytes `(make-array size :element-type '(unsigned-byte 8)))))
     (loop
        :for i :below size
        :do (setf (aref bytes i) (mem-aref pointer :unsigned-char i)))
     bytes))

(defmacro bytes-to-foreign (bytes pointer size)
  `(let ((bytes ,bytes)
         (pointer ,pointer)
         (size ,size))
     (loop
        :for i :below size
        :do (setf (mem-aref pointer :unsigned-char i) (aref bytes i)))))


;;;-----------------------------------------------------------------------------
;;; libsecp256k1 bindings

(define-foreign-library libsecp256k1
  (t (:default "libsecp256k1")))

(use-foreign-library libsecp256k1)

;; Opaque data structure that holds a parsed and valid public key.
;;
;; The exact representation of data inside is implementation defined and not
;; guaranteed to be portable between different platforms or versions. It is
;; however guaranteed to be 64 bytes in size, and can be safely copied/moved.
;; If you need to convert to a format suitable for storage, transmission, or
;; comparison, use secp256k1_ec_pubkey_serialize and secp256k1_ec_pubkey_parse.
(defcstruct secp256k1-pubkey
    (data :unsigned-char :count 64))

;; Opaque data structured that holds a parsed ECDSA signature.
;;
;; The exact representation of data inside is implementation defined and not
;; guaranteed to be portable between different platforms or versions. It is
;; however guaranteed to be 64 bytes in size, and can be safely copied/moved.
;; If you need to convert to a format suitable for storage, transmission, or
;; comparison, use the secp256k1_ecdsa_signature_serialize_* and
;; secp256k1_ecdsa_signature_parse_* functions.
(defcstruct secp256k1-ecdsa-signature
  (data :unsigned-char :count 64))

;; All flags' lower 8 bits indicate what they're for. Do not use directly.
(defconstant +secp256k1-flags-type-mask+        (- (ash 1 8) 1))
(defconstant +secp256k1-flags-type-context+     (ash 1 0))
(defconstant +secp256k1-flags-type-compression+ (ash 1 1))
;; The higher bits contain the actual data. Do not use directly.
(defconstant +secp256k1-flags-bit-context-verify+ (ash 1 8))
(defconstant +secp256k1-flags-bit-context-sign+   (ash 1 9))
(defconstant +secp256k1-flags-bit-compression+    (ash 1 8))

;; Flags to pass to secp256k1-context-create.
(defconstant +secp256k1-context-none+ +secp256k1-flags-type-context+)
(defconstant +secp256k1-context-verify+
  (logior +secp256k1-flags-type-context+ +secp256k1-flags-bit-context-verify+))
(defconstant +secp256k1-context-sign+
  (logior +secp256k1-flags-type-context+ +secp256k1-flags-bit-context-sign+))

;; Flags to pass to SECP256K1-EC-PUBKEY-SERIALIZE and
;; SECP256K1-EC-PRIVKEY-EXPORT.
(defconstant +secp256k1-ec-uncompressed+ +secp256k1-flags-type-compression+)
(defconstant +secp256k1-ec-compressed+
  (logior +secp256k1-flags-type-compression+ +secp256k1-flags-bit-compression+))

;; Prefix byte used to tag various encoded curvepoints for specific purposes.
(defconstant +secp256k1-tag-pubkey-even+ #x02)
(defconstant +secp256k1-tag-pubkey-odd+ #x03)
(defconstant +secp256k1-tag-pubkey-uncompressed+ #x04)
(defconstant +secp256k1-tag-pubkey-hybrid-even+ #x06)
(defconstant +secp256k1-tag-pubkey-hybrid-odd+ #x07)

;; Create a secp256k1 context object.
;;
;; Returns: a newly created context object.
;; In:      flags: which parts of the context to initialize.
;;
;; See also secp256k1_context_randomize.
(defcfun "secp256k1_context_create" :pointer
  (flags :unsigned-int))

;; Copies a secp256k1 context object.
;;
;; Returns: a newly created context object.
;; Args:    ctx: an existing context to copy (cannot be NULL)
(defcfun "secp256k1_context_clone" :pointer
  (ctx :pointer))

;; Destroy a secp256k1 context object.
;;
;; The context pointer may not be used afterwards.
;; Args:   ctx: an existing context to destroy (cannot be NULL)
(defcfun "secp256k1_context_destroy" :void
  (ctx :pointer))

;; Updates the context randomization to protect against side-channel leakage.
;; Returns: 1: randomization successfully updated or nothing to randomize
;;          0: error
;; Args:    ctx:       pointer to a context object (cannot be NULL)
;; In:      seed32:    pointer to a 32-byte random seed (NULL resets to initial state)
;;
;; While secp256k1 code is written to be constant-time no matter what secret
;; values are, it's possible that a future compiler may output code which isn't,
;; and also that the CPU may not emit the same radio frequencies or draw the same
;; amount power for all values.
;;
;; This function provides a seed which is combined into the blinding value: that
;; blinding value is added before each multiplication (and removed afterwards) so
;; that it does not affect function results, but shields against attacks which
;; rely on any input-dependent behaviour.
;;
;; This function has currently an effect only on contexts initialized for signing
;; because randomization is currently used only for signing. However, this is not
;; guaranteed and may change in the future. It is safe to call this function on
;; contexts not initialized for signing; then it will have no effect and return 1.
;;
;; You should call this after secp256k1_context_create or
;; secp256k1_context_clone, and may call this repeatedly afterwards.
(defcfun "secp256k1_context_randomize" :int
  (ctx :pointer) ;; secp256k1_context*
  (seed32 (:pointer :unsigned-char)))

(defun context-create-none ()
  (secp256k1-context-create +secp256k1-context-none+))

(defun context-create-verify ()
  (secp256k1-context-create +secp256k1-context-verify+))

(defun context-create-sign ()
  (let ((ctx (secp256k1-context-create +secp256k1-context-sign+))
        (seed32 (random-bytes 32)))
    (with-foreign-objects
        ((cseed32 :unsigned-char 32))
      (bytes-to-foreign seed32 cseed32 32)
      (assert (not (zerop (secp256k1-context-randomize ctx cseed32)))
              () "Sign context randomization error.")
      ctx)))

(defvar *context-none*   (context-create-none))
(defvar *context-verify* (context-create-verify))
(defvar *context-sign*   (context-create-sign))

;; Create a secp256k1 scratch space object.
;;
;; Returns: a newly created scratch space.
;; Args: ctx:  an existing context object (cannot be NULL)
;; In:   max_size: maximum amount of memory to allocate
(defcfun "secp256k1_scratch_space_create" :pointer
  (ctx :pointer) ;; secp256k1-context*
  (max-size size-t))

;; Destroy a secp256k1 scratch space.
;;
;; The pointer may not be used afterwards.
;; Args:   scratch: space to destroy
(defcfun "secp256k1_scratch_space_destroy" :void
  (scratch :pointer)) ;; secp256k1_scratch_space*

;; Parse a variable-length public key into the pubkey object.
;;
;; Returns: 1 if the public key was fully valid.
;;          0 if the public key could not be parsed or is invalid.
;; Args: ctx:      a secp256k1 context object.
;; Out:  pubkey:   pointer to a pubkey object. If 1 is returned, it is set to a
;;                 parsed version of input. If not, its value is undefined.
;; In:   input:    pointer to a serialized public key
;;       inputlen: length of the array pointed to by input
;;
;; This function supports parsing compressed (33 bytes, header byte 0x02 or
;; 0x03), uncompressed (65 bytes, header byte 0x04), or hybrid (65 bytes, header
;; byte 0x06 or 0x07) format public keys.
(defcfun "secp256k1_ec_pubkey_parse" :int
  (ctx :pointer ) ;; secp256k1_context*
  (pubkey (:pointer (:struct secp256k1-pubkey)))
  (input (:pointer :unsigned-char))
  (inputlen size-t))

(defun ec-pubkey-parse (input)
  (let ((inputlen (length input)))
    (with-foreign-objects
        ((cpubkey '(:struct secp256k1-pubkey))
         (cinput :unsigned-char inputlen))
      (bytes-to-foreign input cinput inputlen)
      (unless (zerop (secp256k1-ec-pubkey-parse *context-sign* cpubkey
                                                cinput inputlen))
        (bytes-from-foreign nil cpubkey 64)))))

;; Serialize a pubkey object into a serialized byte sequence.
;;
;; Returns: 1 always.
;; Args:   ctx:        a secp256k1 context object.
;; Out:    output:     a pointer to a 65-byte (if compressed==0) or 33-byte (if
;;                     compressed==1) byte array to place the serialized key
;;                     in.
;; In/Out: outputlen:  a pointer to an integer which is initially set to the
;;                     size of output, and is overwritten with the written
;;                     size.
;; In:     pubkey:     a pointer to a secp256k1_pubkey containing an
;;                     initialized public key.
;;         flags:      SECP256K1_EC_COMPRESSED if serialization should be in
;;                     compressed format, otherwise SECP256K1_EC_UNCOMPRESSED.
(defcfun "secp256k1_ec_pubkey_serialize" :int
  (ctx :pointer) ;; secp256k1_context*
  (output (:pointer :unsigned-char))
  (outputlen (:pointer size-t))
  (pubkey (:pointer (:struct secp256k1-pubkey)))
  (flags :unsigned-int))

(defun ec-pubkey-serialize (pubkey &key compressed)
  (let ((outputlen (if compressed 33 65)))
    (with-foreign-objects
        ((coutput :unsigned-char outputlen)
         (coutputlen 'size-t 1)
         (cpubkey '(:struct secp256k1-pubkey)))
      (setf (mem-aref coutputlen 'size-t 0) outputlen)
      (bytes-to-foreign pubkey cpubkey 64)
      (secp256k1-ec-pubkey-serialize *context-none* coutput coutputlen cpubkey
                                     (if compressed
                                         +secp256k1-ec-compressed+
                                         +secp256k1-ec-uncompressed+))
      (bytes-from-foreign nil coutput (mem-aref coutputlen :unsigned-int 0)))))

;; Parse an ECDSA signature in compact (64 bytes) format.
;;
;; Returns: 1 when the signature could be parsed, 0 otherwise.
;; Args: ctx:      a secp256k1 context object
;; Out:  sig:      a pointer to a signature object
;; In:   input64:  a pointer to the 64-byte array to parse
;;
;; The signature must consist of a 32-byte big endian R value, followed by a
;; 32-byte big endian S value. If R or S fall outside of [0..order-1], the
;; encoding is invalid. R and S with value 0 are allowed in the encoding.
;;
;; After the call, sig will always be initialized. If parsing failed or R or
;; S are zero, the resulting sig value is guaranteed to fail validation for any
;; message and public key.
(defcfun "secp256k1_ecdsa_signature_parse_compact" :int
  (ctx :pointer) ;; secp256k1_context*
  (sig (:pointer (:struct secp256k1-ecdsa-signature)))
  (input64 (:pointer :unsigned-char)))

(defun ecdsa-signature-parse-compact (input64)
  (with-foreign-objects
      ((csignature '(:struct secp256k1-ecdsa-signature))
       (cinput64 :unsigned-char 64))
    (bytes-to-foreign input64 cinput64 64)
    (unless (zerop (secp256k1-ecdsa-signature-parse-compact
                    *context-none* csignature cinput64))
      (bytes-from-foreign nil csignature 64))))

;; Parse a DER ECDSA signature.
;;
;; Returns: 1 when the signature could be parsed, 0 otherwise.
;; Args: ctx:      a secp256k1 context object
;; Out:  sig:      a pointer to a signature object
;; In:   input:    a pointer to the signature to be parsed
;;       inputlen: the length of the array pointed to be input
;;
;; This function will accept any valid DER encoded signature, even if the
;; encoded numbers are out of range.
;;
;; After the call, sig will always be initialized. If parsing failed or the
;; encoded numbers are out of range, signature validation with it is
;; guaranteed to fail for every message and public key.
(defcfun "secp256k1_ecdsa_signature_parse_der" :int
  (ctx :pointer) ;; secp256k1_context*
  (sig (:pointer (:struct secp256k1-ecdsa-signature)))
  (input (:pointer :unsigned-char))
  (inputlen size-t))

(defun ecdsa-signature-parse-der (input)
  (let ((inputlen (length input)))
    (with-foreign-objects
        ((csignature '(:struct secp256k1-ecdsa-signature))
         (cinput :unsigned-char inputlen))
      (bytes-to-foreign input cinput inputlen)
      (unless (zerop (secp256k1-ecdsa-signature-parse-der
                      *context-none* csignature cinput inputlen))
        (bytes-from-foreign nil csignature 64)))))

(defun ecdsa-signature-parse-der-lax (input)
  "This function is taken from the libsecp256k1 distribution and
implements DER parsing for ECDSA signatures, while supporting an
arbitrary subset of format violations (see Bitcoin's pubkey.cpp)."
  (let* ((inputlen (length input))
         (tmpsig   (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0))
         (sig      (ecdsa-signature-parse-compact tmpsig))
         pos lenbyte rpos rlen spos slen overflow)
    (macrolet ((%fail ()
                 `(return-from ecdsa-signature-parse-der-lax nil))
               (%check-tag ()
                 `(progn
                    (when (or (= pos inputlen) (/= (aref input pos) #x02))
                      (%fail))
                    (incf pos)))
               (%compute-len (cpos clen)
                 `(progn
                    (when (= pos inputlen) (%fail))
                    (setf lenbyte (aref input pos))
                    (incf pos)
                    (if (not (= 0 (logand lenbyte #x80)))
                        (progn
                          (decf lenbyte #x80)
                          (when (> lenbyte (- inputlen pos)) (%fail))
                          (loop
                             :while (and (> lenbyte 0) (= 0 (aref input pos)))
                             :do
                               (incf pos)
                               (decf lenbyte))
                          (when (>= lenbyte 4) (%fail))
                          (setf ,clen 0)
                          (loop
                             :while (> lenbyte 0)
                             :do
                               (setf ,clen (+ (ash ,clen 8) (aref input pos)))
                               (incf pos)
                               (decf lenbyte)))
                        (setf ,clen lenbyte))
                    (when (> ,clen (- inputlen pos)) (%fail))
                    (setf ,cpos pos)))
               (%skip-zeroes (cpos clen)
                 `(loop
                     :while (and (> ,clen 0) (= 0 (aref input ,cpos)))
                     :do
                       (decf ,clen)
                       (incf ,cpos)))
               (%copy (cpos clen offset)
                 `(if (> ,clen 32)
                      (setf overflow t)
                      (loop
                         :for i :below ,clen
                         :do (setf
                              (aref tmpsig (+ (- ,offset ,clen) i))
                              (aref input (+ ,cpos i)))))))
      ;; Sequence tag byte.
      (setf pos 0)
      (when (or (= pos inputlen) (/= (aref input pos) #x30))
        (%fail))
      (incf pos)
      ;; Sequence length bytes.
      (when (= pos inputlen) (%fail))
      (setf lenbyte (aref input pos))
      (incf pos)
      (when (not (= 0 (logand lenbyte #x80)))
        (decf lenbyte #x80)
        (when (> lenbyte (- inputlen pos)) (%fail))
        (incf pos lenbyte))
      ;; Integer tag byte for R.
      (%check-tag)
      ;; Integer len for R.
      (%compute-len rpos rlen)
      (incf pos rlen)
      ;; Integer tag byte for S.
      (%check-tag)
      ;; Integer len for R.
      (%compute-len spos slen)
      ;; Ignore leading zeroes in R.
      (%skip-zeroes rpos rlen)
      ;; Copy R value.
      (%copy rpos rlen 32)
      ;; Ignore leading zeroes in S.
      (%skip-zeroes spos slen)
      ;; Copy S value.
      (%copy spos slen 64)
      ;; Parse fixed signature.
      (when (not overflow)
        (setf overflow (not (setf sig (ecdsa-signature-parse-compact tmpsig)))))
      (when overflow
        ;; Overwrite the result again with a correctly-parsed but
        ;; invalid signature if parsing failed.
        (loop :for i :below 64 :do (setf (aref tmpsig i) 0))
        (setf sig (ecdsa-signature-parse-compact tmpsig)))
      sig)))

;; Serialize an ECDSA signature in DER format.
;;
;; Returns: 1 if enough space was available to serialize, 0 otherwise
;; Args:   ctx:       a secp256k1 context object
;; Out:    output:    a pointer to an array to store the DER serialization
;; In/Out: outputlen: a pointer to a length integer. Initially, this integer
;;                    should be set to the length of output. After the call
;;                    it will be set to the length of the serialization (even
;;                    if 0 was returned).
;; In:     sig:       a pointer to an initialized signature object
(defcfun "secp256k1_ecdsa_signature_serialize_der" :int
  (ctx :pointer) ;; secp256k1_context*
  (output (:pointer :unsigned-char))
  (outputlen (:pointer size-t))
  (sig (:pointer (:struct secp256k1-ecdsa-signature))))

(defun ecdsa-signature-serialize-der (signature)
  (with-foreign-objects
      ((coutput :unsigned-char 74)
       (coutputlen 'size-t 1)
       (csignature '(:struct secp256k1-ecdsa-signature)))
    (setf (mem-aref coutputlen 'size-t 0) 74)
    (bytes-to-foreign signature csignature 64)
    (unless (zerop (secp256k1-ecdsa-signature-serialize-der
                    *context-none* coutput coutputlen csignature))
      (bytes-from-foreign nil coutput (mem-aref coutputlen 'size-t 0)))))

;; Serialize an ECDSA signature in compact (64 byte) format.
;;
;; Returns: 1
;; Args:   ctx:       a secp256k1 context object
;; Out:    output64:  a pointer to a 64-byte array to store the compact serialization
;; In:     sig:       a pointer to an initialized signature object
;;
;; See secp256k1_ecdsa_signature_parse_compact for details about the encoding.
(defcfun "secp256k1_ecdsa_signature_serialize_compact" :int
  (ctx :pointer) ;; secp256k1_context*
  (output64 (:pointer :unsigned-char))
  (sig (:pointer (:struct secp256k1-ecdsa-signature))))

(defun ecdsa-signature-serialize-compact (signature)
  (with-foreign-objects
      ((coutput :unsigned-char 64)
       (csignature '(:struct secp256k1-ecdsa-signature)))
    (bytes-to-foreign signature csignature 64)
    (unless (zerop (secp256k1-ecdsa-signature-serialize-compact
                    *context-none* coutput csignature))
      (bytes-from-foreign nil coutput 64))))

;; Verify an ECDSA signature.
;;
;; Returns: 1: correct signature
;;          0: incorrect or unparseable signature
;; Args:    ctx:       a secp256k1 context object, initialized for verification.
;; In:      sig:       the signature being verified (cannot be NULL)
;;          msg32:     the 32-byte message hash being verified (cannot be NULL)
;;          pubkey:    pointer to an initialized public key to verify with (cannot be NULL)
;;
;; To avoid accepting malleable signatures, only ECDSA signatures in lower-S
;; form are accepted.
;;
;; If you need to accept ECDSA signatures from sources that do not obey this
;; rule, apply secp256k1_ecdsa_signature_normalize to the signature prior to
;; validation, but be aware that doing so results in malleable signatures.
;;
;; For details, see the comments for that function.
(defcfun "secp256k1_ecdsa_verify" :int
  (ctx :pointer) ;; secp256k1_context*
  (sig :pointer) ;; secp256k1_ecdsa_signature*
  (msg32 (:pointer :unsigned-char))
  (pubkey (:pointer (:struct secp256k1-pubkey))))

(defun ecdsa-verify (signature msg32 pubkey)
  "Verify an ECDSA signature."
  (with-foreign-objects
      ((csignature '(:struct secp256k1-ecdsa-signature))
       (cmsg32 :unsigned-char 32)
       (cpubkey '(:struct secp256k1-pubkey)))
    (bytes-to-foreign signature csignature 64)
    (bytes-to-foreign msg32 cmsg32 32)
    (bytes-to-foreign pubkey cpubkey 64)
    (unless (zerop (secp256k1-ecdsa-verify
                    *context-verify* csignature cmsg32 cpubkey))
      t)))

;; Convert a signature to a normalized lower-S form.
;;
;; Returns: 1 if sigin was not normalized, 0 if it already was.
;; Args: ctx:    a secp256k1 context object
;; Out:  sigout: a pointer to a signature to fill with the normalized form,
;;               or copy if the input was already normalized. (can be NULL if
;;               you're only interested in whether the input was already
;;               normalized).
;; In:   sigin:  a pointer to a signature to check/normalize (cannot be NULL,
;;               can be identical to sigout)
;;
;; With ECDSA a third-party can forge a second distinct signature of the same
;; message, given a single initial signature, but without knowing the key. This
;; is done by negating the S value modulo the order of the curve, 'flipping'
;; the sign of the random point R which is not included in the signature.
;;
;; Forgery of the same message isn't universally problematic, but in systems
;; where message malleability or uniqueness of signatures is important this can
;; cause issues. This forgery can be blocked by all verifiers forcing signers
;; to use a normalized form.
;;
;; The lower-S form reduces the size of signatures slightly on average when
;; variable length encodings (such as DER) are used and is cheap to verify,
;; making it a good choice. Security of always using lower-S is assured because
;; anyone can trivially modify a signature after the fact to enforce this
;; property anyway.
;;
;; The lower S value is always between 0x1 and
;; 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0,
;; inclusive.
;;
;; No other forms of ECDSA malleability are known and none seem likely, but
;; there is no formal proof that ECDSA, even with this additional restriction,
;; is free of other malleability. Commonly used serialization schemes will also
;; accept various non-unique encodings, so care should be taken when this
;; property is required for an application.
;;
;; The secp256k1_ecdsa_sign function will by default create signatures in the
;; lower-S form, and secp256k1_ecdsa_verify will not accept others. In case
;; signatures come from a system that cannot enforce this property,
;; secp256k1_ecdsa_signature_normalize must be called before verification.
(defcfun "secp256k1_ecdsa_signature_normalize" :int
  (ctx :pointer) ;; secp256k1_context*
  (sigout (:pointer (:struct secp256k1-ecdsa-signature)))
  (sigin (:pointer (:struct secp256k1-ecdsa-signature))))

(defun ecdsa-signature-normalize (sigin)
  (with-foreign-objects
      ((csigout '(:struct secp256k1-ecdsa-signature))
       (csigin '(:struct secp256k1-ecdsa-signature)))
    (bytes-to-foreign sigin csigin 64)
    (unless (zerop (secp256k1-ecdsa-signature-normalize
                    *context-none* csigout csigin))
      (bytes-from-foreign nil csigout 64))))

;; Create an ECDSA signature.
;;
;; Returns: 1: signature created
;;          0: the nonce generation function failed, or the private key was invalid.
;; Args:    ctx:    pointer to a context object, initialized for signing (cannot be NULL)
;; Out:     sig:    pointer to an array where the signature will be placed (cannot be NULL)
;; In:      msg32:  the 32-byte message hash being signed (cannot be NULL)
;;          seckey: pointer to a 32-byte secret key (cannot be NULL)
;;          noncefp:pointer to a nonce generation function. If NULL, secp256k1_nonce_function_default is used
;;          ndata:  pointer to arbitrary data used by the nonce generation function (can be NULL)
;;
;; The created signature is always in lower-S form. See
;; secp256k1_ecdsa_signature_normalize for more details.
(defcfun "secp256k1_ecdsa_sign" :int
  (ctx     :pointer) ;; secp256k1_context*
  (sig     (:pointer (:struct secp256k1-ecdsa-signature)))
  (msg32   (:pointer :unsigned-char))
  (seckey  (:pointer :unsigned-char))
  (noncefp :pointer)  ;; secp256k1_nonce_function
  (ndata   :pointer)) ;; void*

(defun ecdsa-sign (msg32 seckey)
  "Create an ECDSA signature."
  (with-foreign-objects
      ((csignature '(:struct secp256k1-ecdsa-signature))
       (cmsg32 :unsigned-char 32)
       (cseckey :unsigned-char 32))
    (bytes-to-foreign msg32 cmsg32 32)
    (bytes-to-foreign seckey cseckey 32)
    (unless (zerop (secp256k1-ecdsa-sign *context-sign* csignature cmsg32 cseckey
                                         (null-pointer) (null-pointer)))
      (bytes-from-foreign nil csignature 64))))

;; Verify an ECDSA secret key.
;;
;; Returns: 1: secret key is valid
;;          0: secret key is invalid
;; Args:    ctx: pointer to a context object (cannot be NULL)
;; In:      seckey: pointer to a 32-byte secret key (cannot be NULL)
(defcfun "secp256k1_ec_seckey_verify" :int
  (ctx :pointer) ;; secp256k1_context*
  (seckey (:pointer :unsigned-char)))

(defun ec-seckey-verify (seckey)
  (with-foreign-objects
      ((cseckey :unsigned-char 32))
    (bytes-to-foreign seckey cseckey 32)
    (unless (zerop (secp256k1-ec-seckey-verify *context-sign* cseckey))
      t)))

;; Compute the public key for a secret key.
;;
;; Returns: 1: secret was valid, public key stores
;;          0: secret was invalid, try again
;; Args:   ctx:        pointer to a context object, initialized for signing (cannot be NULL)
;; Out:    pubkey:     pointer to the created public key (cannot be NULL)
;; In:     seckey:     pointer to a 32-byte private key (cannot be NULL)
(defcfun "secp256k1_ec_pubkey_create" :int
  (ctx :pointer)
  (pubkey (:pointer (:struct secp256k1-pubkey)))
  (seckey (:pointer :unsigned-char)))

(defun ec-pubkey-create (seckey)
  (with-foreign-objects
      ((cpubkey '(:struct secp256k1-pubkey))
       (cseckey :unsigned-char 32))
    (bytes-to-foreign seckey cseckey 32)
    (unless (zerop (secp256k1-ec-pubkey-create *context-sign* cpubkey cseckey))
      (bytes-from-foreign nil cpubkey 64))))

;; Negates a private key in place.
;;
;; Returns: 1 always
;; Args:   ctx:        pointer to a context object
;; In/Out: seckey:     pointer to the 32-byte private key to be negated (cannot be NULL)
(defcfun "secp256k1_ec_privkey_negate" :int
  (ctx :pointer) ;; secp256k1_context*
  (seckey (:pointer :unsigned-char)))

(defun ec-privkey-negate (seckey)
  (with-foreign-objects
      ((cseckey :unsigned-char 32))
    (bytes-to-foreign seckey cseckey 32)
    (secp256k1-ec-privkey-negate *context-sign* cseckey)
    (bytes-from-foreign seckey cseckey 32)))

;; Negates a public key in place.
;;
;; Returns: 1 always
;; Args:   ctx:        pointer to a context object
;; In/Out: pubkey:     pointer to the public key to be negated (cannot be NULL)
(defcfun "secp256k1_ec_pubkey_negate" :int
  (ctx :pointer) ;; secp256k1_context*
  (pubkey (:pointer (:struct secp256k1-pubkey))))

(defun ec-pubkey-negate (pubkey)
  (with-foreign-objects
      ((cpubkey '(:struct secp256k1-pubkey)))
    (bytes-to-foreign pubkey cpubkey 64)
    (secp256k1-ec-pubkey-negate *context-sign* cpubkey)
    (bytes-from-foreign pubkey cpubkey 64)))

;; Tweak a private key by adding tweak to it.
;; Returns: 0 if the tweak was out of range (chance of around 1 in 2^128 for
;;          uniformly random 32-byte arrays, or if the resulting private key
;;          would be invalid (only when the tweak is the complement of the
;;          private key). 1 otherwise.
;; Args:    ctx:    pointer to a context object (cannot be NULL).
;; In/Out:  seckey: pointer to a 32-byte private key.
;; In:      tweak:  pointer to a 32-byte tweak.
(defcfun "secp256k1_ec_privkey_tweak_add" :int
  (ctx :pointer) ;; secp256k1_context*
  (seckey (:pointer :unsigned-char))
  (tweak (:pointer :unsigned-char)))

;; Tweak a public key by adding tweak times the generator to it.
;; Returns: 0 if the tweak was out of range (chance of around 1 in 2^128 for
;;          uniformly random 32-byte arrays, or if the resulting public key
;;          would be invalid (only when the tweak is the complement of the
;;          corresponding private key). 1 otherwise.
;; Args:    ctx:    pointer to a context object initialized for validation
;;                  (cannot be NULL).
;; In/Out:  pubkey: pointer to a public key object.
;; In:      tweak:  pointer to a 32-byte tweak.
(defcfun "secp256k1_ec_pubkey_tweak_add" :int
  (ctx :pointer) ;; secp256k1_context*
  (pubkey (:pointer (:struct secp256k1-pubkey)))
  (tweak (:pointer :unsigned-char)))

;; Tweak a private key by multiplying it by a tweak.
;; Returns: 0 if the tweak was out of range (chance of around 1 in 2^128 for
;;          uniformly random 32-byte arrays, or equal to zero. 1 otherwise.
;; Args:   ctx:    pointer to a context object (cannot be NULL).
;; In/Out: seckey: pointer to a 32-byte private key.
;; In:     tweak:  pointer to a 32-byte tweak.
(defcfun "secp256k1_ec_privkey_tweak_mul" :int
  (ctx :pointer) ;; secp256k1_context*
  (seckey (:pointer :unsigned-char))
  (tweak (:pointer :unsigned-char)))

;; Tweak a public key by multiplying it by a tweak value.
;; Returns: 0 if the tweak was out of range (chance of around 1 in 2^128 for
;;          uniformly random 32-byte arrays, or equal to zero. 1 otherwise.
;; Args:    ctx:    pointer to a context object initialized for validation
;;                 (cannot be NULL).
;; In/Out:  pubkey: pointer to a public key obkect.
;; In:      tweak:  pointer to a 32-byte tweak.
(defcfun "secp256k1_ec_pubkey_tweak_mul" :int
  (ctx :pointer) ;; secp256k1_context*
  (pubkey (:pointer (:struct secp256k1-pubkey)))
  (tweak (:pointer :unsigned-char)))

;; Add a number of public keys together.
;; Returns: 1: the sum of the public keys is valid.
;;          0: the sum of the public keys is not valid.
;; Args:   ctx:        pointer to a context object
;; Out:    out:        pointer to a public key object for placing the resulting public key
;;                     (cannot be NULL)
;; In:     ins:        pointer to array of pointers to public keys (cannot be NULL)
;;         n:          the number of public keys to add together (must be at least 1)
(defcfun "secp256k1_ec_pubkey_combine" :int
  (ctx :pointer) ;; secp256k1_context*
  (out (:pointer (:struct secp256k1-pubkey)))
  (ins (:pointer (:pointer (:struct secp256k1-pubkey))))
  (n size-t))



;;;-----------------------------------------------------------------------------
;;; High-level API

(defstruct (key (:constructor %make-key))
  bytes)

(defstruct (pubkey (:constructor %make-pubkey))
  bytes)

(defstruct (signature (:constructor %make-signature))
  bytes)

(defun make-key ()
  (%make-key :bytes (random-bytes 32)))

(defun make-pubkey (key)
  (%make-pubkey :bytes (ec-pubkey-create (key-bytes key))))

(defun parse-pubkey (bytes)
  (%make-pubkey :bytes (ec-pubkey-parse bytes)))

(defun serialize-pubkey (key)
  (ec-pubkey-serialize (key-bytes key)))

(defun parse-signature (bytes &key (type :relaxed))
  (let* ((bytes (ecase type
                  (:compact
                   (ecdsa-signature-parse-compact bytes))
                  (:der
                   (ecdsa-signature-parse-der bytes))
                  (:relaxed
                   (ecdsa-signature-parse-der-lax bytes)))))
    (%make-signature :bytes bytes)))

(defun serialize-signature (signature &key (type :der))
  (ecase type
    (:compact
     (ecdsa-signature-serialize-compact (signature-bytes signature)))
    (:der
     (ecdsa-signature-serialize-der (signature-bytes signature)))))

(defun make-signature (key hash)
  (%make-signature :bytes (ecdsa-sign hash (key-bytes key))))

(defun verify-signature (pubkey hash signature)
  (let* ((bytes  (signature-bytes signature))
         (nbytes (ecdsa-signature-normalize bytes)))
    (ecdsa-verify (or nbytes bytes) hash (pubkey-bytes pubkey))))
