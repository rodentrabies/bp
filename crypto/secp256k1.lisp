;;; Copyright (c) BP Developers & Contributors
;;; See the accompanying file LICENSE for the full license governing this code.

(uiop:define-package :bp.crypto.secp256k1 (:nicknames :secp256k1 :bp/crypto/secp256k1)
  (:use :cl :cffi)
  (:use :bp.crypto.random)
  (:export
   ;; Signature API
   #:ecdsa-sign
   #:ecdsa-verify
   ;; Key utilities
   #:ec-pubkey-parse
   #:ec-pubkey-serialize
   #:ec-pubkey-create
   #:ec-seckey-verify
   #:ec-seckey-negate
   #:ec-pubkey-negate
   ;; Signature utilities
   #:ecdsa-signature-parse-compact
   #:ecdsa-signature-serialize-compact
   #:ecdsa-signature-parse-der
   #:ecdsa-signature-serialize-der
   #:ecdsa-signature-normalize
   ;; High-level API
   #:key
   #:make-key
   #:pubkey
   #:make-pubkey
   #:parse-pubkey
   #:serialize-pubkey
   #:combine-pubkeys
   #:signature
   #:make-signature
   #:verify-signature
   #:parse-signature
   #:serialize-signature))

(in-package :bp.crypto.secp256k1)

;;;-----------------------------------------------------------------------------
;;; libsecp256k1
;;;
;;; This file contains manual translation of the include/*.h files from
;;; libsecp256k1 as well as wrappers around API functions that accept Lisp
;;; values, translate them into foreign objects and call corresponding C
;;; functions.
;;;
;;; libsecp256k1 version:
;;;
;;;     v0.7.1 (1a53f4961f337b4d166c25fce72ef0dc88806618)
;;;
;;;
;;; Comments for CFFI declarations are taken directly from the libsecp256k1
;;; include/*.h files without any changes.
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
;;;

(define-foreign-library libsecp256k1
  (t (:default "libsecp256k1")))

(use-foreign-library libsecp256k1)

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

(defmacro bytes-clear-foreign (pointer size)
  `(let ((pointer ,pointer)
         (size ,size))
     (loop
        :for i :below size
        :do (setf (mem-aref pointer :unsigned-char i) 0))))


;;;-----------------------------------------------------------------------------
;;; secp256k1.h
;;;
;;; Unless explicitly stated all pointer arguments must not be NULL.
;;;
;;; The following rules specify the order of arguments in API calls:
;;;
;;; 1. Context pointers go first, followed by output arguments, combined
;;;    output/input arguments, and finally input-only arguments.
;;; 2. Array lengths always immediately follow the argument whose length
;;;    they describe, even if this violates rule 1.
;;; 3. Within the OUT/OUTIN/IN groups, pointers to data that is typically generated
;;;    later go first. This means: signatures, public nonces, secret nonces,
;;;    messages, public keys, secret keys, tweaks.
;;; 4. Arguments that are not data pointers go last, from more complex to less
;;;    complex: function pointers, algorithm names, messages, void pointers,
;;;    counts, flags, booleans.
;;; 5. Opaque data pointers follow the function pointer they are to be passed to.
;;;

;; Opaque data structure that holds context information
;;
;; The primary purpose of context objects is to store randomization data for
;; enhanced protection against side-channel leakage. This protection is only
;; effective if the context is randomized after its creation. See
;; secp256k1_context_create for creation of contexts and
;; secp256k1_context_randomize for randomization.
;;
;; A secondary purpose of context objects is to store pointers to callback
;; functions that the library will call when certain error states arise. See
;; secp256k1_context_set_error_callback as well as
;; secp256k1_context_set_illegal_callback for details. Future library versions
;; may use context objects for additional purposes.
;;
;; A constructed context can safely be used from multiple threads
;; simultaneously, but API calls that take a non-const pointer to a context
;; need exclusive access to it. In particular this is the case for
;; secp256k1_context_destroy, secp256k1_context_preallocated_destroy,
;; and secp256k1_context_randomize.
;;
;; Regarding randomization, either do it once at creation time (in which case
;; you do not need any locking for the other calls), or use a read-write lock.
;;
(defcstruct secp256k1-context)

;; Opaque data structure that holds a parsed and valid public key.
;;
;; The exact representation of data inside is implementation defined and not
;; guaranteed to be portable between different platforms or versions. It is
;; however guaranteed to be 64 bytes in size, and can be safely copied/moved.
;; If you need to convert to a format suitable for storage or transmission,
;; use secp256k1_ec_pubkey_serialize and secp256k1_ec_pubkey_parse. To
;; compare keys, use secp256k1_ec_pubkey_cmp.
;;
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
;;
(defcstruct secp256k1-ecdsa-signature
  (data :unsigned-char :count 64))

;; A pointer to a function to deterministically generate a nonce.
;;
;; Returns: 1 if a nonce was successfully generated. 0 will cause signing to fail.
;; Out:     nonce32:   pointer to a 32-byte array to be filled by the function.
;; In:      msg32:     the 32-byte message hash being verified (will not be NULL)
;;          key32:     pointer to a 32-byte secret key (will not be NULL)
;;          algo16:    pointer to a 16-byte array describing the signature
;;                     algorithm (will be NULL for ECDSA for compatibility).
;;          data:      Arbitrary data pointer that is passed through.
;;          attempt:   how many iterations we have tried to find a nonce.
;;                     This will almost always be 0, but different attempt values
;;                     are required to result in a different nonce.
;;
;; Except for test cases, this function should compute some cryptographic hash
;; of the message, the algorithm, the key and the attempt.
;;
;; typedef int (*secp256k1_nonce_function)(
;;     unsigned char *nonce32,
;;     const unsigned char *msg32,
;;     const unsigned char *key32,
;;     const unsigned char *algo16,
;;     void *data,
;;     unsigned int attempt
;; );
(defctype secp256k1-nonce-function :pointer)

;; All flags' lower 8 bits indicate what they're for. Do not use directly.
(defconstant +secp256k1-flags-type-mask+        (1- (ash 1 8)))
(defconstant +secp256k1-flags-type-context+     (ash 1 0))
(defconstant +secp256k1-flags-type-compression+ (ash 1 1))

;; The higher bits contain the actual data. Do not use directly.
(defconstant +secp256k1-flags-bit-context-verify+     (ash 1  8))
(defconstant +secp256k1-flags-bit-context-sign+       (ash 1  9))
(defconstant +secp256k1-flags-bit-context-declassify+ (ash 1 10))
(defconstant +secp256k1-flags-bit-compression+        (ash 1  8))

;; Context flags to pass to secp256k1_context_create, secp256k1_context_preallocated_size, and
;; secp256k1_context_preallocated_create.
(defconstant +secp256k1-context-none+ +secp256k1-flags-type-context+)

;; Deprecated context flags. These flags are treated equivalent to SECP256K1_CONTEXT_NONE.
(defconstant +secp256k1-context-verify+ (logior +secp256k1-flags-type-context+
                                                +secp256k1-flags-bit-context-verify+))

(defconstant +secp256k1-context-sign+ (logior +secp256k1-flags-type-context+
                                              +secp256k1-flags-bit-context-sign+))

;; Testing flag. Do not use.
(defconstant +secp256k1-context-declassify+ (logior +secp256k1-flags-type-context+
                                                    +secp256k1-flags-bit-context-declassify+))

;; Flag to pass to secp256k1_ec_pubkey_serialize.
(defconstant +secp256k1-ec-compressed+ (logior +secp256k1-flags-type-compression+
                                               +secp256k1-flags-bit-compression+))

(defconstant +secp256k1-ec-uncompressed+ +secp256k1-flags-type-compression+)

;; Prefix byte used to tag various encoded curvepoints for specific purposes.
(defconstant +secp256k1-tag-pubkey-even+         #x02)
(defconstant +secp256k1-tag-pubkey-odd+          #x03)
(defconstant +secp256k1-tag-pubkey-uncompressed+ #x04)
(defconstant +secp256k1-tag-pubkey-hybrid-even+  #x06)
(defconstant +secp256k1-tag-pubkey-hybrid-odd+   #x07)

;; A built-in constant secp256k1 context object with static storage duration, to be
;; used in conjunction with secp256k1_selftest.
;;
;; This context object offers *only limited functionality* , i.e., it cannot be used
;; for API functions that perform computations involving secret keys, e.g., signing
;; and public key generation. If this restriction applies to a specific API function,
;; it is mentioned in its documentation. See secp256k1_context_create if you need a
;; full context object that supports all functionality offered by the library.
;;
;; It is highly recommended to call secp256k1_selftest before using this context.
;;
(defcvar "secp256k1_context_static" (:pointer (:struct secp256k1-context)))

;; Deprecated alias for secp256k1_context_static.
(defcvar "secp256k1_context_no_precomp" (:pointer (:struct secp256k1-context)))

;; Perform basic self tests (to be used in conjunction with secp256k1_context_static)
;;
;; This function performs self tests that detect some serious usage errors and
;; similar conditions, e.g., when the library is compiled for the wrong endianness.
;; This is a last resort measure to be used in production. The performed tests are
;; very rudimentary and are not intended as a replacement for running the test
;; binaries.
;;
;; It is highly recommended to call this before using secp256k1_context_static.
;; It is not necessary to call this function before using a context created with
;; secp256k1_context_create (or secp256k1_context_preallocated_create), which will
;; take care of performing the self tests.
;;
;; If the tests fail, this function will call the default error handler to abort the
;; program (see secp256k1_context_set_error_callback).
;;
(defcfun "secp256k1_selftest" :void)

;; Create a secp256k1 context object (in dynamically allocated memory).
;;
;; This function uses malloc to allocate memory. It is guaranteed that malloc is
;; called at most once for every call of this function. If you need to avoid dynamic
;; memory allocation entirely, see secp256k1_context_static and the functions in
;; secp256k1_preallocated.h.
;;
;; Returns: a newly created context object.
;; In:      flags: Always set to SECP256K1_CONTEXT_NONE (see below).
;;
;; The only valid non-deprecated flag in recent library versions is
;; SECP256K1_CONTEXT_NONE, which will create a context sufficient for all functionality
;; offered by the library. All other (deprecated) flags will be treated as equivalent
;; to the SECP256K1_CONTEXT_NONE flag. Though the flags parameter primarily exists for
;; historical reasons, future versions of the library may introduce new flags.
;;
;; If the context is intended to be used for API functions that perform computations
;; involving secret keys, e.g., signing and public key generation, then it is highly
;; recommended to call secp256k1_context_randomize on the context before calling
;; those API functions. This will provide enhanced protection against side-channel
;; leakage, see secp256k1_context_randomize for details.
;;
;; Do not create a new context object for each operation, as construction and
;; randomization can take non-negligible time.
;;
(defcfun "secp256k1_context_create" (:pointer (:struct secp256k1-context))
  (flags :unsigned-int))

(defun context-create ()
  (secp256k1-context-create +secp256k1-context-none+))

;; Copy a secp256k1 context object (into dynamically allocated memory).
;;
;; This function uses malloc to allocate memory. It is guaranteed that malloc is
;; called at most once for every call of this function. If you need to avoid dynamic
;; memory allocation entirely, see the functions in secp256k1_preallocated.h.
;;
;; Returns: a newly created context object.
;; Args:    ctx: an existing context to copy
;;
(defcfun "secp256k1_context_clone" (:pointer (:struct secp256k1-context))
  (ctx (:pointer (:struct secp256k1-context))))

;; Destroy a secp256k1 context object (created in dynamically allocated memory).
;;
;; The context pointer may not be used afterwards.
;;
;; The context to destroy must have been created using secp256k1_context_create
;; or secp256k1_context_clone. If the context has instead been created using
;; secp256k1_context_preallocated_create or secp256k1_context_preallocated_clone, the
;; behaviour is undefined. In that case, secp256k1_context_preallocated_destroy must
;; be used instead.
;;
;; Args:   ctx: an existing context to destroy, constructed using
;;              secp256k1_context_create or secp256k1_context_clone
;;
(defcfun "secp256k1_context_destroy" :void
  (ctx (:pointer (:struct secp256k1-context))))

(defun context-destroy (ctx)
  (secp256k1-context-destroy ctx))

;; Randomizes the context to provide enhanced protection against side-channel leakage.
;;
;; Returns: 1: randomization successful (or called on copy of secp256k1_context_static)
;;          0: error
;; Args:    ctx:       pointer to a context object.
;; In:      seed32:    pointer to a 32-byte random seed (NULL resets to initial state)
;;
;; While secp256k1 code is written and tested to be constant-time no matter what
;; secret values are, it is possible that a compiler may output code which is not,
;; and also that the CPU may not emit the same radio frequencies or draw the same
;; amount of power for all values. Randomization of the context shields against
;; side-channel observations which aim to exploit secret-dependent behaviour in
;; certain computations which involve secret keys.
;;
;; It is highly recommended to call this function on contexts returned from
;; secp256k1_context_create or secp256k1_context_clone (or from the corresponding
;; functions in secp256k1_preallocated.h) before using these contexts to call API
;; functions that perform computations involving secret keys, e.g., signing and
;; public key generation. It is possible to call this function more than once on
;; the same context, and doing so before every few computations involving secret
;; keys is recommended as a defense-in-depth measure.
;;
;; Currently, the random seed is mainly used for blinding multiplications of a
;; secret scalar with the elliptic curve base point. Multiplications of this
;; kind are performed by exactly those API functions which are documented to
;; require a context that is not the secp256k1_context_static. As a rule of thumb,
;; these are all functions which take a secret key (or a keypair) as an input.
;; A notable exception to that rule is the ECDH module, which relies on a different
;; kind of elliptic curve point multiplication and thus does not benefit from
;; enhanced protection against side-channel leakage currently.
;;
;; It is safe call this function on a copy of secp256k1_context_static in writable
;; memory (e.g., obtained via secp256k1_context_clone). In that case, this
;; function is guaranteed to return 1, but the call will have no effect because
;; the static context (or a copy thereof) is not meant to be randomized.
;;
(defcfun "secp256k1_context_randomize" :int
  (ctx    (:pointer (:struct secp256k1-context)))
  (seed32 (:pointer :unsigned-char)))

(defun context-randomize (ctx)
  (with-foreign-objects
      ((cseed32 :unsigned-char 32))
    (bytes-to-foreign (random-bytes 32) cseed32 32)
    (unwind-protect
         (assert (not (zerop (secp256k1-context-randomize ctx cseed32)))
                 () "Context randomization error.")
      (bytes-clear-foreign cseed32 32)))
  ctx)

(defvar *secp256k1-context* (context-randomize (context-create)))

;; Set a callback function to be called when an illegal argument is passed to
;; an API call. It will only trigger for violations that are mentioned
;; explicitly in the header.
;;
;; The philosophy is that these shouldn't be dealt with through a
;; specific return value, as calling code should not have branches to deal with
;; the case that this code itself is broken.
;;
;; On the other hand, during debug stage, one would want to be informed about
;; such mistakes, and the default (crashing) may be inadvisable.
;; When this callback is triggered, the API function called is guaranteed not
;; to cause a crash, though its return value and output arguments are
;; undefined.
;;
;; When this function has not been called (or called with fn==NULL), then the
;; default handler will be used. The library provides a default handler which
;; writes the message to stderr and calls abort. This default handler can be
;; replaced at link time if the preprocessor macro
;; USE_EXTERNAL_DEFAULT_CALLBACKS is defined, which is the case if the build
;; has been configured with --enable-external-default-callbacks. Then the
;; following two symbols must be provided to link against:
;;  - void secp256k1_default_illegal_callback_fn(const char* message, void* data);
;;  - void secp256k1_default_error_callback_fn(const char* message, void* data);
;; The library can call these default handlers even before a proper callback data
;; pointer could have been set using secp256k1_context_set_illegal_callback or
;; secp256k1_context_set_error_callback, e.g., when the creation of a context
;; fails. In this case, the corresponding default handler will be called with
;; the data pointer argument set to NULL.
;;
;; Args: ctx:  an existing context object.
;; In:   fun:  a pointer to a function to call when an illegal argument is
;;             passed to the API, taking a message and an opaque pointer.
;;             (NULL restores the default handler.)
;;       data: the opaque pointer to pass to fun above, must be NULL for the default handler.
;;
;; See also secp256k1_context_set_error_callback.
;;
(defcfun "secp256k1_context_set_illegal_callback" :void
  (ctx  (:pointer (:struct secp256k1-context)))
  (fun  :pointer)  ;; void (*fun)(const char* message, void* data)
  (data :pointer)) ;; void*

;; Set a callback function to be called when an internal consistency check
;; fails.
;;
;; The default callback writes an error message to stderr and calls abort
;; to abort the program.
;;
;; This can only trigger in case of a hardware failure, miscompilation,
;; memory corruption, serious bug in the library, or other error would can
;; otherwise result in undefined behaviour. It will not trigger due to mere
;; incorrect usage of the API (see secp256k1_context_set_illegal_callback
;; for that). After this callback returns, anything may happen, including
;; crashing.
;;
;; Args: ctx:  an existing context object.
;; In:   fun:  a pointer to a function to call when an internal error occurs,
;;             taking a message and an opaque pointer (NULL restores the
;;             default handler, see secp256k1_context_set_illegal_callback
;;             for details).
;;       data: the opaque pointer to pass to fun above, must be NULL for the default handler.
;;
;; See also secp256k1_context_set_illegal_callback.
;;
(defcfun "secp256k1_context_set_error_callback" :void
  (ctx  (:pointer (:struct secp256k1-context)))
  (fun  :pointer)  ;; void (*fun)(const char* message, void* data)
  (data :pointer)) ;; void*

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
;;
(defcfun "secp256k1_ec_pubkey_parse" :int
  (ctx      (:pointer (:struct secp256k1-context)))
  (pubkey   (:pointer (:struct secp256k1-pubkey)))
  (input    (:pointer :unsigned-char))
  (inputlen :size))

(defun ec-pubkey-parse (input)
  (let ((inputlen (length input)))
    (with-foreign-objects
        ((cpubkey '(:struct secp256k1-pubkey))
         (cinput :unsigned-char inputlen))
      (bytes-to-foreign input cinput inputlen)
      (unless (zerop (secp256k1-ec-pubkey-parse *secp256k1-context* cpubkey
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
;;
(defcfun "secp256k1_ec_pubkey_serialize" :int
  (ctx       (:pointer (:struct secp256k1-context)))
  (output    (:pointer :unsigned-char))
  (outputlen (:pointer :size))
  (pubkey    (:pointer (:struct secp256k1-pubkey)))
  (flags     :unsigned-int))

(defun ec-pubkey-serialize (pubkey &key compressed)
  (let ((outputlen (if compressed 33 65)))
    (with-foreign-objects
        ((coutput :unsigned-char outputlen)
         (coutputlen :size 1)
         (cpubkey '(:struct secp256k1-pubkey)))
      (setf (mem-aref coutputlen :size 0) outputlen)
      (bytes-to-foreign pubkey cpubkey 64)
      (secp256k1-ec-pubkey-serialize *secp256k1-context* coutput coutputlen cpubkey
                                     (if compressed
                                         +secp256k1-ec-compressed+
                                         +secp256k1-ec-uncompressed+))
      (bytes-from-foreign nil coutput (mem-aref coutputlen :size 0)))))

;; Compare two public keys using lexicographic (of compressed serialization) order
;;
;; Returns: <0 if the first public key is less than the second
;;          >0 if the first public key is greater than the second
;;          0 if the two public keys are equal
;; Args: ctx:      a secp256k1 context object.
;; In:   pubkey1:  first public key to compare
;;       pubkey2:  second public key to compare
;;
(defcfun "secp256k1_ec_pubkey_cmp" :int
  (ctx     (:pointer (:struct secp256k1-context)))
  (pubkey1 (:pointer (:struct secp256k1-pubkey)))
  (pubkey2 (:pointer (:struct secp256k1-pubkey))))

;; Sort public keys using lexicographic (of compressed serialization) order
;;
;; Returns: 0 if the arguments are invalid. 1 otherwise.
;;
;; Args:     ctx: pointer to a context object
;; In:   pubkeys: array of pointers to pubkeys to sort
;;     n_pubkeys: number of elements in the pubkeys array
;;
(defcfun "secp256k1_ec_pubkey_sort" :int
  (ctx       (:pointer (:struct secp256k1-context)))
  (pubkeys   (:pointer (:pointer (:struct secp256k1-pubkey))))
  (n-pubkeys :size))

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
;; S are zero, the resulting sig value is guaranteed to fail verification for
;; any message and public key.
;;
(defcfun "secp256k1_ecdsa_signature_parse_compact" :int
  (ctx     (:pointer (:struct secp256k1-context)))
  (sig     (:pointer (:struct secp256k1-ecdsa-signature)))
  (input64 (:pointer :unsigned-char)))

(defun ecdsa-signature-parse-compact (input64)
  (with-foreign-objects
      ((csignature '(:struct secp256k1-ecdsa-signature))
       (cinput64 :unsigned-char 64))
    (bytes-to-foreign input64 cinput64 64)
    (unless (zerop (secp256k1-ecdsa-signature-parse-compact
                    *secp256k1-context* csignature cinput64))
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
;; encoded numbers are out of range, signature verification with it is
;; guaranteed to fail for every message and public key.
;;
(defcfun "secp256k1_ecdsa_signature_parse_der" :int
  (ctx      (:pointer (:struct secp256k1-context)))
  (sig      (:pointer (:struct secp256k1-ecdsa-signature)))
  (input    (:pointer :unsigned-char))
  (inputlen :size))

(defun ecdsa-signature-parse-der (input)
  (let ((inputlen (length input)))
    (with-foreign-objects
        ((csignature '(:struct secp256k1-ecdsa-signature))
         (cinput :unsigned-char inputlen))
      (bytes-to-foreign input cinput inputlen)
      (unless (zerop (secp256k1-ecdsa-signature-parse-der
                      *secp256k1-context* csignature cinput inputlen))
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
                    (cond ((not (= 0 (logand lenbyte #x80)))
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
                          (t
                           (setf ,clen lenbyte)))
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
      (unless (= 0 (logand lenbyte #x80))
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
      (unless overflow
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
;;
(defcfun "secp256k1_ecdsa_signature_serialize_der" :int
  (ctx       (:pointer (:struct secp256k1-context)))
  (output    (:pointer :unsigned-char))
  (outputlen (:pointer :size))
  (sig       (:pointer (:struct secp256k1-ecdsa-signature))))

(defun ecdsa-signature-serialize-der (signature)
  (with-foreign-objects
      ((coutput :unsigned-char 74)
       (coutputlen :size 1)
       (csignature '(:struct secp256k1-ecdsa-signature)))
    (setf (mem-aref coutputlen :size 0) 74)
    (bytes-to-foreign signature csignature 64)
    (unless (zerop (secp256k1-ecdsa-signature-serialize-der
                    *secp256k1-context* coutput coutputlen csignature))
      (bytes-from-foreign nil coutput (mem-aref coutputlen :size 0)))))

;; Serialize an ECDSA signature in compact (64 byte) format.
;;
;; Returns: 1
;; Args:   ctx:       a secp256k1 context object
;; Out:    output64:  a pointer to a 64-byte array to store the compact serialization
;; In:     sig:       a pointer to an initialized signature object
;;
;; See secp256k1_ecdsa_signature_parse_compact for details about the encoding.
;;
(defcfun "secp256k1_ecdsa_signature_serialize_compact" :int
  (ctx      (:pointer (:struct secp256k1-context)))
  (output64 (:pointer :unsigned-char))
  (sig      (:pointer (:struct secp256k1-ecdsa-signature))))

(defun ecdsa-signature-serialize-compact (signature)
  (with-foreign-objects
      ((coutput :unsigned-char 64)
       (csignature '(:struct secp256k1-ecdsa-signature)))
    (bytes-to-foreign signature csignature 64)
    (unless (zerop (secp256k1-ecdsa-signature-serialize-compact
                    *secp256k1-context* coutput csignature))
      (bytes-from-foreign nil coutput 64))))

;; Verify an ECDSA signature.
;;
;; Returns: 1: correct signature
;;          0: incorrect or unparseable signature
;; Args:    ctx:       a secp256k1 context object.
;; In:      sig:       the signature being verified.
;;          msghash32: the 32-byte message hash being verified.
;;                     The verifier must make sure to apply a cryptographic
;;                     hash function to the message by itself and not accept an
;;                     msghash32 value directly. Otherwise, it would be easy to
;;                     create a "valid" signature without knowledge of the
;;                     secret key. See also
;;                     https://bitcoin.stackexchange.com/a/81116/35586 for more
;;                     background on this topic.
;;          pubkey:    pointer to an initialized public key to verify with.
;;
;; To avoid accepting malleable signatures, only ECDSA signatures in lower-S
;; form are accepted.
;;
;; If you need to accept ECDSA signatures from sources that do not obey this
;; rule, apply secp256k1_ecdsa_signature_normalize to the signature prior to
;; verification, but be aware that doing so results in malleable signatures.
;;
;; For details, see the comments for that function.
;;
(defcfun "secp256k1_ecdsa_verify" :int
  (ctx    (:pointer (:struct secp256k1-context)))
  (sig    (:pointer (:struct secp256k1-ecdsa-signature)))
  (msg32  (:pointer :unsigned-char))
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
                    *secp256k1-context* csignature cmsg32 cpubkey))
      t)))

;; Convert a signature to a normalized lower-S form.
;;
;; Returns: 1 if sigin was not normalized, 0 if it already was.
;; Args: ctx:    a secp256k1 context object
;; Out:  sigout: a pointer to a signature to fill with the normalized form,
;;               or copy if the input was already normalized. (can be NULL if
;;               you're only interested in whether the input was already
;;               normalized).
;; In:   sigin:  a pointer to a signature to check/normalize (can be identical to sigout)
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
;;
(defcfun "secp256k1_ecdsa_signature_normalize" :int
  (ctx    (:pointer (:struct secp256k1-context)))
  (sigout (:pointer (:struct secp256k1-ecdsa-signature)))
  (sigin  (:pointer (:struct secp256k1-ecdsa-signature))))

(defun ecdsa-signature-normalize (sigin)
  (with-foreign-objects
      ((csigout '(:struct secp256k1-ecdsa-signature))
       (csigin '(:struct secp256k1-ecdsa-signature)))
    (bytes-to-foreign sigin csigin 64)
    (unless (zerop (secp256k1-ecdsa-signature-normalize
                    *secp256k1-context* csigout csigin))
      (bytes-from-foreign nil csigout 64))))

;; An implementation of RFC6979 (using HMAC-SHA256) as nonce generation function.
;; If a data pointer is passed, it is assumed to be a pointer to 32 bytes of
;; extra entropy.
;;
(defcvar "secp256k1_nonce_function_rfc6979" secp256k1-nonce-function)

;; A default safe nonce generation function (currently equal to secp256k1_nonce_function_rfc6979).
;;
(defcvar "secp256k1_nonce_function_default" secp256k1-nonce-function)

;; Create an ECDSA signature.
;;
;; Returns: 1: signature created
;;          0: the nonce generation function failed, or the secret key was invalid.
;; Args:    ctx:       pointer to a context object (not secp256k1_context_static).
;; Out:     sig:       pointer to an array where the signature will be placed.
;; In:      msghash32: the 32-byte message hash being signed.
;;          seckey:    pointer to a 32-byte secret key.
;;          noncefp:   pointer to a nonce generation function. If NULL,
;;                     secp256k1_nonce_function_default is used.
;;          ndata:     pointer to arbitrary data used by the nonce generation function
;;                     (can be NULL). If it is non-NULL and
;;                     secp256k1_nonce_function_default is used, then ndata must be a
;;                     pointer to 32-bytes of additional data.
;;
;; The created signature is always in lower-S form. See
;; secp256k1_ecdsa_signature_normalize for more details.
;;
(defcfun "secp256k1_ecdsa_sign" :int
  (ctx     (:pointer (:struct secp256k1-context)))
  (sig     (:pointer (:struct secp256k1-ecdsa-signature)))
  (msg32   (:pointer :unsigned-char))
  (seckey  (:pointer :unsigned-char))
  (noncefp secp256k1-nonce-function)
  (ndata   :pointer)) ;; void*

(defun ecdsa-sign (msg32 seckey)
  "Create an ECDSA signature."
  (with-foreign-objects
      ((csignature '(:struct secp256k1-ecdsa-signature))
       (cmsg32 :unsigned-char 32)
       (cseckey :unsigned-char 32))
    (bytes-to-foreign msg32 cmsg32 32)
    (bytes-to-foreign seckey cseckey 32)
    (unwind-protect
         (unless (zerop (secp256k1-ecdsa-sign *secp256k1-context* csignature cmsg32 cseckey
                                              (null-pointer) (null-pointer)))
           (bytes-from-foreign nil csignature 64))
      (bytes-clear-foreign cseckey 32))))

;; Verify an ECDSA secret key.
;;
;; A secret key is valid if it is not 0 and less than the secp256k1 curve order
;; when interpreted as an integer (most significant byte first). The
;; probability of choosing a 32-byte string uniformly at random which is an
;; invalid secret key is negligible.
;;
;; Returns: 1: secret key is valid
;;          0: secret key is invalid
;; Args:    ctx: pointer to a context object.
;; In:      seckey: pointer to a 32-byte secret key.
;;
(defcfun "secp256k1_ec_seckey_verify" :int
  (ctx    (:pointer (:struct secp256k1-context)))
  (seckey (:pointer :unsigned-char)))

(defun ec-seckey-verify (seckey)
  (with-foreign-objects
      ((cseckey :unsigned-char 32))
    (bytes-to-foreign seckey cseckey 32)
    (unwind-protect
         (unless (zerop (secp256k1-ec-seckey-verify *secp256k1-context* cseckey))
           t)
      (bytes-clear-foreign cseckey 32))))

;; Compute the public key for a secret key.
;;
;; Returns: 1: secret was valid, public key stores.
;;          0: secret was invalid, try again.
;; Args:    ctx:    pointer to a context object (not secp256k1_context_static).
;; Out:     pubkey: pointer to the created public key.
;; In:      seckey: pointer to a 32-byte secret key.
;;
(defcfun "secp256k1_ec_pubkey_create" :int
  (ctx    (:pointer (:struct secp256k1-context)))
  (pubkey (:pointer (:struct secp256k1-pubkey)))
  (seckey (:pointer :unsigned-char)))

(defun ec-pubkey-create (seckey)
  (with-foreign-objects
      ((cpubkey '(:struct secp256k1-pubkey))
       (cseckey :unsigned-char 32))
    (bytes-to-foreign seckey cseckey 32)
    (unwind-protect
         (unless (zerop (secp256k1-ec-pubkey-create *secp256k1-context* cpubkey cseckey))
           (bytes-from-foreign nil cpubkey 64))
      (bytes-clear-foreign cseckey 32))))

;; Negates a secret key in place.
;;
;; Returns: 0 if the given secret key is invalid according to
;;          secp256k1_ec_seckey_verify. 1 otherwise
;; Args:   ctx:    pointer to a context object
;; In/Out: seckey: pointer to the 32-byte secret key to be negated. If the
;;                 secret key is invalid according to
;;                 secp256k1_ec_seckey_verify, this function returns 0 and
;;                 seckey will be set to some unspecified value.
;;
(defcfun "secp256k1_ec_seckey_negate" :int
  (ctx    (:pointer (:struct secp256k1-context)))
  (seckey (:pointer :unsigned-char)))

(defun ec-seckey-negate (seckey)
  (with-foreign-objects
      ((cseckey :unsigned-char 32))
    (bytes-to-foreign seckey cseckey 32)
    (unwind-protect
         (unless (zerop (secp256k1-ec-seckey-negate *secp256k1-context* cseckey))
           (bytes-from-foreign seckey cseckey 32))
      (bytes-clear-foreign cseckey 32))))

;; Negates a public key in place.
;;
;; Returns: 1 always
;; Args:   ctx:        pointer to a context object
;; In/Out: pubkey:     pointer to the public key to be negated.
;;
(defcfun "secp256k1_ec_pubkey_negate" :int
  (ctx    (:pointer (:struct secp256k1-context)))
  (pubkey (:pointer (:struct secp256k1-pubkey))))

(defun ec-pubkey-negate (pubkey)
  (with-foreign-objects
      ((cpubkey '(:struct secp256k1-pubkey)))
    (bytes-to-foreign pubkey cpubkey 64)
    (secp256k1-ec-pubkey-negate *secp256k1-context* cpubkey)
    (bytes-from-foreign pubkey cpubkey 64)))

;; Tweak a secret key by adding tweak to it.
;;
;; Returns: 0 if the arguments are invalid or the resulting secret key would be
;;          invalid (only when the tweak is the negation of the secret key). 1
;;          otherwise.
;; Args:    ctx:   pointer to a context object.
;; In/Out: seckey: pointer to a 32-byte secret key. If the secret key is
;;                 invalid according to secp256k1_ec_seckey_verify, this
;;                 function returns 0. seckey will be set to some unspecified
;;                 value if this function returns 0.
;; In:    tweak32: pointer to a 32-byte tweak. If the tweak is invalid according to
;;                 secp256k1_ec_seckey_verify, this function returns 0. For
;;                 uniformly random 32-byte arrays the chance of being invalid
;;                 is negligible (around 1 in 2^128).
;;
(defcfun "secp256k1_ec_seckey_tweak_add" :int
  (ctx    (:pointer (:struct secp256k1-context)))
  (seckey (:pointer :unsigned-char))
  (tweak  (:pointer :unsigned-char)))

;; Tweak a public key by adding tweak times the generator to it.
;;
;; Returns: 0 if the arguments are invalid or the resulting public key would be
;;          invalid (only when the tweak is the negation of the corresponding
;;          secret key). 1 otherwise.
;; Args:    ctx:   pointer to a context object.
;; In/Out: pubkey: pointer to a public key object. pubkey will be set to an
;;                 invalid value if this function returns 0.
;; In:    tweak32: pointer to a 32-byte tweak. If the tweak is invalid according to
;;                 secp256k1_ec_seckey_verify, this function returns 0. For
;;                 uniformly random 32-byte arrays the chance of being invalid
;;                 is negligible (around 1 in 2^128).
;;
(defcfun "secp256k1_ec_pubkey_tweak_add" :int
  (ctx    (:pointer (:struct secp256k1-context)))
  (pubkey (:pointer (:struct secp256k1-pubkey)))
  (tweak  (:pointer :unsigned-char)))

;; Tweak a secret key by multiplying it by a tweak.
;;
;; Returns: 0 if the arguments are invalid. 1 otherwise.
;; Args:   ctx:    pointer to a context object.
;; In/Out: seckey: pointer to a 32-byte secret key. If the secret key is
;;                 invalid according to secp256k1_ec_seckey_verify, this
;;                 function returns 0. seckey will be set to some unspecified
;;                 value if this function returns 0.
;; In:    tweak32: pointer to a 32-byte tweak. If the tweak is invalid according to
;;                 secp256k1_ec_seckey_verify, this function returns 0. For
;;                 uniformly random 32-byte arrays the chance of being invalid
;;                 is negligible (around 1 in 2^128).
;;
(defcfun "secp256k1_ec_seckey_tweak_mul" :int
  (ctx    (:pointer (:struct secp256k1-context)))
  (seckey (:pointer :unsigned-char))
  (tweak  (:pointer :unsigned-char)))

;; Tweak a public key by multiplying it by a tweak value.
;;
;; Returns: 0 if the arguments are invalid. 1 otherwise.
;; Args:    ctx:   pointer to a context object.
;; In/Out: pubkey: pointer to a public key object. pubkey will be set to an
;;                 invalid value if this function returns 0.
;; In:    tweak32: pointer to a 32-byte tweak. If the tweak is invalid according to
;;                 secp256k1_ec_seckey_verify, this function returns 0. For
;;                 uniformly random 32-byte arrays the chance of being invalid
;;                 is negligible (around 1 in 2^128).
;;
(defcfun "secp256k1_ec_pubkey_tweak_mul" :int
  (ctx    (:pointer (:struct secp256k1-context)))
  (pubkey (:pointer (:struct secp256k1-pubkey)))
  (tweak  (:pointer :unsigned-char)))

;; Add a number of public keys together.
;;
;; Returns: 1: the sum of the public keys is valid.
;;          0: the sum of the public keys is not valid.
;; Args:   ctx:        pointer to a context object.
;; Out:    out:        pointer to a public key object for placing the resulting public key.
;; In:     ins:        pointer to array of pointers to public keys.
;;         n:          the number of public keys to add together (must be at least 1).
;;
(defcfun "secp256k1_ec_pubkey_combine" :int
  (ctx (:pointer (:struct secp256k1-context)))
  (out (:pointer (:struct secp256k1-pubkey)))
  (ins (:pointer (:pointer (:struct secp256k1-pubkey))))
  (n   :size))

(defun ec-pubkey-combine (ins)
  (let ((n (length ins)))
    (with-foreign-objects
        ((cins    '(:struct secp256k1-pubkey) n)
         (pins    '(:pointer (:struct secp256k1-pubkey)) n)
         (cpubkey '(:struct secp256k1-pubkey)))
      (loop
        :for i   :below n
        :for in  :in ins
        :for cin := (mem-aptr cins '(:struct secp256k1-pubkey) i)
        :do (bytes-to-foreign in cin 64)
            (setf (mem-aref pins '(:pointer (:struct secp256k1-pubkey)) i) cin))
      (unless (zerop (secp256k1-ec-pubkey-combine *secp256k1-context* cpubkey pins n))
        (bytes-from-foreign nil cpubkey 64)))))

;; Compute a tagged hash as defined in BIP-340.
;;
;; This is useful for creating a message hash and achieving domain separation
;; through an application-specific tag. This function returns
;; SHA256(SHA256(tag)||SHA256(tag)||msg). Therefore, tagged hash
;; implementations optimized for a specific tag can precompute the SHA256 state
;; after hashing the tag hashes.
;;
;; Returns: 1 always.
;; Args:    ctx: pointer to a context object
;; Out:  hash32: pointer to a 32-byte array to store the resulting hash
;; In:      tag: pointer to an array containing the tag
;;       taglen: length of the tag array
;;          msg: pointer to an array containing the message
;;       msglen: length of the message array
;;
(defcfun "secp256k1_tagged_sha256" :int
  (ctx    (:pointer (:struct secp256k1-context)))
  (hash32 (:pointer :unsigned-char))
  (tag    (:pointer :unsigned-char))
  (taglen :size)
  (msg    (:pointer :unsigned-char))
  (msglen :size))


;;;-----------------------------------------------------------------------------
;;; secp256k1_ecdh.h

;; A pointer to a function that hashes an EC point to obtain an ECDH secret
;;
;; Returns: 1 if the point was successfully hashed.
;;          0 will cause secp256k1_ecdh to fail and return 0.
;;          Other return values are not allowed, and the behaviour of
;;          secp256k1_ecdh is undefined for other return values.
;; Out:     output:     pointer to an array to be filled by the function
;; In:      x32:        pointer to a 32-byte x coordinate
;;          y32:        pointer to a 32-byte y coordinate
;;          data:       arbitrary data pointer that is passed through
;;
;; typedef int (*secp256k1_ecdh_hash_function)(
;;   unsigned char *output,
;;   const unsigned char *x32,
;;   const unsigned char *y32,
;;   void *data
;; );
(defctype secp256k1-ecdh-hash-function :pointer)

;; An implementation of SHA256 hash function that applies to compressed public key.
;; Populates the output parameter with 32 bytes.
;;
(defcvar "secp256k1_ecdh_hash_function_sha256" secp256k1-ecdh-hash-function)

;; A default ECDH hash function (currently equal to secp256k1_ecdh_hash_function_sha256).
;; Populates the output parameter with 32 bytes.
;;
(defcvar "secp256k1_ecdh_hash_function_default" secp256k1-ecdh-hash-function)

;; Compute an EC Diffie-Hellman secret in constant time
;;
;; Returns: 1: exponentiation was successful
;;          0: scalar was invalid (zero or overflow) or hashfp returned 0
;; Args:    ctx:        pointer to a context object.
;; Out:     output:     pointer to an array to be filled by hashfp.
;; In:      pubkey:     a pointer to a secp256k1_pubkey containing an initialized public key.
;;          seckey:     a 32-byte scalar with which to multiply the point.
;;          hashfp:     pointer to a hash function. If NULL,
;;                      secp256k1_ecdh_hash_function_sha256 is used
;;                      (in which case, 32 bytes will be written to output).
;;          data:       arbitrary data pointer that is passed through to hashfp
;;                      (can be NULL for secp256k1_ecdh_hash_function_sha256).
;;
(defcfun "secp256k1_ecdh" :int
  (ctx    (:pointer (:struct secp256k1-context)))
  (output (:pointer :unsigned-char))
  (pubkey (:pointer (:struct secp256k1-pubkey)))
  (seckey (:pointer :unsigned-char))
  (hashfp secp256k1-ecdh-hash-function)
  (data   :pointer)) ;; void*


;;;-----------------------------------------------------------------------------
;;; secp256k1_ellswift.h
;;;
;;; This module provides an implementation of ElligatorSwift as well as a
;;; version of x-only ECDH using it (including compatibility with BIP324).
;;;
;;; ElligatorSwift is described in https://eprint.iacr.org/2022/759 by
;;; Chavez-Saab, Rodriguez-Henriquez, and Tibouchi. It permits encoding
;;; uniformly chosen public keys as 64-byte arrays which are indistinguishable
;;; from uniformly random arrays.
;;;
;;; Let f be the function from pairs of field elements to point X coordinates,
;;; defined as follows (all operations modulo p = 2^256 - 2^32 - 977)
;;; f(u,t):
;;; - Let C = 0xa2d2ba93507f1df233770c2a797962cc61f6d15da14ecd47d8d27ae1cd5f852,
;;;   a square root of -3.
;;; - If u=0, set u=1 instead.
;;; - If t=0, set t=1 instead.
;;; - If u^3 + t^2 + 7 = 0, multiply t by 2.
;;; - Let X = (u^3 + 7 - t^2) / (2 * t)
;;; - Let Y = (X + t) / (C * u)
;;; - Return the first in [u + 4 * Y^2, (-X/Y - u) / 2, (X/Y - u) / 2] that is an
;;;   X coordinate on the curve (at least one of them is, for any u and t).
;;;
;;; Then an ElligatorSwift encoding of x consists of the 32-byte big-endian
;;; encodings of field elements u and t concatenated, where f(u,t) = x.
;;; The encoding algorithm is described in the paper, and effectively picks a
;;; uniformly random pair (u,t) among those which encode x.
;;;
;;; If the Y coordinate is relevant, it is given the same parity as t.
;;;
;;; Changes w.r.t. the paper:
;;; - The u=0, t=0, and u^3+t^2+7=0 conditions result in decoding to the point
;;;   at infinity in the paper. Here they are remapped to finite points.
;;; - The paper uses an additional encoding bit for the parity of y. Here the
;;;   parity of t is used (negating t does not affect the decoded x coordinate,
;;;   so this is possible).
;;;
;;; For mathematical background about the scheme, see the doc/ellswift.md file.
;;;

;; A pointer to a function used by secp256k1_ellswift_xdh to hash the shared X
;; coordinate along with the encoded public keys to a uniform shared secret.
;;
;; Returns: 1 if a shared secret was successfully computed.
;;          0 will cause secp256k1_ellswift_xdh to fail and return 0.
;;          Other return values are not allowed, and the behaviour of
;;          secp256k1_ellswift_xdh is undefined for other return values.
;; Out:     output:     pointer to an array to be filled by the function
;; In:      x32:        pointer to the 32-byte serialized X coordinate
;;                      of the resulting shared point (will not be NULL)
;;          ell_a64:    pointer to the 64-byte encoded public key of party A
;;                      (will not be NULL)
;;          ell_b64:    pointer to the 64-byte encoded public key of party B
;;                      (will not be NULL)
;;          data:       arbitrary data pointer that is passed through
;;
;; typedef int (*secp256k1_ellswift_xdh_hash_function)(
;;     unsigned char *output,
;;     const unsigned char *x32,
;;     const unsigned char *ell_a64,
;;     const unsigned char *ell_b64,
;;     void *data
;; );
(defctype secp256k1-ellswift-xdh-hash-function :pointer)

;; An implementation of an secp256k1_ellswift_xdh_hash_function which uses
;; SHA256(prefix64 || ell_a64 || ell_b64 || x32), where prefix64 is the 64-byte
;; array pointed to by data.
;;
(defcvar "secp256k1_ellswift_xdh_hash_function_prefix"
    secp256k1-ellswift-xdh-hash-function)

;; An implementation of an secp256k1_ellswift_xdh_hash_function compatible with
;; BIP324. It returns H_tag(ell_a64 || ell_b64 || x32), where H_tag is the
;; BIP340 tagged hash function with tag "bip324_ellswift_xonly_ecdh". Equivalent
;; to secp256k1_ellswift_xdh_hash_function_prefix with prefix64 set to
;; SHA256("bip324_ellswift_xonly_ecdh")||SHA256("bip324_ellswift_xonly_ecdh").
;; The data argument is ignored.
;;
(defcvar "secp256k1_ellswift_xdh_hash_function_bip324"
    secp256k1-ellswift-xdh-hash-function)

;; Construct a 64-byte ElligatorSwift encoding of a given pubkey.
;;
;; Returns: 1 always.
;; Args:    ctx:        pointer to a context object
;; Out:     ell64:      pointer to a 64-byte array to be filled
;; In:      pubkey:     pointer to a secp256k1_pubkey containing an
;;                      initialized public key
;;          rnd32:      pointer to 32 bytes of randomness
;;
;; It is recommended that rnd32 consists of 32 uniformly random bytes, not
;; known to any adversary trying to detect whether public keys are being
;; encoded, though 16 bytes of randomness (padded to an array of 32 bytes,
;; e.g., with zeros) suffice to make the result indistinguishable from
;; uniform. The randomness in rnd32 must not be a deterministic function of
;; the pubkey (it can be derived from the private key, though).
;;
;; It is not guaranteed that the computed encoding is stable across versions
;; of the library, even if all arguments to this function (including rnd32)
;; are the same.
;;
;; This function runs in variable time.
;;
(defcfun "secp256k1_ellswift_encode" :int
  (ctx    (:pointer (:struct secp256k1-context)))
  (ell64  (:pointer :unsigned-char))
  (pubkey (:pointer (:struct secp256k1-pubkey)))
  (rnd32  (:pointer :unsigned-char)))

;; Decode a 64-bytes ElligatorSwift encoded public key.
;;
;; Returns: always 1
;; Args:    ctx:        pointer to a context object
;; Out:     pubkey:     pointer to a secp256k1_pubkey that will be filled
;; In:      ell64:      pointer to a 64-byte array to decode
;;
;; This function runs in variable time.
;;
(defcfun "secp256k1_ellswift_decode" :int
  (ctx    (:pointer (:struct secp256k1-context)))
  (pubkey (:pointer (:struct secp256k1-pubkey)))
  (ell64  (:pointer :unsigned-char)))

;; Compute an ElligatorSwift public key for a secret key.
;;
;; Returns: 1: secret was valid, public key was stored.
;;          0: secret was invalid, try again.
;; Args:    ctx:        pointer to a context object (not secp256k1_context_static)
;; Out:     ell64:      pointer to a 64-byte array to receive the ElligatorSwift
;;                      public key
;; In:      seckey32:   pointer to a 32-byte secret key
;;          auxrnd32:   (optional) pointer to 32 bytes of randomness
;;
;; Constant time in seckey and auxrnd32, but not in the resulting public key.
;;
;; It is recommended that auxrnd32 contains 32 uniformly random bytes, though
;; it is optional (and does result in encodings that are indistinguishable from
;; uniform even without any auxrnd32). It differs from the (mandatory) rnd32
;; argument to secp256k1_ellswift_encode in this regard.
;;
;; This function can be used instead of calling secp256k1_ec_pubkey_create
;; followed by secp256k1_ellswift_encode. It is safer, as it uses the secret
;; key as entropy for the encoding (supplemented with auxrnd32, if provided).
;;
;; Like secp256k1_ellswift_encode, this function does not guarantee that the
;; computed encoding is stable across versions of the library, even if all
;; arguments (including auxrnd32) are the same.
;;
(defcfun "secp256k1_ellswift_create" :int
  (ctx      (:pointer (:struct secp256k1-context)))
  (ell64    (:pointer :unsigned-char))
  (seckey32 (:pointer :unsigned-char))
  (auxrnd32 (:pointer :unsigned-char)))

;; Given a private key, and ElligatorSwift public keys sent in both directions,
;; compute a shared secret using x-only Elliptic Curve Diffie-Hellman (ECDH).
;;
;; Returns: 1: shared secret was successfully computed
;;          0: secret was invalid or hashfp returned 0
;; Args:    ctx:       pointer to a context object.
;; Out:     output:    pointer to an array to be filled by hashfp.
;; In:      ell_a64:   pointer to the 64-byte encoded public key of party A
;;                     (will not be NULL)
;;          ell_b64:   pointer to the 64-byte encoded public key of party B
;;                     (will not be NULL)
;;          seckey32:  pointer to our 32-byte secret key
;;          party:     boolean indicating which party we are: zero if we are
;;                     party A, non-zero if we are party B. seckey32 must be
;;                     the private key corresponding to that party's ell_?64.
;;                     This correspondence is not checked.
;;          hashfp:    pointer to a hash function.
;;          data:      arbitrary data pointer passed through to hashfp.
;;
;; Constant time in seckey32.
;;
;; This function is more efficient than decoding the public keys, and performing
;; ECDH on them.
;;
(defcfun "secp256k1_ellswift_xdh" :int
  (ctx      (:pointer (:struct secp256k1-context)))
  (output   (:pointer :unsigned-char))
  (ell-a64  (:pointer :unsigned-char))
  (ell-b64  (:pointer :unsigned-char))
  (seckey32 (:pointer :unsigned-char))
  (party    :int)
  (hashfp   secp256k1-ellswift-xdh-hash-function)
  (data     :pointer)) ;; void*


;;;-----------------------------------------------------------------------------
;;; secp256k1_preallocated.h
;;;
;;; The module provided by this header file is intended for settings in which it
;;; is not possible or desirable to rely on dynamic memory allocation. It provides
;;; functions for creating, cloning, and destroying secp256k1 context objects in a
;;; contiguous fixed-size block of memory provided by the caller.
;;;
;;; Context objects created by functions in this module can be used like contexts
;;; objects created by functions in secp256k1.h, i.e., they can be passed to any
;;; API function that expects a context object (see secp256k1.h for details). The
;;; only exception is that context objects created by functions in this module
;;; must be destroyed using secp256k1_context_preallocated_destroy (in this
;;; module) instead of secp256k1_context_destroy (in secp256k1.h).
;;;
;;; It is guaranteed that functions in this module will not call malloc or its
;;; friends realloc, calloc, and free.
;;;

;; Determine the memory size of a secp256k1 context object to be created in
;; caller-provided memory.
;;
;; The purpose of this function is to determine how much memory must be provided
;; to secp256k1_context_preallocated_create.
;;
;; Returns: the required size of the caller-provided memory block
;; In:      flags:    which parts of the context to initialize.
;;
(defcfun "secp256k1_context_preallocated_size" :size
  (flags :unsigned-int))

;; Create a secp256k1 context object in caller-provided memory.
;;
;; The caller must provide a pointer to a rewritable contiguous block of memory
;; of size at least secp256k1_context_preallocated_size(flags) bytes, suitably
;; aligned to hold an object of any type.
;;
;; The block of memory is exclusively owned by the created context object during
;; the lifetime of this context object, which begins with the call to this
;; function and ends when a call to secp256k1_context_preallocated_destroy
;; (which destroys the context object again) returns. During the lifetime of the
;; context object, the caller is obligated not to access this block of memory,
;; i.e., the caller may not read or write the memory, e.g., by copying the memory
;; contents to a different location or trying to create a second context object
;; in the memory. In simpler words, the prealloc pointer (or any pointer derived
;; from it) should not be used during the lifetime of the context object.
;;
;; Returns: a newly created context object.
;; In:      prealloc: a pointer to a rewritable contiguous block of memory of
;;                    size at least secp256k1_context_preallocated_size(flags)
;;                    bytes, as detailed above.
;;          flags:    which parts of the context to initialize.
;;
;; See secp256k1_context_create (in secp256k1.h) for further details.
;;
;; See also secp256k1_context_randomize (in secp256k1.h)
;; and secp256k1_context_preallocated_destroy.
;;
(defcfun "secp256k1_context_preallocated_create" (:pointer (:struct secp256k1-context))
  (prealloc :pointer) ;; void*
  (flags    :unsigned-int))

;; Determine the memory size of a secp256k1 context object to be copied into
;; caller-provided memory.
;;
;; Returns: the required size of the caller-provided memory block.
;; In:      ctx: an existing context to copy.
;;
(defcfun "secp256k1_context_preallocated_clone_size" :size
  (ctx (:pointer (:struct secp256k1-context))))

;; Copy a secp256k1 context object into caller-provided memory.
;;
;; The caller must provide a pointer to a rewritable contiguous block of memory
;; of size at least secp256k1_context_preallocated_size(flags) bytes, suitably
;; aligned to hold an object of any type.
;;
;; The block of memory is exclusively owned by the created context object during
;; the lifetime of this context object, see the description of
;; secp256k1_context_preallocated_create for details.
;;
;; Returns: a newly created context object.
;; Args:    ctx:      an existing context to copy.
;; In:      prealloc: a pointer to a rewritable contiguous block of memory of
;;                    size at least secp256k1_context_preallocated_size(flags)
;;                    bytes, as detailed above.
;;
(defcfun "secp256k1_context_preallocated_clone" (:pointer (:struct secp256k1-context))
  (ctx      (:pointer (:struct secp256k1-context)))
  (prealloc :pointer)) ;; void*

;; Destroy a secp256k1 context object that has been created in
;; caller-provided memory.
;;
;; The context pointer may not be used afterwards.
;;
;; The context to destroy must have been created using
;; secp256k1_context_preallocated_create or secp256k1_context_preallocated_clone.
;; If the context has instead been created using secp256k1_context_create or
;; secp256k1_context_clone, the behaviour is undefined. In that case,
;; secp256k1_context_destroy must be used instead.
;;
;; If required, it is the responsibility of the caller to deallocate the block
;; of memory properly after this function returns, e.g., by calling free on the
;; preallocated pointer given to secp256k1_context_preallocated_create or
;; secp256k1_context_preallocated_clone.
;;
;; Args:   ctx: an existing context to destroy, constructed using
;;              secp256k1_context_preallocated_create or
;;              secp256k1_context_preallocated_clone.
;;
(defcfun "secp256k1_context_preallocated_destroy" :void
 (ctx (:pointer (:struct secp256k1-context))))


;;;-----------------------------------------------------------------------------
;;; secp256k1_recovery.h

;; Opaque data structured that holds a parsed ECDSA signature,
;; supporting pubkey recovery.
;;
;; The exact representation of data inside is implementation defined and not
;; guaranteed to be portable between different platforms or versions. It is
;; however guaranteed to be 65 bytes in size, and can be safely copied/moved.
;; If you need to convert to a format suitable for storage or transmission, use
;; the secp256k1_ecdsa_signature_serialize_* and
;; secp256k1_ecdsa_signature_parse_* functions.
;;
;; Furthermore, it is guaranteed that identical signatures (including their
;; recoverability) will have identical representation, so they can be
;; memcmp'ed.
;;
(defcstruct secp256k1-ecdsa-recoverable-signature
  (data :unsigned-char :count 65))

;; Parse a compact ECDSA signature (64 bytes + recovery id).
;;
;; Returns: 1 when the signature could be parsed, 0 otherwise
;; Args: ctx:     a secp256k1 context object
;; Out:  sig:     a pointer to a signature object
;; In:   input64: a pointer to a 64-byte compact signature
;;       recid:   the recovery id (0, 1, 2 or 3)
;;
(defcfun "secp256k1_ecdsa_recoverable_signature_parse_compact" :int
  (ctx     (:pointer (:struct secp256k1-context)))
  (sig     (:pointer (:struct secp256k1-ecdsa-recoverable-signature)))
  (input64 (:pointer :unsigned-char))
  (recid   :int))

;; Convert a recoverable signature into a normal signature.
;;
;; Returns: 1
;; Args: ctx:    a secp256k1 context object.
;; Out:  sig:    a pointer to a normal signature.
;; In:   sigin:  a pointer to a recoverable signature.
;;
(defcfun "secp256k1_ecdsa_recoverable_signature_convert" :int
  (ctx   (:pointer (:struct secp256k1-context)))
  (sig   (:pointer (:struct secp256k1-ecdsa-signature)))
  (sigin (:pointer (:struct secp256k1-ecdsa-recoverable-signature))))

;; Serialize an ECDSA signature in compact format (64 bytes + recovery id).
;;
;; Returns: 1
;; Args: ctx:      a secp256k1 context object.
;; Out:  output64: a pointer to a 64-byte array of the compact signature.
;;       recid:    a pointer to an integer to hold the recovery id.
;; In:   sig:      a pointer to an initialized signature object.
;;
(defcfun "secp256k1_ecdsa_recoverable_signature_serialize_compact" :int
  (ctx      (:pointer (:struct secp256k1-context)))
  (output64 (:pointer :unsigned-char))
  (recid    (:pointer :int))
  (sig      (:pointer (:struct secp256k1-ecdsa-recoverable-signature))))

;; Create a recoverable ECDSA signature.
;;
;; Returns: 1: signature created
;;          0: the nonce generation function failed, or the secret key was invalid.
;; Args:    ctx:       pointer to a context object (not secp256k1_context_static).
;; Out:     sig:       pointer to an array where the signature will be placed.
;; In:      msghash32: the 32-byte message hash being signed.
;;          seckey:    pointer to a 32-byte secret key.
;;          noncefp:   pointer to a nonce generation function. If NULL,
;;                     secp256k1_nonce_function_default is used.
;;          ndata:     pointer to arbitrary data used by the nonce generation function
;;                     (can be NULL for secp256k1_nonce_function_default).
;;
(defcfun "secp256k1_ecdsa_sign_recoverable" :int
  (ctx       (:pointer (:struct secp256k1-context)))
  (sig       (:pointer (:struct secp256k1-ecdsa-recoverable-signature)))
  (msghash32 (:pointer :unsigned-char))
  (seckey    (:pointer :unsigned-char))
  (noncefp   secp256k1-nonce-function)
  (ndata     :pointer)) ;; void*

;; Recover an ECDSA public key from a signature.
;;
;; Returns: 1: public key successfully recovered (which guarantees a correct signature).
;;          0: otherwise.
;; Args:    ctx:       pointer to a context object.
;; Out:     pubkey:    pointer to the recovered public key.
;; In:      sig:       pointer to initialized signature that supports pubkey recovery.
;;          msghash32: the 32-byte message hash assumed to be signed.
;;
(defcfun "secp256k1_ecdsa_recover" :int
  (ctx       (:pointer (:struct secp256k1-context)))
  (pubkey    (:pointer (:struct secp256k1-pubkey)))
  (sig       (:pointer (:struct secp256k1-ecdsa-recoverable-signature)))
  (msghash32 (:pointer :unsigned-char)))


;;;-----------------------------------------------------------------------------
;;; secp256k1_extrakeys.h

;; Opaque data structure that holds a parsed and valid "x-only" public key.
;; An x-only pubkey encodes a point whose Y coordinate is even. It is
;; serialized using only its X coordinate (32 bytes). See BIP-340 for more
;; information about x-only pubkeys.
;;
;; The exact representation of data inside is implementation defined and not
;; guaranteed to be portable between different platforms or versions. It is
;; however guaranteed to be 64 bytes in size, and can be safely copied/moved.
;; If you need to convert to a format suitable for storage, transmission, use
;; use secp256k1_xonly_pubkey_serialize and secp256k1_xonly_pubkey_parse. To
;; compare keys, use secp256k1_xonly_pubkey_cmp.
;;
(defcstruct secp256k1-xonly-pubkey
  (data :unsigned-char :count 64))

;; Opaque data structure that holds a keypair consisting of a secret and a
;; public key.
;;
;; The exact representation of data inside is implementation defined and not
;; guaranteed to be portable between different platforms or versions. It is
;; however guaranteed to be 96 bytes in size, and can be safely copied/moved.
;;
(defcstruct secp256k1-keypair
  (data :unsigned-char :count 96))

;; Parse a 32-byte sequence into a xonly_pubkey object.
;;
;; Returns: 1 if the public key was fully valid.
;;          0 if the public key could not be parsed or is invalid.
;;
;; Args:   ctx: a secp256k1 context object.
;; Out: pubkey: pointer to a pubkey object. If 1 is returned, it is set to a
;;              parsed version of input. If not, it's set to an invalid value.
;; In: input32: pointer to a serialized xonly_pubkey.
;;
(defcfun "secp256k1_xonly_pubkey_parse" :int
  (ctx     (:pointer (:struct secp256k1-context)))
  (pubkey  (:pointer (:struct secp256k1-xonly-pubkey)))
  (input32 (:pointer :unsigned-char)))

;; Serialize an xonly_pubkey object into a 32-byte sequence.
;;
;; Returns: 1 always.
;;
;; Args:     ctx: a secp256k1 context object.
;; Out: output32: a pointer to a 32-byte array to place the serialized key in.
;; In:    pubkey: a pointer to a secp256k1_xonly_pubkey containing an initialized public key.
;;
(defcfun "secp256k1_xonly_pubkey_serialize" :int
  (ctx      (:pointer (:struct secp256k1-context)))
  (output32 (:pointer :unsigned-char))
  (pubkey   (:pointer (:struct secp256k1-xonly-pubkey))))

;; Compare two x-only public keys using lexicographic order
;;
;; Returns: <0 if the first public key is less than the second
;;          >0 if the first public key is greater than the second
;;          0 if the two public keys are equal
;; Args: ctx:      a secp256k1 context object.
;; In:   pubkey1:  first public key to compare
;;       pubkey2:  second public key to compare
;;
(defcfun "secp256k1_xonly_pubkey_cmp" :int
  (ctx (:pointer (:struct secp256k1-context)))
  (pk1 (:pointer (:struct secp256k1-xonly-pubkey)))
  (pk2 (:pointer (:struct secp256k1-xonly-pubkey))))

;; Converts a secp256k1_pubkey into a secp256k1_xonly_pubkey.
;;
;; Returns: 1 always.
;;
;; Args:         ctx: pointer to a context object.
;; Out: xonly_pubkey: pointer to an x-only public key object for placing the converted public key.
;;         pk_parity: Ignored if NULL. Otherwise, pointer to an integer that
;;                    will be set to 1 if the point encoded by xonly_pubkey is
;;                    the negation of the pubkey and set to 0 otherwise.
;; In:        pubkey: pointer to a public key that is converted.
;;
(defcfun "secp256k1_xonly_pubkey_from_pubkey" :int
  (ctx          (:pointer (:struct secp256k1-context)))
  (xonly-pubkey (:pointer (:struct secp256k1-xonly-pubkey)))
  (pk-parity    (:pointer :int))
  (pubkey       (:pointer (:struct secp256k1-pubkey))))

;; Tweak an x-only public key by adding the generator multiplied with tweak32
;; to it.
;;
;; Note that the resulting point can not in general be represented by an x-only
;; pubkey because it may have an odd Y coordinate. Instead, the output_pubkey
;; is a normal secp256k1_pubkey.
;;
;; Returns: 0 if the arguments are invalid or the resulting public key would be
;;          invalid (only when the tweak is the negation of the corresponding
;;          secret key). 1 otherwise.
;;
;; Args:           ctx: pointer to a context object.
;; Out:  output_pubkey: pointer to a public key to store the result. Will be set
;;                      to an invalid value if this function returns 0.
;; In: internal_pubkey: pointer to an x-only pubkey to apply the tweak to.
;;             tweak32: pointer to a 32-byte tweak. If the tweak is invalid
;;                      according to secp256k1_ec_seckey_verify, this function
;;                      returns 0. For uniformly random 32-byte arrays the
;;                      chance of being invalid is negligible (around 1 in 2^128).
;;
(defcfun "secp256k1_xonly_pubkey_tweak_add" :int
  (ctx             (:pointer (:struct secp256k1-context)))
  (output-pubkey   (:pointer (:struct secp256k1-pubkey)))
  (internal-pubkey (:pointer (:struct secp256k1-xonly-pubkey)))
  (tweak32         (:pointer :unsigned-char)))

;; Checks that a tweaked pubkey is the result of calling
;; secp256k1_xonly_pubkey_tweak_add with internal_pubkey and tweak32.
;;
;; The tweaked pubkey is represented by its 32-byte x-only serialization and
;; its pk_parity, which can both be obtained by converting the result of
;; tweak_add to a secp256k1_xonly_pubkey.
;;
;; Note that this alone does _not_ verify that the tweaked pubkey is a
;; commitment. If the tweak is not chosen in a specific way, the tweaked pubkey
;; can easily be the result of a different internal_pubkey and tweak.
;;
;; Returns: 0 if the arguments are invalid or the tweaked pubkey is not the
;;          result of tweaking the internal_pubkey with tweak32. 1 otherwise.
;; Args:            ctx: pointer to a context object.
;; In: tweaked_pubkey32: pointer to a serialized xonly_pubkey.
;;    tweaked_pk_parity: the parity of the tweaked pubkey (whose serialization
;;                       is passed in as tweaked_pubkey32). This must match the
;;                       pk_parity value that is returned when calling
;;                       secp256k1_xonly_pubkey with the tweaked pubkey, or
;;                       this function will fail.
;;      internal_pubkey: pointer to an x-only public key object to apply the tweak to.
;;              tweak32: pointer to a 32-byte tweak.
;;

(defcfun "secp256k1_xonly_pubkey_tweak_add_check" :int
  (ctx               (:pointer (:struct secp256k1-context)))
  (tweaked-pubkey32  (:pointer :unsigned-char))
  (tweaked-pk-parity :int)
  (internal-pubkey   (:pointer (:struct secp256k1-xonly-pubkey)))
  (tweak32           (:pointer :unsigned-char)))

;; Compute the keypair for a secret key.
;;
;; Returns: 1: secret was valid, keypair is ready to use
;;          0: secret was invalid, try again with a different secret
;; Args:    ctx: pointer to a context object (not secp256k1_context_static).
;; Out: keypair: pointer to the created keypair.
;; In:   seckey: pointer to a 32-byte secret key.
;;
(defcfun "secp256k1_keypair_create" :int
  (ctx     (:pointer (:struct secp256k1-context)))
  (keypair (:pointer (:struct secp256k1-keypair)))
  (seckey  (:pointer :unsigned-char)))

;; Get the secret key from a keypair.
;;
;; Returns: 1 always.
;; Args:   ctx: pointer to a context object.
;; Out: seckey: pointer to a 32-byte buffer for the secret key.
;; In: keypair: pointer to a keypair.
;;
(defcfun "secp256k1_keypair_sec" :int
  (ctx     (:pointer (:struct secp256k1-context)))
  (seckey  (:pointer :unsigned-char))
  (keypair (:pointer (:struct secp256k1-keypair))))

;; Get the public key from a keypair.
;;
;; Returns: 1 always.
;; Args:    ctx: pointer to a context object.
;; Out: pubkey: pointer to a pubkey object. If 1 is returned, it is set to
;;              the keypair public key. If not, it's set to an invalid value.
;; In: keypair: pointer to a keypair.
;;
(defcfun "secp256k1_keypair_pub" :int
  (ctx     (:pointer (:struct secp256k1-context)))
  (pubkey  (:pointer (:struct secp256k1-pubkey)))
  (keypair (:pointer (:struct secp256k1-keypair))))

;; Get the x-only public key from a keypair.
;;
;; This is the same as calling secp256k1_keypair_pub and then
;; secp256k1_xonly_pubkey_from_pubkey.
;;
;; Returns: 1 always.
;; Args:   ctx: pointer to a context object.
;; Out: pubkey: pointer to an xonly_pubkey object. If 1 is returned, it is set
;;              to the keypair public key after converting it to an
;;              xonly_pubkey. If not, it's set to an invalid value.
;;   pk_parity: Ignored if NULL. Otherwise, pointer to an integer that will be set to the
;;              pk_parity argument of secp256k1_xonly_pubkey_from_pubkey.
;; In: keypair: pointer to a keypair.
;;
(defcfun "secp256k1_keypair_xonly_pub" :int
  (ctx       (:pointer (:struct secp256k1-context)))
  (pubkey    (:pointer (:struct secp256k1-xonly-pubkey)))
  (pk-parity (:pointer :int))
  (keypair   (:pointer (:struct secp256k1-keypair))))

;; Tweak a keypair by adding tweak32 to the secret key and updating the public
;; key accordingly.
;;
;; Calling this function and then secp256k1_keypair_pub results in the same
;; public key as calling secp256k1_keypair_xonly_pub and then
;; secp256k1_xonly_pubkey_tweak_add.
;;
;; Returns: 0 if the arguments are invalid or the resulting keypair would be
;;          invalid (only when the tweak is the negation of the keypair's
;;          secret key). 1 otherwise.
;;
;; Args:       ctx: pointer to a context object.
;; In/Out: keypair: pointer to a keypair to apply the tweak to. Will be set to
;;                  an invalid value if this function returns 0.
;; In:     tweak32: pointer to a 32-byte tweak. If the tweak is invalid according
;;                  to secp256k1_ec_seckey_verify, this function returns 0. For
;;                  uniformly random 32-byte arrays the chance of being invalid
;;                  is negligible (around 1 in 2^128).
;;
(defcfun "secp256k1_keypair_xonly_tweak_add" :int
  (ctx     (:pointer (:struct secp256k1-context)))
  (keypair (:pointer (:struct secp256k1-keypair)))
  (tweak32 (:pointer :unsigned-char)))


;;;-----------------------------------------------------------------------------
;;; secp256k1_schnorrsig.h
;;;
;;; This module implements a variant of Schnorr signatures compliant with
;;; Bitcoin Improvement Proposal 340 "Schnorr Signatures for secp256k1"
;;; (https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).
;;;

;; A pointer to a function to deterministically generate a nonce.
;;
;; Same as secp256k1_nonce function with the exception of accepting an
;; additional pubkey argument and not requiring an attempt argument. The pubkey
;; argument can protect signature schemes with key-prefixed challenge hash
;; inputs against reusing the nonce when signing with the wrong precomputed
;; pubkey.
;;
;; Returns: 1 if a nonce was successfully generated. 0 will cause signing to
;;          return an error.
;; Out:  nonce32: pointer to a 32-byte array to be filled by the function
;; In:       msg: the message being verified. Is NULL if and only if msglen
;;                is 0.
;;        msglen: the length of the message
;;         key32: pointer to a 32-byte secret key (will not be NULL)
;;    xonly_pk32: the 32-byte serialized xonly pubkey corresponding to key32
;;                (will not be NULL)
;;          algo: pointer to an array describing the signature
;;                algorithm (will not be NULL)
;;       algolen: the length of the algo array
;;          data: arbitrary data pointer that is passed through
;;
;; Except for test cases, this function should compute some cryptographic hash of
;; the message, the key, the pubkey, the algorithm description, and data.
;;
;; typedef int (*secp256k1_nonce_function_hardened)(
;;     unsigned char *nonce32,
;;     const unsigned char *msg,
;;     size_t msglen,
;;     const unsigned char *key32,
;;     const unsigned char *xonly_pk32,
;;     const unsigned char *algo,
;;     size_t algolen,
;;     void *data
;; );
(defctype secp256k1-nonce-function-hardened :pointer)

;; An implementation of the nonce generation function as defined in Bitcoin
;; Improvement Proposal 340 "Schnorr Signatures for secp256k1"
;; (https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).
;;
;; If a data pointer is passed, it is assumed to be a pointer to 32 bytes of
;; auxiliary random data as defined in BIP-340. If the data pointer is NULL,
;; the nonce derivation procedure follows BIP-340 by setting the auxiliary
;; random data to zero. The algo argument must be non-NULL, otherwise the
;; function will fail and return 0. The hash will be tagged with algo.
;; Therefore, to create BIP-340 compliant signatures, algo must be set to
;; "BIP0340/nonce" and algolen to 13.
;;
(defcvar "secp256k1_nonce_function_bip340" secp256k1-nonce-function-hardened)

;; Data structure that contains additional arguments for schnorrsig_sign_custom.
;;
;; A schnorrsig_extraparams structure object can be initialized correctly by
;; setting it to SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT.
;;
;; Members:
;;     magic: set to SECP256K1_SCHNORRSIG_EXTRAPARAMS_MAGIC at initialization
;;            and has no other function than making sure the object is
;;            initialized.
;;   noncefp: pointer to a nonce generation function. If NULL,
;;            secp256k1_nonce_function_bip340 is used
;;     ndata: pointer to arbitrary data used by the nonce generation function
;;            (can be NULL). If it is non-NULL and
;;            secp256k1_nonce_function_bip340 is used, then ndata must be a
;;            pointer to 32-byte auxiliary randomness as per BIP-340.
;;
(defcstruct secp256k1-schnorrsig-extraparams
  (magic   :unsigned-char :count 4)
  (noncefp secp256k1-nonce-function-hardened)
  (ndata   :pointer)) ;; void*

(defconstant +secp256k1-schnorrsig-extraparams-magic+ '(#xda #x6f #xb3 #x8c))

;; Create a Schnorr signature.
;;
;; Does _not_ strictly follow BIP-340 because it does not verify the resulting
;; signature. Instead, you can manually use secp256k1_schnorrsig_verify and
;; abort if it fails.
;;
;; This function only signs 32-byte messages. If you have messages of a
;; different size (or the same size but without a context-specific tag
;; prefix), it is recommended to create a 32-byte message hash with
;; secp256k1_tagged_sha256 and then sign the hash. Tagged hashing allows
;; providing an context-specific tag for domain separation. This prevents
;; signatures from being valid in multiple contexts by accident.
;;
;; Returns 1 on success, 0 on failure.
;; Args:    ctx: pointer to a context object (not secp256k1_context_static).
;; Out:   sig64: pointer to a 64-byte array to store the serialized signature.
;; In:    msg32: the 32-byte message being signed.
;;      keypair: pointer to an initialized keypair.
;;   aux_rand32: 32 bytes of fresh randomness. While recommended to provide
;;               this, it is only supplemental to security and can be NULL. A
;;               NULL argument is treated the same as an all-zero one. See
;;               BIP-340 "Default Signing" for a full explanation of this
;;               argument and for guidance if randomness is expensive.
;;
(defcfun "secp256k1_schnorrsig_sign32" :int
  (ctx        (:pointer (:struct secp256k1-context)))
  (sig64      (:pointer :unsigned-char))
  (msg32      (:pointer :unsigned-char))
  (keypair    (:pointer (:struct secp256k1-keypair)))
  (aux-rand32 (:pointer :unsigned-char)))

;; Same as secp256k1_schnorrsig_sign32, but DEPRECATED. Will be removed in
;; future versions.
(defcfun "secp256k1_schnorrsig_sign" :int
  (ctx        (:pointer (:struct secp256k1-context)))
  (sig64      (:pointer :unsigned-char))
  (msg32      (:pointer :unsigned-char))
  (keypair    (:pointer (:struct secp256k1-keypair)))
  (aux-rand32 (:pointer :unsigned-char)))

;; Create a Schnorr signature with a more flexible API.
;;
;; Same arguments as secp256k1_schnorrsig_sign except that it allows signing
;; variable length messages and accepts a pointer to an extraparams object that
;; allows customizing signing by passing additional arguments.
;;
;; Creates the same signatures as schnorrsig_sign if msglen is 32 and the
;; extraparams.ndata is the same as aux_rand32.
;;
;; In:     msg: the message being signed. Can only be NULL if msglen is 0.
;;      msglen: length of the message
;; extraparams: pointer to a extraparams object (can be NULL)
;;
(defcfun "secp256k1_schnorrsig_sign_custom" :int
  (ctx         (:pointer (:struct secp256k1-context)))
  (sig64       (:pointer :unsigned-char))
  (msg         (:pointer :unsigned-char))
  (msglen      :size)
  (keypair     (:pointer (:struct secp256k1-keypair)))
  (extraparams (:pointer (:struct secp256k1-schnorrsig-extraparams))))

;; Verify a Schnorr signature.
;;
;; Returns: 1: correct signature
;;          0: incorrect signature
;; Args:    ctx: a secp256k1 context object.
;; In:    sig64: pointer to the 64-byte signature to verify.
;;          msg: the message being verified. Can only be NULL if msglen is 0.
;;       msglen: length of the message
;;       pubkey: pointer to an x-only public key to verify with (cannot be NULL)
;;
(defcfun "secp256k1_schnorrsig_verify" :int
  (ctx    (:pointer (:struct secp256k1-context)))
  (sig64  (:pointer :unsigned-char))
  (msg    (:pointer :unsigned-char))
  (msglen :size)
  (pubkey (:pointer (:struct secp256k1-xonly-pubkey))))


;;;-----------------------------------------------------------------------------
;;; secp256k1_musig.h
;;;
;;; This module implements BIP 327 "MuSig2 for BIP340-compatible
;;; Multi-Signatures"
;;; (https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki)
;;; v1.0.0. You can find an example demonstrating the musig module in
;;; examples/musig.c.
;;;
;;; The module also supports BIP 341 ("Taproot") public key tweaking.
;;;
;;; It is recommended to read the documentation in this include file carefully.
;;; Further notes on API usage can be found in doc/musig.md
;;;
;;; Since the first version of MuSig is essentially replaced by MuSig2, we use
;;; MuSig, musig and MuSig2 synonymously unless noted otherwise.
;;;

;; Opaque data structures
;;
;; The exact representation of data inside the opaque data structures is
;; implementation defined and not guaranteed to be portable between different
;; platforms or versions. With the exception of `secp256k1_musig_secnonce`, the
;; data structures can be safely copied/moved. If you need to convert to a
;; format suitable for storage, transmission, or comparison, use the
;; corresponding serialization and parsing functions.
;;

;; Opaque data structure that caches information about public key aggregation.
;;
;; Guaranteed to be 197 bytes in size. No serialization and parsing functions
;; (yet).
;;
(defcstruct secp256k1-musig-keyagg-cache
  (data :unsigned-char :count 197))

;; Opaque data structure that holds a signer's _secret_ nonce.
;;
;; Guaranteed to be 132 bytes in size.
;;
;; WARNING: This structure MUST NOT be copied or read or written to directly. A
;; signer who is online throughout the whole process and can keep this
;; structure in memory can use the provided API functions for a safe standard
;; workflow.
;;
;; Copying this data structure can result in nonce reuse which will leak the
;; secret signing key.
;;
(defcstruct secp256k1-musig-secnonce
  (data :unsigned-char :count 132))

;; Opaque data structure that holds a signer's public nonce.
;;
;; Guaranteed to be 132 bytes in size. Serialized and parsed with
;; `musig_pubnonce_serialize` and `musig_pubnonce_parse`.
;;
(defcstruct secp256k1-musig-pubnonce
  (data :unsigned-char :count 132))

;; Opaque data structure that holds an aggregate public nonce.
;;
;; Guaranteed to be 132 bytes in size. Serialized and parsed with
;; `musig_aggnonce_serialize` and `musig_aggnonce_parse`.
;;
(defcstruct secp256k1-musig-aggnonce
  (data :unsigned-char :count 132))

;; Opaque data structure that holds a MuSig session.
;;
;; This structure is not required to be kept secret for the signing protocol to
;; be secure. Guaranteed to be 133 bytes in size. No serialization and parsing
;; functions (yet).
;;
(defcstruct secp256k1-musig-session
  (data :unsigned-char :count 133))

;; Opaque data structure that holds a partial MuSig signature.
;;
;; Guaranteed to be 36 bytes in size. Serialized and parsed with
;; `musig_partial_sig_serialize` and `musig_partial_sig_parse`.
;;
(defcstruct secp256k1-musig-partial-sig
  (data :unsigned-char :count 36))

;; Parse a signer's public nonce.
;;
;; Returns: 1 when the nonce could be parsed, 0 otherwise.
;; Args:    ctx: pointer to a context object
;; Out:   nonce: pointer to a nonce object
;; In:     in66: pointer to the 66-byte nonce to be parsed
;;
(defcfun "secp256k1_musig_pubnonce_parse" :int
  (ctx   (:pointer (:struct secp256k1-context)))
  (nonce (:pointer (:struct secp256k1-musig-pubnonce)))
  (in66  (:pointer :unsigned-char)))

;; Serialize a signer's public nonce
;;
;; Returns: 1 always
;; Args:    ctx: pointer to a context object
;; Out:   out66: pointer to a 66-byte array to store the serialized nonce
;; In:    nonce: pointer to the nonce
;;
(defcfun "secp256k1_musig_pubnonce_serialize" :int
  (ctx   (:pointer (:struct secp256k1-context)))
  (out66 (:pointer :unsigned-char))
  (nonce (:pointer (:struct secp256k1-musig-pubnonce))))

;; Parse an aggregate public nonce.
;;
;; Returns: 1 when the nonce could be parsed, 0 otherwise.
;; Args:    ctx: pointer to a context object
;; Out:   nonce: pointer to a nonce object
;; In:     in66: pointer to the 66-byte nonce to be parsed
;;
(defcfun "secp256k1_musig_aggnonce_parse" :int
  (ctx   (:pointer (:struct secp256k1-context)))
  (nonce (:pointer (:struct secp256k1-musig-aggnonce)))
  (in66  (:pointer :unsigned-char)))

;; Serialize an aggregate public nonce
;;
;; Returns: 1 always
;; Args:    ctx: pointer to a context object
;; Out:   out66: pointer to a 66-byte array to store the serialized nonce
;; In:    nonce: pointer to the nonce
;;
(defcfun "secp256k1_musig_aggnonce_serialize" :int
  (ctx   (:pointer (:struct secp256k1-context)))
  (out66 (:pointer :unsigned-char))
  (nonce (:pointer (:struct secp256k1-musig-aggnonce))))

;; Parse a MuSig partial signature.
;;
;; Returns: 1 when the signature could be parsed, 0 otherwise.
;; Args:    ctx: pointer to a context object
;; Out:     sig: pointer to a signature object
;; In:     in32: pointer to the 32-byte signature to be parsed
;;
(defcfun "secp256k1_musig_partial_sig_parse" :int
  (ctx  (:pointer (:struct secp256k1-context)))
  (sig  (:pointer (:struct secp256k1-musig-partial-sig)))
  (in32 (:pointer :unsigned-char)))

;; Serialize a MuSig partial signature
;;
;; Returns: 1 always
;; Args:    ctx: pointer to a context object
;; Out:   out32: pointer to a 32-byte array to store the serialized signature
;; In:      sig: pointer to the signature
;;
(defcfun "secp256k1_musig_partial_sig_serialize" :int
  (ctx   (:pointer (:struct secp256k1-context)))
  (out32 (:pointer :unsigned-char))
  (sig   (:pointer (:struct secp256k1-musig-partial-sig))))

;; Computes an aggregate public key and uses it to initialize a keyagg_cache
;;
;; Different orders of `pubkeys` result in different `agg_pk`s.
;;
;; Before aggregating, the pubkeys can be sorted with `secp256k1_ec_pubkey_sort`
;; which ensures the same `agg_pk` result for the same multiset of pubkeys.
;; This is useful to do before `pubkey_agg`, such that the order of pubkeys
;; does not affect the aggregate public key.
;;
;; Returns: 0 if the arguments are invalid, 1 otherwise
;; Args:        ctx: pointer to a context object
;; Out:      agg_pk: the MuSig-aggregated x-only public key. If you do not need it,
;;                   this arg can be NULL.
;;     keyagg_cache: if non-NULL, pointer to a musig_keyagg_cache struct that
;;                   is required for signing (or observing the signing session
;;                   and verifying partial signatures).
;;  In:     pubkeys: input array of pointers to public keys to aggregate. The order
;;                   is important; a different order will result in a different
;;                   aggregate public key.
;;        n_pubkeys: length of pubkeys array. Must be greater than 0.
;;
(defcfun "secp256k1_musig_pubkey_agg" :int
  (ctx          (:pointer (:struct secp256k1-context)))
  (agg-pk       (:pointer (:struct secp256k1-xonly-pubkey)))
  (keyagg-cache (:pointer (:struct secp256k1-musig-keyagg-cache)))
  (pubkeys      (:pointer (:pointer (:struct secp256k1-pubkey))))
  (n-pubkeys    :size))

;; Obtain the aggregate public key from a keyagg_cache.
;;
;; This is only useful if you need the non-xonly public key, in particular for
;; plain (non-xonly) tweaking or batch-verifying multiple key aggregations
;; (not implemented).
;;
;; Returns: 0 if the arguments are invalid, 1 otherwise
;; Args:        ctx: pointer to a context object
;; Out:      agg_pk: the MuSig-aggregated public key.
;; In: keyagg_cache: pointer to a `musig_keyagg_cache` struct initialized by
;;                   `musig_pubkey_agg`
;;
(defcfun "secp256k1_musig_pubkey_get" :int
  (ctx          (:pointer (:struct secp256k1-context)))
  (agg-pk       (:pointer (:struct secp256k1-pubkey)))
  (keyagg-cache (:pointer (:struct secp256k1-musig-keyagg-cache))))

;; Apply plain "EC" tweaking to a public key in a given keyagg_cache by adding
;; the generator multiplied with `tweak32` to it. This is useful for deriving
;; child keys from an aggregate public key via BIP 32 where `tweak32` is set to
;; a hash as defined in BIP 32.
;;
;; Callers are responsible for deriving `tweak32` in a way that does not reduce
;; the security of MuSig (for example, by following BIP 32).
;;
;; The tweaking method is the same as `secp256k1_ec_pubkey_tweak_add`. So after
;; the following pseudocode buf and buf2 have identical contents (absent
;; earlier failures).
;;
;; secp256k1_musig_pubkey_agg(..., keyagg_cache, pubkeys, ...)
;; secp256k1_musig_pubkey_get(..., agg_pk, keyagg_cache)
;; secp256k1_musig_pubkey_ec_tweak_add(..., output_pk, tweak32, keyagg_cache)
;; secp256k1_ec_pubkey_serialize(..., buf, ..., output_pk, ...)
;; secp256k1_ec_pubkey_tweak_add(..., agg_pk, tweak32)
;; secp256k1_ec_pubkey_serialize(..., buf2, ..., agg_pk, ...)
;;
;; This function is required if you want to _sign_ for a tweaked aggregate key.
;; If you are only computing a public key but not intending to create a
;; signature for it, use `secp256k1_ec_pubkey_tweak_add` instead.
;;
;; Returns: 0 if the arguments are invalid, 1 otherwise
;; Args:            ctx: pointer to a context object
;; Out:   output_pubkey: pointer to a public key to store the result. Will be set
;;                       to an invalid value if this function returns 0. If you
;;                       do not need it, this arg can be NULL.
;; In/Out: keyagg_cache: pointer to a `musig_keyagg_cache` struct initialized by
;;                      `musig_pubkey_agg`
;; In:          tweak32: pointer to a 32-byte tweak. The tweak is valid if it passes
;;                       `secp256k1_ec_seckey_verify` and is not equal to the
;;                       secret key corresponding to the public key represented
;;                       by keyagg_cache or its negation. For uniformly random
;;                       32-byte arrays the chance of being invalid is
;;                       negligible (around 1 in 2^128).
;;
(defcfun "secp256k1_musig_pubkey_ec_tweak_add" :int
  (ctx           (:pointer (:struct secp256k1-context)))
  (output-pubkey (:pointer (:struct secp256k1-pubkey)))
  (keyagg-cache  (:pointer (:struct secp256k1-musig-keyagg-cache)))
  (tweak32       (:pointer :unsigned-char)))

;; Apply x-only tweaking to a public key in a given keyagg_cache by adding the
;; generator multiplied with `tweak32` to it. This is useful for creating
;; Taproot outputs where `tweak32` is set to a TapTweak hash as defined in BIP
;; 341.
;;
;; Callers are responsible for deriving `tweak32` in a way that does not reduce
;; the security of MuSig (for example, by following Taproot BIP 341).
;;
;; The tweaking method is the same as `secp256k1_xonly_pubkey_tweak_add`. So in
;; the following pseudocode xonly_pubkey_tweak_add_check (absent earlier
;; failures) returns 1.
;;
;; secp256k1_musig_pubkey_agg(..., agg_pk, keyagg_cache, pubkeys, ...)
;; secp256k1_musig_pubkey_xonly_tweak_add(..., output_pk, keyagg_cache, tweak32)
;; secp256k1_xonly_pubkey_serialize(..., buf, output_pk)
;; secp256k1_xonly_pubkey_tweak_add_check(..., buf, ..., agg_pk, tweak32)
;;
;; This function is required if you want to _sign_ for a tweaked aggregate key.
;; If you are only computing a public key but not intending to create a
;; signature for it, use `secp256k1_xonly_pubkey_tweak_add` instead.
;;
;; Returns: 0 if the arguments are invalid, 1 otherwise
;; Args:            ctx: pointer to a context object
;; Out:   output_pubkey: pointer to a public key to store the result. Will be set
;;                       to an invalid value if this function returns 0. If you
;;                       do not need it, this arg can be NULL.
;; In/Out: keyagg_cache: pointer to a `musig_keyagg_cache` struct initialized by
;;                      `musig_pubkey_agg`
;; In:          tweak32: pointer to a 32-byte tweak. The tweak is valid if it passes
;;                       `secp256k1_ec_seckey_verify` and is not equal to the
;;                       secret key corresponding to the public key represented
;;                       by keyagg_cache or its negation. For uniformly random
;;                       32-byte arrays the chance of being invalid is
;;                       negligible (around 1 in 2^128).
;;
(defcfun "secp256k1_musig_pubkey_xonly_tweak_add" :int
  (ctx           (:pointer (:struct secp256k1-context)))
  (output-pubkey (:pointer (:struct secp256k1-pubkey)))
  (keyagg-cache  (:pointer (:struct secp256k1-musig-keyagg-cache)))
  (tweak32       (:pointer :unsigned-char)))

;; Starts a signing session by generating a nonce
;;
;; This function outputs a secret nonce that will be required for signing and a
;; corresponding public nonce that is intended to be sent to other signers.
;;
;; MuSig differs from regular Schnorr signing in that implementers _must_ take
;; special care to not reuse a nonce. This can be ensured by following these rules:
;;
;; 1. Each call to this function must have a UNIQUE session_secrand32 that must
;;    NOT BE REUSED in subsequent calls to this function and must be KEPT
;;    SECRET (even from other signers).
;; 2. If you already know the seckey, message or aggregate public key
;;    cache, they can be optionally provided to derive the nonce and increase
;;    misuse-resistance. The extra_input32 argument can be used to provide
;;    additional data that does not repeat in normal scenarios, such as the
;;    current time.
;; 3. Avoid copying (or serializing) the secnonce. This reduces the possibility
;;    that it is used more than once for signing.
;;
;; If you don't have access to good randomness for session_secrand32, but you
;; have access to a non-repeating counter, then see
;; secp256k1_musig_nonce_gen_counter.
;;
;; Remember that nonce reuse will leak the secret key!
;; Note that using the same seckey for multiple MuSig sessions is fine.
;;
;; Returns: 0 if the arguments are invalid and 1 otherwise
;; Args:         ctx: pointer to a context object (not secp256k1_context_static)
;; Out:     secnonce: pointer to a structure to store the secret nonce
;;          pubnonce: pointer to a structure to store the public nonce
;; In/Out:
;; session_secrand32: a 32-byte session_secrand32 as explained above. Must be unique to this
;;                    call to secp256k1_musig_nonce_gen and must be uniformly
;;                    random. If the function call is successful, the
;;                    session_secrand32 buffer is invalidated to prevent reuse.
;; In:
;;            seckey: the 32-byte secret key that will later be used for signing, if
;;                    already known (can be NULL)
;;            pubkey: public key of the signer creating the nonce. The secnonce
;;                    output of this function cannot be used to sign for any
;;                    other public key. While the public key should correspond
;;                    to the provided seckey, a mismatch will not cause the
;;                    function to return 0.
;;             msg32: the 32-byte message that will later be signed, if already known
;;                    (can be NULL)
;;      keyagg_cache: pointer to the keyagg_cache that was used to create the aggregate
;;                    (and potentially tweaked) public key if already known
;;                    (can be NULL)
;;     extra_input32: an optional 32-byte array that is input to the nonce
;;                    derivation function (can be NULL)
;;
(defcfun "secp256k1_musig_nonce_gen" :int
  (ctx               (:pointer (:struct secp256k1-context)))
  (secnonce          (:pointer (:struct secp256k1-musig-secnonce)))
  (pubnonce          (:pointer (:struct secp256k1-musig-pubnonce)))
  (session-secrand32 (:pointer :unsigned-char))
  (seckey            (:pointer :unsigned-char))
  (pubkey            (:pointer (:struct secp256k1-pubkey)))
  (msg32             (:pointer :unsigned-char))
  (keyagg-cache      (:pointer (:struct secp256k1-musig-keyagg-cache)))
  (extra-input32     (:pointer :unsigned-char)))

;; Alternative way to generate a nonce and start a signing session
;;
;; This function outputs a secret nonce that will be required for signing and a
;; corresponding public nonce that is intended to be sent to other signers.
;;
;; This function differs from `secp256k1_musig_nonce_gen` by accepting a
;; non-repeating counter value instead of a secret random value. This requires
;; that a secret key is provided to `secp256k1_musig_nonce_gen_counter`
;; (through the keypair argument), as opposed to `secp256k1_musig_nonce_gen`
;; where the seckey argument is optional.
;;
;; MuSig differs from regular Schnorr signing in that implementers _must_ take
;; special care to not reuse a nonce. This can be ensured by following these rules:
;;
;; 1. The nonrepeating_cnt argument must be a counter value that never repeats,
;;    i.e., you must never call `secp256k1_musig_nonce_gen_counter` twice with
;;    the same keypair and nonrepeating_cnt value. For example, this implies
;;    that if the same keypair is used with `secp256k1_musig_nonce_gen_counter`
;;    on multiple devices, none of the devices should have the same counter
;;    value as any other device.
;; 2. If the seckey, message or aggregate public key cache is already available
;;    at this stage, any of these can be optionally provided, in which case
;;    they will be used in the derivation of the nonce and increase
;;    misuse-resistance. The extra_input32 argument can be used to provide
;;    additional data that does not repeat in normal scenarios, such as the
;;    current time.
;; 3. Avoid copying (or serializing) the secnonce. This reduces the possibility
;;    that it is used more than once for signing.
;;
;; Remember that nonce reuse will leak the secret key!
;; Note that using the same keypair for multiple MuSig sessions is fine.
;;
;; Returns: 0 if the arguments are invalid and 1 otherwise
;; Args:         ctx: pointer to a context object (not secp256k1_context_static)
;; Out:     secnonce: pointer to a structure to store the secret nonce
;;          pubnonce: pointer to a structure to store the public nonce
;; In:
;;  nonrepeating_cnt: the value of a counter as explained above. Must be
;;                    unique to this call to secp256k1_musig_nonce_gen.
;;           keypair: keypair of the signer creating the nonce. The secnonce
;;                    output of this function cannot be used to sign for any
;;                    other keypair.
;;             msg32: the 32-byte message that will later be signed, if already known
;;                    (can be NULL)
;;      keyagg_cache: pointer to the keyagg_cache that was used to create the aggregate
;;                    (and potentially tweaked) public key if already known
;;                    (can be NULL)
;;     extra_input32: an optional 32-byte array that is input to the nonce
;;                    derivation function (can be NULL)
;;
(defcfun "secp256k1_musig_nonce_gen_counter" :int
  (ctx              (:pointer (:struct secp256k1-context)))
  (secnonce         (:pointer (:struct secp256k1-musig-secnonce)))
  (pubnonce         (:pointer (:struct secp256k1-musig-pubnonce)))
  (nonrepeating-cnt :uint64)
  (keypair          (:pointer (:struct secp256k1-keypair)))
  (msg32            (:pointer :unsigned-char))
  (keyagg-cache     (:pointer (:struct secp256k1-musig-keyagg-cache)))
  (extra-input32    (:pointer :unsigned-char)))

;; Aggregates the nonces of all signers into a single nonce
;;
;; This can be done by an untrusted party to reduce the communication
;; between signers. Instead of everyone sending nonces to everyone else, there
;; can be one party receiving all nonces, aggregating the nonces with this
;; function and then sending only the aggregate nonce back to the signers.
;;
;; If the aggregator does not compute the aggregate nonce correctly, the final
;; signature will be invalid.
;;
;; Returns: 0 if the arguments are invalid, 1 otherwise
;; Args:           ctx: pointer to a context object
;; Out:       aggnonce: pointer to an aggregate public nonce object for
;;                      musig_nonce_process
;; In:       pubnonces: array of pointers to public nonces sent by the
;;                      signers
;;         n_pubnonces: number of elements in the pubnonces array. Must be
;;                      greater than 0.
;;
(defcfun "secp256k1_musig_nonce_agg" :int
  (ctx         (:pointer (:struct secp256k1-context)))
  (aggnonce    (:pointer (:struct secp256k1-musig-aggnonce)))
  (pubnonces   (:pointer (:pointer (:struct secp256k1-musig-pubnonce))))
  (n-pubnonces :size))

;; Takes the aggregate nonce and creates a session that is required for signing
;; and verification of partial signatures.
;;
;; Returns: 0 if the arguments are invalid, 1 otherwise
;; Args:          ctx: pointer to a context object
;; Out:       session: pointer to a struct to store the session
;; In:       aggnonce: pointer to an aggregate public nonce object that is the
;;                     output of musig_nonce_agg
;;             msg32:  the 32-byte message to sign
;;      keyagg_cache:  pointer to the keyagg_cache that was used to create the
;;                     aggregate (and potentially tweaked) pubkey
;;
(defcfun "secp256k1_musig_nonce_process" :int
  (ctx          (:pointer (:struct secp256k1-context)))
  (session      (:pointer (:struct secp256k1-musig-session)))
  (aggnonce     (:pointer (:struct secp256k1-musig-aggnonce)))
  (msg32        (:pointer :unsigned-char))
  (keyagg-cache (:pointer (:struct secp256k1-musig-keyagg-cache))))

;; Produces a partial signature
;;
;; This function overwrites the given secnonce with zeros and will abort if given a
;; secnonce that is all zeros. This is a best effort attempt to protect against nonce
;; reuse. However, this is of course easily defeated if the secnonce has been
;; copied (or serialized). Remember that nonce reuse will leak the secret key!
;;
;; For signing to succeed, the secnonce provided to this function must have
;; been generated for the provided keypair. This means that when signing for a
;; keypair consisting of a seckey and pubkey, the secnonce must have been
;; created by calling musig_nonce_gen with that pubkey. Otherwise, the
;; illegal_callback is called.
;;
;; This function does not verify the output partial signature, deviating from
;; the BIP 327 specification. It is recommended to verify the output partial
;; signature with `secp256k1_musig_partial_sig_verify` to prevent random or
;; adversarially provoked computation errors.
;;
;; Returns: 0 if the arguments are invalid or the provided secnonce has already
;;          been used for signing, 1 otherwise
;; Args:         ctx: pointer to a context object
;; Out:  partial_sig: pointer to struct to store the partial signature
;; In/Out:  secnonce: pointer to the secnonce struct created in
;;                    musig_nonce_gen that has been never used in a
;;                    partial_sign call before and has been created for the
;;                    keypair
;; In:       keypair: pointer to keypair to sign the message with
;;      keyagg_cache: pointer to the keyagg_cache that was output when the
;;                    aggregate public key for this session
;;           session: pointer to the session that was created with
;;                    musig_nonce_process
;;
(defcfun "secp256k1_musig_partial_sign" :int
  (ctx          (:pointer (:struct secp256k1-context)))
  (partial-sig  (:pointer (:struct secp256k1-musig-partial-sig)))
  (secnonce     (:pointer (:struct secp256k1-musig-secnonce)))
  (keypair      (:pointer (:struct secp256k1-keypair)))
  (keyagg-cache (:pointer (:struct secp256k1-musig-keyagg-cache)))
  (session      (:pointer (:struct secp256k1-musig-session))))

;; Verifies an individual signer's partial signature
;;
;; The signature is verified for a specific signing session. In order to avoid
;; accidentally verifying a signature from a different or non-existing signing
;; session, you must ensure the following:
;;   1. The `keyagg_cache` argument is identical to the one used to create the
;;      `session` with `musig_nonce_process`.
;;   2. The `pubkey` argument must be identical to the one sent by the signer
;;      before aggregating it with `musig_pubkey_agg` to create the
;;      `keyagg_cache`.
;;   3. The `pubnonce` argument must be identical to the one sent by the signer
;;      before aggregating it with `musig_nonce_agg` and using the result to
;;      create the `session` with `musig_nonce_process`.
;;
;; It is not required to call this function in regular MuSig sessions, because
;; if any partial signature does not verify, the final signature will not
;; verify either, so the problem will be caught. However, this function
;; provides the ability to identify which specific partial signature fails
;; verification.
;;
;; Returns: 0 if the arguments are invalid or the partial signature does not
;;          verify, 1 otherwise
;; Args         ctx: pointer to a context object
;; In:  partial_sig: pointer to partial signature to verify, sent by
;;                   the signer associated with `pubnonce` and `pubkey`
;;         pubnonce: public nonce of the signer in the signing session
;;           pubkey: public key of the signer in the signing session
;;     keyagg_cache: pointer to the keyagg_cache that was output when the
;;                   aggregate public key for this signing session
;;          session: pointer to the session that was created with
;;                   `musig_nonce_process`
;;
(defcfun "secp256k1_musig_partial_sig_verify" :int
  (ctx          (:pointer (:struct secp256k1-context)))
  (partial-sig  (:pointer (:struct secp256k1-musig-partial-sig)))
  (pubnonce     (:pointer (:struct secp256k1-musig-pubnonce)))
  (pubkey       (:pointer (:struct secp256k1-pubkey)))
  (keyagg-cache (:pointer (:struct secp256k1-musig-keyagg-cache)))
  (session      (:pointer (:struct secp256k1-musig-session))))

;; Aggregates partial signatures
;;
;; Returns: 0 if the arguments are invalid, 1 otherwise (which does NOT mean
;;          the resulting signature verifies).
;; Args:         ctx: pointer to a context object
;; Out:        sig64: complete (but possibly invalid) Schnorr signature
;; In:       session: pointer to the session that was created with
;;                    musig_nonce_process
;;      partial_sigs: array of pointers to partial signatures to aggregate
;;            n_sigs: number of elements in the partial_sigs array. Must be
;;                    greater than 0.
;;
(defcfun "secp256k1_musig_partial_sig_agg" :int
  (ctx          (:pointer (:struct secp256k1-context)))
  (sig64        (:pointer :unsigned-char))
  (session      (:pointer (:struct secp256k1-musig-session)))
  (partial-sigs (:pointer (:pointer (:struct secp256k1-musig-partial-sig))))
  (n-sigs       :size))


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
  (let ((bytes (ec-pubkey-parse bytes)))
    (when bytes
      (%make-pubkey :bytes bytes))))

(defun serialize-pubkey (pubkey &key compressed)
  (ec-pubkey-serialize (pubkey-bytes pubkey) :compressed compressed))

(defun parse-signature (bytes &key (type :relaxed))
  (let ((bytes (ecase type
                 (:compact
                  (ecdsa-signature-parse-compact bytes))
                 (:der
                  (ecdsa-signature-parse-der bytes))
                 (:relaxed
                  (ecdsa-signature-parse-der-lax bytes)))))
    (when bytes
      (%make-signature :bytes bytes))))

(defun serialize-signature (signature &key (type :der))
  (ecase type
    (:compact
     (ecdsa-signature-serialize-compact (signature-bytes signature)))
    (:der
     (ecdsa-signature-serialize-der (signature-bytes signature)))))

(defun make-signature (key hash)
  (%make-signature :bytes (ecdsa-sign hash (key-bytes key))))

(defun verify-signature (pubkey hash signature)
  (when (and pubkey signature)
    (let* ((bytes  (signature-bytes signature))
           (nbytes (ecdsa-signature-normalize bytes)))
      (ecdsa-verify (or nbytes bytes) hash (pubkey-bytes pubkey)))))

(defun combine-pubkeys (&rest pubkeys)
  (let ((bytes (ec-pubkey-combine (mapcar #'pubkey-bytes pubkeys))))
    (when bytes
      (%make-pubkey :bytes bytes))))
