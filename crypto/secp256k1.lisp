;;; Copyright (c) 2019-2023 BP Developers & Contributors
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
;;;     v0.2.0 (21ffe4b22a9683cf24ae0763359e401d1284cc7a)
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

;; This is incorrect but fits both 64-bit Linux and 64-bit macOS, so
;; is good enough for now.
(defctype size :unsigned-long)

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

;; Opaque data structure that holds rewritable "scratch space"
;;
;; The purpose of this structure is to replace dynamic memory allocations,
;; because we target architectures where this may not be available. It is
;; essentially a resizable (within specified parameters) block of bytes,
;; which is initially created either by memory allocation or TODO as a pointer
;; into some fixed rewritable space.
;;
;; Unlike the context object, this cannot safely be shared between threads
;; without additional synchronization logic.
;;
(defcstruct secp256k1-scratch-space)

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
(defconstant +secp256k1-flags-type-mask+        (- (ash 1 8) 1))
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
    (assert (not (zerop (secp256k1-context-randomize ctx cseed32)))
            () "Context randomization error."))
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

;; Create a secp256k1 scratch space object.
;;
;; Returns: a newly created scratch space.
;; Args: ctx:  an existing context object.
;; In:   size: amount of memory to be available as scratch space. Some extra
;;             (<100 bytes) will be allocated for extra accounting.
;;
(defcfun "secp256k1_scratch_space_create" :pointer
  (ctx  (:pointer (:struct secp256k1-context)))
  (size size))

;; Destroy a secp256k1 scratch space.
;;
;; The pointer may not be used afterwards.
;; Args:       ctx: a secp256k1 context object.
;;         scratch: space to destroy
;;
(defcfun "secp256k1_scratch_space_destroy" :void
  (ctx     (:pointer (:struct secp256k1-context)))
  (scratch (:pointer (:struct secp256k1-scratch-space))))

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
  (inputlen size))

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
  (outputlen (:pointer size))
  (pubkey    (:pointer (:struct secp256k1-pubkey)))
  (flags     :unsigned-int))

(defun ec-pubkey-serialize (pubkey &key compressed)
  (let ((outputlen (if compressed 33 65)))
    (with-foreign-objects
        ((coutput :unsigned-char outputlen)
         (coutputlen 'size 1)
         (cpubkey '(:struct secp256k1-pubkey)))
      (setf (mem-aref coutputlen 'size 0) outputlen)
      (bytes-to-foreign pubkey cpubkey 64)
      (secp256k1-ec-pubkey-serialize *secp256k1-context* coutput coutputlen cpubkey
                                     (if compressed
                                         +secp256k1-ec-compressed+
                                         +secp256k1-ec-uncompressed+))
      (bytes-from-foreign nil coutput (mem-aref coutputlen :unsigned-int 0)))))

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
  (inputlen size))

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
;;
(defcfun "secp256k1_ecdsa_signature_serialize_der" :int
  (ctx       (:pointer (:struct secp256k1-context)))
  (output    (:pointer :unsigned-char))
  (outputlen (:pointer size))
  (sig       (:pointer (:struct secp256k1-ecdsa-signature))))

(defun ecdsa-signature-serialize-der (signature)
  (with-foreign-objects
      ((coutput :unsigned-char 74)
       (coutputlen 'size 1)
       (csignature '(:struct secp256k1-ecdsa-signature)))
    (setf (mem-aref coutputlen 'size 0) 74)
    (bytes-to-foreign signature csignature 64)
    (unless (zerop (secp256k1-ecdsa-signature-serialize-der
                    *secp256k1-context* coutput coutputlen csignature))
      (bytes-from-foreign nil coutput (mem-aref coutputlen 'size 0)))))

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
    (unless (zerop (secp256k1-ecdsa-sign *secp256k1-context* csignature cmsg32 cseckey
                                         (null-pointer) (null-pointer)))
      (bytes-from-foreign nil csignature 64))))

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
    (unless (zerop (secp256k1-ec-seckey-verify *secp256k1-context* cseckey))
      t)))

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
    (unless (zerop (secp256k1-ec-pubkey-create *secp256k1-context* cpubkey cseckey))
      (bytes-from-foreign nil cpubkey 64))))

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
    (secp256k1-ec-privkey-negate *secp256k1-context* cseckey)
    (bytes-from-foreign seckey cseckey 32)))

;; Same as secp256k1_ec_seckey_negate, but DEPRECATED. Will be removed in
;; future versions.
(defcfun "secp256k1_ec_privkey_negate" :int
  (ctx    (:pointer (:struct secp256k1-context)))
  (seckey (:pointer :unsigned-char)))

(defun ec-privkey-negate (seckey)
  (with-foreign-objects
      ((cseckey :unsigned-char 32))
    (bytes-to-foreign seckey cseckey 32)
    (secp256k1-ec-privkey-negate *secp256k1-context* cseckey)
    (bytes-from-foreign seckey cseckey 32)))

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

;; Same as secp256k1_ec_seckey_tweak_add, but DEPRECATED. Will be removed in
;; future versions.
(defcfun "secp256k1_ec_privkey_tweak_add" :int
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

;; Same as secp256k1_ec_seckey_tweak_mul, but DEPRECATED. Will be removed in
;; future versions.
(defcfun "secp256k1_ec_privkey_tweak_mul" :int
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
  (n   size))

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
      (secp256k1-ec-pubkey-combine *secp256k1-context* cpubkey pins n)
      (bytes-from-foreign nil cpubkey 64))))

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
  (taglen size)
  (msg    (:pointer :unsigned-char))
  (msglen size))


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
(defcfun "secp256k1_context_preallocated_size" size
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
(defcfun "secp256k1_context_preallocated_clone_size" size
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
  (pk-parity :int)
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

(defconstant +secp256k1-schnorrsig-extraparams-magic+ '(0xda 0x6f 0xb3 0x8c))

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
  (msglen      size)
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
  (msglen size)
  (pubkey (:pointer (:struct secp256k1-xonly-pubkey))))


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

(defun serialize-pubkey (pubkey &key compressed)
  (ec-pubkey-serialize (pubkey-bytes pubkey) :compressed compressed))

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

(defun combine-pubkeys (&rest pubkeys)
  (%make-pubkey
   :bytes
   (ec-pubkey-combine (mapcar #'pubkey-bytes pubkeys))))
