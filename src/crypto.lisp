;;;; crypto.lisp — HAP crypto, built on ironclad.
;;;;
;;;; ironclad natively provides SHA-512, HMAC/HKDF, Ed25519, X25519, ChaCha20,
;;;; and Poly1305.  The one AEAD HAP needs — ChaCha20-Poly1305 (RFC 8439) — is
;;;; NOT a packaged ironclad mode, so we assemble it here from ChaCha20 + Poly1305
;;;; and gate it on the RFC 8439 test vectors before anything depends on it.

(in-package #:hap)

(defun sha512 (data)
  (ironclad:digest-sequence :sha512 (coerce data '(simple-array (unsigned-byte 8) (*)))))

(defun ct-equal (a b)
  "Constant-time octet-vector equality (for authentication tags)."
  (and (= (length a) (length b))
       (loop with diff = 0
             for x across a for y across b
             do (setf diff (logior diff (logxor x y)))
             finally (return (zerop diff)))))

(defun le64 (n)
  (let ((v (make-array 8 :element-type '(unsigned-byte 8))))
    (dotimes (i 8 v) (setf (aref v i) (ldb (byte 8 (* 8 i)) n)))))

(defun %pad16-length (n) (mod (- 16 (mod n 16)) 16))

;;; --- ChaCha20-Poly1305 AEAD (RFC 8439) -------------------------------------

(defun %chacha20-otk-and-cipher (key nonce)
  "Return (values one-time-poly1305-key cipher) where CIPHER is a ChaCha20 stream
positioned at block 1 — i.e. block 0's first 32 bytes become the Poly1305 key and
subsequent encryption uses counter 1+ (RFC 8439 §2.6/§2.8)."
  (let ((cipher (ironclad:make-cipher :chacha :key key :mode :stream
                                      :initialization-vector nonce))
        (block0 (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
    (ironclad:encrypt-in-place cipher block0)
    (values (subseq block0 0 32) cipher)))

(defun %poly1305-aead-tag (otk aad ciphertext)
  (let ((mac (ironclad:make-mac :poly1305 otk))
        (zeros (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (flet ((up (x) (ironclad:update-mac mac (coerce x '(simple-array (unsigned-byte 8) (*))))))
      (up aad)        (up (subseq zeros 0 (%pad16-length (length aad))))
      (up ciphertext) (up (subseq zeros 0 (%pad16-length (length ciphertext))))
      (up (le64 (length aad)))
      (up (le64 (length ciphertext))))
    (ironclad:produce-mac mac)))

(defun chacha20-poly1305-encrypt (key nonce aad plaintext)
  "AEAD encrypt.  KEY 32 bytes, NONCE 12 bytes.  Returns (values ciphertext tag)."
  (let ((aad (or aad #())))
    (multiple-value-bind (otk cipher) (%chacha20-otk-and-cipher key nonce)
      (let ((ct (copy-seq (coerce plaintext '(simple-array (unsigned-byte 8) (*))))))
        (ironclad:encrypt-in-place cipher ct)      ; stream: uses counter 1+
        (values ct (%poly1305-aead-tag otk aad ct))))))

(defun chacha20-poly1305-decrypt (key nonce aad ciphertext tag)
  "AEAD decrypt.  Returns the plaintext, or NIL if the tag doesn't authenticate."
  (let ((aad (or aad #())))
    (multiple-value-bind (otk cipher) (%chacha20-otk-and-cipher key nonce)
      (when (ct-equal tag (%poly1305-aead-tag otk aad ciphertext))
        (let ((pt (copy-seq (coerce ciphertext '(simple-array (unsigned-byte 8) (*))))))
          (ironclad:encrypt-in-place cipher pt)    ; stream cipher: XOR both ways
          pt)))))

(defun %octets (x) (coerce x '(simple-array (unsigned-byte 8) (*))))

;;; --- Ed25519 (long-term identity signatures) -------------------------------

(defun ed25519-generate ()
  "Return (values seed-32 public-32) for a fresh Ed25519 identity key."
  (multiple-value-bind (priv pub) (ironclad:generate-key-pair :ed25519)
    (values (ironclad:ed25519-key-x priv) (ironclad:ed25519-key-y pub))))

(defun ed25519-public-from-seed (seed)
  (ironclad:ed25519-key-y (ironclad:make-private-key :ed25519 :x seed)))

(defun ed25519-sign (seed message)
  (ironclad:sign-message (ironclad:make-private-key :ed25519 :x seed) (%octets message)))

(defun ed25519-verify (public-bytes message signature)
  (ironclad:verify-signature (ironclad:make-public-key :ed25519 :y public-bytes)
                             (%octets message) (%octets signature)))

;;; --- X25519 (ephemeral session key agreement) ------------------------------

(defstruct (x25519-keypair (:constructor %make-x25519-keypair))
  private public-bytes)

(defun x25519-generate ()
  (multiple-value-bind (priv pub) (ironclad:generate-key-pair :curve25519)
    (%make-x25519-keypair :private priv :public-bytes (ironclad:curve25519-key-y pub))))

(defun x25519-shared-secret (keypair their-public-bytes)
  "The X25519 shared secret between our KEYPAIR and the peer's raw public key.
Rejects an all-zero result: that is what a low-order/degenerate peer public key
produces, and continuing would key the session off a value the peer controls."
  (let ((secret (ironclad:diffie-hellman
                 (x25519-keypair-private keypair)
                 (ironclad:make-public-key :curve25519 :y their-public-bytes))))
    (when (every #'zerop secret)
      (error "X25519 produced an all-zero shared secret (invalid peer public key)"))
    secret))

;;; --- HKDF (RFC 5869) -------------------------------------------------------
;;;
;;; Hand-rolled on ironclad's HMAC because ironclad's built-in :hmac-kdf ignores
;;; the `info` parameter — and HAP relies on distinct info strings to derive
;;; different keys (session read/write, pairing verify, etc.) from one secret.

(defun hmac (digest key data)
  (let ((h (ironclad:make-hmac (%octets key) digest)))
    (ironclad:update-hmac h (%octets data))
    (ironclad:hmac-digest h)))

(defun hkdf (digest salt ikm info length)
  "RFC 5869 HKDF-Extract-then-Expand with DIGEST."
  (let* ((hlen (ironclad:digest-length digest))
         (salt (if (plusp (length salt)) salt
                   (make-array hlen :element-type '(unsigned-byte 8) :initial-element 0)))
         (prk (hmac digest salt ikm))
         (out (make-array 0 :element-type '(unsigned-byte 8)))
         (prev (make-array 0 :element-type '(unsigned-byte 8))))
    (loop for i from 1 while (< (length out) length)
          do (setf prev (hmac digest prk
                              (concatenate '(vector (unsigned-byte 8))
                                           prev (%octets info) (vector i))))
             (setf out (concatenate '(vector (unsigned-byte 8)) out prev)))
    (subseq out 0 length)))

(defun hkdf-sha512 (salt ikm info length)
  "HKDF-SHA512 — the KDF HAP uses for session and pairing keys."
  (hkdf :sha512 salt ikm info length))
