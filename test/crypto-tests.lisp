;;;; test/crypto-tests.lisp — crypto against published test vectors.

(in-package #:hap/test)

(in-suite hap-tests)

(defun hex (s)
  (let ((v (make-array (/ (length s) 2) :element-type '(unsigned-byte 8))))
    (dotimes (i (length v) v)
      (setf (aref v i) (parse-integer s :start (* 2 i) :end (+ 2 (* 2 i)) :radix 16)))))

(defun ascii (s) (sb-ext:string-to-octets s :external-format :utf-8))

(test sha512-vector
  ;; FIPS 180-4 SHA-512("abc")
  (is (equalp (hex "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")
              (hap::sha512 (ascii "abc")))))

(test chacha20-poly1305-rfc8439-vector
  ;; RFC 8439 §2.8.2 AEAD known-answer — the gate for the hand-built AEAD.
  (let* ((key   (hex "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"))
         (nonce (hex "070000004041424344454647"))
         (aad   (hex "50515253c0c1c2c3c4c5c6c7"))
         (pt    (ascii "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."))
         (want-ct  (hex "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"))
         (want-tag (hex "1ae10b594f09e26a7e902ecbd0600691")))
    (multiple-value-bind (ct tag) (hap::chacha20-poly1305-encrypt key nonce aad pt)
      (is (equalp want-ct ct))
      (is (equalp want-tag tag)))
    ;; decrypt round-trips and authenticates
    (is (equalp pt (hap::chacha20-poly1305-decrypt key nonce aad want-ct want-tag)))
    ;; a tampered tag must fail to authenticate
    (let ((bad (copy-seq want-tag)))
      (setf (aref bad 0) (logxor #xff (aref bad 0)))
      (is (null (hap::chacha20-poly1305-decrypt key nonce aad want-ct bad))))))

(test ed25519-sign-verify-round-trips
  (multiple-value-bind (seed pub) (hap::ed25519-generate)
    (is (= 32 (length seed)))
    (is (= 32 (length pub)))
    ;; the public key is deterministically derived from the seed
    (is (equalp pub (hap::ed25519-public-from-seed seed)))
    (let ((sig (hap::ed25519-sign seed (ascii "hello homekit"))))
      (is (= 64 (length sig)))
      (is (hap::ed25519-verify pub (ascii "hello homekit") sig))
      ;; wrong message must not verify
      (is (not (hap::ed25519-verify pub (ascii "tampered") sig))))))

(test x25519-ecdh-agrees
  (let* ((a (hap::x25519-generate))
         (b (hap::x25519-generate))
         (ss-a (hap::x25519-shared-secret a (hap::x25519-keypair-public-bytes b)))
         (ss-b (hap::x25519-shared-secret b (hap::x25519-keypair-public-bytes a))))
    (is (= 32 (length (hap::x25519-keypair-public-bytes a))))
    (is (equalp ss-a ss-b))))               ; both sides derive the same secret

(test hkdf-rfc5869-vector
  ;; RFC 5869 Test Case 1 (SHA-256) — gates the hand-rolled HKDF algorithm.
  (let ((okm (hap::hkdf :sha256
                        (hex "000102030405060708090a0b0c")                 ; salt
                        (hex "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b") ; ikm
                        (hex "f0f1f2f3f4f5f6f7f8f9")                       ; info
                        42)))
    (is (equalp (hex "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
                okm))))

(test hkdf-sha512-info-matters
  (let ((k1 (hap::hkdf-sha512 (ascii "salt") (ascii "ikm") (ascii "info") 32))
        (k2 (hap::hkdf-sha512 (ascii "salt") (ascii "ikm") (ascii "info") 32))
        (k3 (hap::hkdf-sha512 (ascii "salt") (ascii "ikm") (ascii "other") 32)))
    (is (equalp k1 k2))                      ; deterministic
    (is (not (equalp k1 k3)))))              ; info actually affects the output
