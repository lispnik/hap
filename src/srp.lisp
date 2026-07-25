;;;; srp.lisp — SRP-6a (RFC 5054 / RFC 2945), the HAP Pair-Setup PAKE.
;;;;
;;;; Plain finite-field math: the accessory is the SRP *server* (verifier holder),
;;;; the iOS controller is the client.  HAP uses the RFC 5054 3072-bit group with
;;;; SHA-512, username "Pair-Setup", and the 8-digit setup code as the password.
;;;;
;;;;   x  = H(salt | H(I | ":" | P))          v = g^x mod N
;;;;   k  = H(N | PAD(g))
;;;;   A  = g^a mod N                          B = (k*v + g^b) mod N
;;;;   u  = H(PAD(A) | PAD(B))
;;;;   client S = (B - k*g^x)^(a + u*x) mod N  server S = (A * v^u)^b mod N
;;;;   M1 = H(H(N) xor H(g) | H(I) | s | A | B | K)   K = H(S)
;;;;   M2 = H(A | M1 | K)
;;;;
;;;; The algorithm is gated against the RFC 5054 Appendix B test vector (1024-bit,
;;;; SHA-1); the HAP 3072/SHA-512 instantiation is exercised by a self-consistent
;;;; client<->server handshake.

(in-package #:hap)

(defstruct (srp-group (:constructor %make-srp-group))
  prime generator hash n-bytes)

(defun make-srp-group (prime generator hash)
  (%make-srp-group :prime prime :generator generator :hash hash
                   :n-bytes (ceiling (integer-length prime) 8)))

;; RFC 5054 Appendix A 3072-bit group (== RFC 3526 group 15), generator g = 5.
(defparameter +srp-3072-prime+
  #xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF)

(defparameter *hap-srp-group* (make-srp-group +srp-3072-prime+ 5 :sha512))

;;; --- helpers ---------------------------------------------------------------

(defun int->bytes (n length)
  "Big-endian octets of N, left-padded to LENGTH bytes."
  (let ((v (make-array length :element-type '(unsigned-byte 8))))
    (dotimes (i length v)
      (setf (aref v i) (ldb (byte 8 (* 8 (- length 1 i))) n)))))

(defun bytes->int (bytes)
  (let ((n 0)) (loop for b across bytes do (setf n (logior (ash n 8) b))) n))

(defun s->octets (s) (sb-ext:string-to-octets s :external-format :utf-8))

(defun cat (&rest vs)
  (apply #'concatenate '(vector (unsigned-byte 8))
         (mapcar (lambda (v) (coerce v '(vector (unsigned-byte 8)))) vs)))

(defun srp-hash-bytes (group &rest vs)
  (ironclad:digest-sequence (srp-group-hash group) (apply #'cat vs)))

(defun srp-hash-int (group &rest vs)
  (bytes->int (apply #'srp-hash-bytes group vs)))

(defun srp-pad (group n)
  (int->bytes n (srp-group-n-bytes group)))

(defun srp-n-bytes (group)
  (int->bytes (srp-group-prime group) (srp-group-n-bytes group)))

;;; --- SRP-6a computations ---------------------------------------------------

(defun srp-x (group salt username password)
  "x = H(salt | H(username | \":\" | password)).  SALT is octets."
  (srp-hash-int group salt
                (srp-hash-bytes group (s->octets username) (s->octets ":")
                                (s->octets password))))

(defun srp-verifier (group salt username password)
  "Returns (values v x) — the verifier v = g^x mod N."
  (let ((x (srp-x group salt username password)))
    (values (ironclad:expt-mod (srp-group-generator group) x (srp-group-prime group)) x)))

(defun srp-k (group)
  (srp-hash-int group (srp-n-bytes group) (srp-pad group (srp-group-generator group))))

(defun srp-u (group a-pub b-pub)
  (srp-hash-int group (srp-pad group a-pub) (srp-pad group b-pub)))

(defun srp-a-pub (group a)
  (ironclad:expt-mod (srp-group-generator group) a (srp-group-prime group)))

(defun srp-b-pub (group v b)
  "Server public B = (k*v + g^b) mod N."
  (let ((n (srp-group-prime group)))
    (mod (+ (* (srp-k group) v)
            (ironclad:expt-mod (srp-group-generator group) b n))
         n)))

(defun srp-client-secret (group a-priv b-pub x)
  "Client premaster S = (B - k*g^x)^(a + u*x) mod N."
  (let* ((n (srp-group-prime group))
         (g (srp-group-generator group))
         (k (srp-k group))
         (u (srp-u group (srp-a-pub group a-priv) b-pub))
         (base (mod (- b-pub (* k (ironclad:expt-mod g x n))) n)))
    (ironclad:expt-mod base (+ a-priv (* u x)) n)))

(defun srp-server-secret (group b-priv a-pub v)
  "Server premaster S = (A * v^u)^b mod N."
  (let* ((n (srp-group-prime group))
         (u (srp-u group a-pub (srp-b-pub group v b-priv))))
    (ironclad:expt-mod (mod (* a-pub (ironclad:expt-mod v u n)) n) b-priv n)))

(defun srp-session-key (group premaster)
  "K = H(PAD(S))."
  (srp-hash-bytes group (srp-pad group premaster)))

(defun srp-m1 (group username salt a-pub b-pub session-key)
  "Client proof M1 = H(H(N) xor H(g) | H(I) | s | A | B | K)."
  (let* ((hn (srp-hash-bytes group (srp-n-bytes group)))
         (hg (srp-hash-bytes group (srp-pad group (srp-group-generator group))))
         (hng (map '(vector (unsigned-byte 8)) #'logxor hn hg))
         (hi (srp-hash-bytes group (s->octets username))))
    (srp-hash-bytes group hng hi salt
                    (srp-pad group a-pub) (srp-pad group b-pub) session-key)))

(defun srp-m2 (group a-pub m1 session-key)
  "Server proof M2 = H(A | M1 | K)."
  (srp-hash-bytes group (srp-pad group a-pub) m1 session-key))
