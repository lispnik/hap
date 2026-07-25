;;;; pairing.lisp — HAP Pair-Setup (HAP spec §5.6).
;;;;
;;;; A 6-message TLV exchange building on SRP-6a: the controller proves knowledge
;;;; of the 8-digit setup code (M1-M4), then the two sides exchange and sign their
;;;; long-term Ed25519 public keys over a ChaCha20-Poly1305 channel keyed from the
;;;; SRP secret (M5-M6).  Both roles are implemented so a full pairing can run
;;;; in-process; a real iPhone drives the accessory side over HTTP (M2 transport).

(in-package #:hap)

;;; HKDF salts/infos and nonces (HAP §5.6).
(defparameter +ps-encrypt-salt+ "Pair-Setup-Encrypt-Salt")
(defparameter +ps-encrypt-info+ "Pair-Setup-Encrypt-Info")
(defparameter +ps-controller-sign-salt+ "Pair-Setup-Controller-Sign-Salt")
(defparameter +ps-controller-sign-info+ "Pair-Setup-Controller-Sign-Info")
(defparameter +ps-accessory-sign-salt+ "Pair-Setup-Accessory-Sign-Salt")
(defparameter +ps-accessory-sign-info+ "Pair-Setup-Accessory-Sign-Info")

(defconstant +tlv-error-authentication+ 2)
(defconstant +tlv-error-max-tries+ 5)
(defconstant +tlv-error-busy+ 7)

(defun ps-nonce (name)
  "An 8-char HAP nonce name -> 12-byte ChaCha20-Poly1305 nonce (4 zero bytes first)."
  (concatenate '(vector (unsigned-byte 8))
               (make-array 4 :element-type '(unsigned-byte 8) :initial-element 0)
               (s->octets name)))

(defun hkdf-key (salt-str ikm info-str)
  (hkdf-sha512 (s->octets salt-str) ikm (s->octets info-str) 32))

(defun octets->string (v) (sb-ext:octets-to-string v :external-format :utf-8))

(defun error-tlv (state code)
  (tlv8-encode (list (cons +tlv-state+ state) (cons +tlv-error+ code))))

;;; ==========================================================================
;;; Accessory side (SRP server)
;;; ==========================================================================

(defstruct pair-session accessory salt v b shared-key encrypt-key)

(defun pair-setup-m2 (session)
  "Respond to the controller's M1 with M2: State=2, PublicKey=B, Salt=s."
  (let* ((acc (pair-session-accessory session))
         (group *hap-srp-group*)
         (salt (ironclad:random-data 16))
         (b (bytes->int (ironclad:random-data 32)))
         (v (srp-verifier group salt "Pair-Setup" (accessory-setup-code acc))))
    (setf (pair-session-salt session) salt
          (pair-session-v session) v
          (pair-session-b session) b)
    (tlv8-encode (list (cons +tlv-state+ 2)
                       (cons +tlv-public-key+ (srp-pad group (srp-b-pub group v b)))
                       (cons +tlv-salt+ salt)))))

(defun pair-setup-m4 (session m3-tlv)
  "Verify the controller's SRP proof (M3) and respond with M4 (server proof) — or
an authentication error if the setup code was wrong."
  (let* ((group *hap-srp-group*)
         (items (tlv8-decode m3-tlv))
         (a-pub (bytes->int (tlv8-get items +tlv-public-key+)))
         (client-proof (tlv8-get items +tlv-proof+))
         (v (pair-session-v session))
         (b (pair-session-b session))
         (salt (pair-session-salt session))
         (secret (srp-server-secret group b a-pub v))
         (k (srp-session-key group secret))
         (b-pub (srp-b-pub group v b))
         (expected (srp-m1 group "Pair-Setup" salt a-pub b-pub k)))
    (cond
      ((equalp client-proof expected)
       (setf (pair-session-shared-key session) k
             (pair-session-encrypt-key session)
             (hkdf-key +ps-encrypt-salt+ k +ps-encrypt-info+))
       (tlv8-encode (list (cons +tlv-state+ 4)
                          (cons +tlv-proof+ (srp-m2 group a-pub expected k)))))
      (t (error-tlv 4 +tlv-error-authentication+)))))

(defun pair-setup-m6 (session m5-tlv)
  "Decrypt the controller's device info (M5), verify its signature, store its
LTPK, and respond with the accessory's signed device info (M6)."
  (let* ((acc (pair-session-accessory session))
         (items (tlv8-decode m5-tlv))
         (enc (tlv8-get items +tlv-encrypted-data+))
         (ekey (pair-session-encrypt-key session))
         (k (pair-session-shared-key session))
         (plain (chacha20-poly1305-decrypt
                 ekey (ps-nonce "PS-Msg05") nil
                 (subseq enc 0 (- (length enc) 16))
                 (subseq enc (- (length enc) 16)))))
    (unless plain (return-from pair-setup-m6 (error-tlv 6 +tlv-error-authentication+)))
    (let* ((sub (tlv8-decode plain))
           (ios-id (tlv8-get sub +tlv-identifier+))
           (ios-ltpk (tlv8-get sub +tlv-public-key+))
           (ios-sig (tlv8-get sub +tlv-signature+))
           (ios-x (hkdf-key +ps-controller-sign-salt+ k +ps-controller-sign-info+))
           (ios-info (cat ios-x ios-id ios-ltpk)))
      (unless (ed25519-verify ios-ltpk ios-info ios-sig)
        (return-from pair-setup-m6 (error-tlv 6 +tlv-error-authentication+)))
      ;; Controller authenticated — remember it.
      (setf (gethash (octets->string ios-id) (accessory-paired-controllers acc)) ios-ltpk
            (accessory-paired acc) t)
      ;; Accessory's own signed device info, encrypted back.
      (let* ((acc-x (hkdf-key +ps-accessory-sign-salt+ k +ps-accessory-sign-info+))
             (acc-id (s->octets (accessory-id acc)))
             (acc-ltpk (accessory-public acc))
             (acc-info (cat acc-x acc-id acc-ltpk))
             (acc-sig (ed25519-sign (accessory-seed acc) acc-info))
             (sub-tlv (tlv8-encode (list (cons +tlv-identifier+ acc-id)
                                         (cons +tlv-public-key+ acc-ltpk)
                                         (cons +tlv-signature+ acc-sig)))))
        (multiple-value-bind (ct tag)
            (chacha20-poly1305-encrypt ekey (ps-nonce "PS-Msg06") nil sub-tlv)
          (tlv8-encode (list (cons +tlv-state+ 6)
                             (cons +tlv-encrypted-data+ (cat ct tag)))))))))

;;; ==========================================================================
;;; Controller side (SRP client) — for the initiator role and for testing
;;; ==========================================================================

(defstruct controller
  (seed nil) (public nil)
  (pairing-id (format nil "~(~{~2,'0X~}~)" (coerce (ironclad:random-data 8) 'list))))

(defun make-hap-controller ()
  (multiple-value-bind (seed pub) (ed25519-generate)
    (make-controller :seed seed :public pub)))

(defstruct controller-session
  controller setup-code a x shared-key encrypt-key accessory-id accessory-ltpk)

(defun pair-setup-controller-m1 ()
  "M1: State=1, Method=0 (Pair-Setup)."
  (tlv8-encode (list (cons +tlv-state+ 1) (cons +tlv-method+ 0))))

(defun pair-setup-controller-m3 (cs m2-tlv)
  "From the accessory's M2 (B, salt) build M3 (A, client proof)."
  (let* ((group *hap-srp-group*)
         (items (tlv8-decode m2-tlv))
         (b-pub (bytes->int (tlv8-get items +tlv-public-key+)))
         (salt (tlv8-get items +tlv-salt+))
         (a (bytes->int (ironclad:random-data 32)))
         (x (srp-x group salt "Pair-Setup" (controller-session-setup-code cs)))
         (a-pub (srp-a-pub group a))
         (secret (srp-client-secret group a b-pub x))
         (k (srp-session-key group secret))
         (proof (srp-m1 group "Pair-Setup" salt a-pub b-pub k)))
    (setf (controller-session-a cs) a
          (controller-session-x cs) x
          (controller-session-shared-key cs) k
          (controller-session-encrypt-key cs) (hkdf-key +ps-encrypt-salt+ k +ps-encrypt-info+))
    (tlv8-encode (list (cons +tlv-state+ 3)
                       (cons +tlv-public-key+ (srp-pad group a-pub))
                       (cons +tlv-proof+ proof)))))

(defun pair-setup-controller-m5 (cs m4-tlv)
  "From the accessory's M4 (server proof) build M5 (encrypted, signed device info).
Signals on an error TLV (e.g. wrong setup code)."
  (let* ((items (tlv8-decode m4-tlv)))
    (when (tlv8-get items +tlv-error+)
      (error "Pair-Setup rejected by accessory (error ~D) — wrong setup code?"
             (tlv8-get-integer items +tlv-error+)))
    (let* ((ctrl (controller-session-controller cs))
           (k (controller-session-shared-key cs))
           (ekey (controller-session-encrypt-key cs))
           (ios-x (hkdf-key +ps-controller-sign-salt+ k +ps-controller-sign-info+))
           (ios-id (s->octets (controller-pairing-id ctrl)))
           (ios-ltpk (controller-public ctrl))
           (ios-info (cat ios-x ios-id ios-ltpk))
           (ios-sig (ed25519-sign (controller-seed ctrl) ios-info))
           (sub (tlv8-encode (list (cons +tlv-identifier+ ios-id)
                                   (cons +tlv-public-key+ ios-ltpk)
                                   (cons +tlv-signature+ ios-sig)))))
      (multiple-value-bind (ct tag)
          (chacha20-poly1305-encrypt ekey (ps-nonce "PS-Msg05") nil sub)
        (tlv8-encode (list (cons +tlv-state+ 5)
                           (cons +tlv-encrypted-data+ (cat ct tag))))))))

(defun pair-setup-controller-finish (cs m6-tlv)
  "Process the accessory's M6: decrypt, verify the accessory's signature, and
store its LTPK.  Returns the accessory pairing id on success."
  (let* ((items (tlv8-decode m6-tlv)))
    (when (tlv8-get items +tlv-error+)
      (error "Pair-Setup M6 error ~D" (tlv8-get-integer items +tlv-error+)))
    (let* ((k (controller-session-shared-key cs))
           (ekey (controller-session-encrypt-key cs))
           (enc (tlv8-get items +tlv-encrypted-data+))
           (plain (chacha20-poly1305-decrypt
                   ekey (ps-nonce "PS-Msg06") nil
                   (subseq enc 0 (- (length enc) 16))
                   (subseq enc (- (length enc) 16)))))
      (unless plain (error "Pair-Setup M6 decryption failed"))
      (let* ((sub (tlv8-decode plain))
             (acc-id (tlv8-get sub +tlv-identifier+))
             (acc-ltpk (tlv8-get sub +tlv-public-key+))
             (acc-sig (tlv8-get sub +tlv-signature+))
             (acc-x (hkdf-key +ps-accessory-sign-salt+ k +ps-accessory-sign-info+))
             (acc-info (cat acc-x acc-id acc-ltpk)))
        (unless (ed25519-verify acc-ltpk acc-info acc-sig)
          (error "Accessory signature invalid"))
        (setf (controller-session-accessory-id cs) (octets->string acc-id)
              (controller-session-accessory-ltpk cs) acc-ltpk)
        (octets->string acc-id)))))
