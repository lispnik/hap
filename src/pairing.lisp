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

(defconstant +tlv-error-unknown+ 1)
(defconstant +tlv-error-authentication+ 2)
(defconstant +tlv-error-max-tries+ 5)
(defconstant +tlv-error-unavailable+ 6)
(defconstant +tlv-error-busy+ 7)

(defparameter *max-pair-attempts* 100
  "How many wrong setup-code attempts before the accessory locks Pair-Setup
(HAP mandates a cap with escalating delay; we use a hard cap).")

;;; HAP Pairings methods (the TLV Method value on /pairings, HAP §5.10-5.12).
(defconstant +pairing-method-add+ 3)
(defconstant +pairing-method-remove+ 4)
(defconstant +pairing-method-list+ 5)

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

(defun pair-setup-begin (acc session)
  "Claim the single Pair-Setup slot for SESSION.  Returns T if acquired, NIL if
another connection is already mid-setup (HAP allows only one at a time)."
  (bordeaux-threads:with-lock-held ((accessory-pairing-lock acc))
    (cond ((null (accessory-pairing-owner acc))
           (setf (accessory-pairing-owner acc) session) t)
          ((eq (accessory-pairing-owner acc) session) t)
          (t nil))))

(defun pair-setup-end (acc session)
  "Release the Pair-Setup slot if SESSION holds it (safe to call unconditionally)."
  (bordeaux-threads:with-lock-held ((accessory-pairing-lock acc))
    (when (eq (accessory-pairing-owner acc) session)
      (setf (accessory-pairing-owner acc) nil))))

(defun pair-setup-m2 (session)
  "Respond to the controller's M1 with M2: State=2, PublicKey=B, Salt=s — or an
error if the accessory is already paired, locked out, or busy with another setup."
  (let* ((acc (pair-session-accessory session))
         (group *hap-srp-group*))
    (cond
      ((accessory-paired acc)                       ; already paired -> use AddPairing
       (error-tlv 2 +tlv-error-unavailable+))
      ((>= (accessory-pair-attempts acc) *max-pair-attempts*)
       (error-tlv 2 +tlv-error-max-tries+))
      ((not (pair-setup-begin acc session))
       (error-tlv 2 +tlv-error-busy+))
      (t
       (let* ((salt (ironclad:random-data 16))
              (b (bytes->int (ironclad:random-data 32)))
              (v (srp-verifier group salt "Pair-Setup" (accessory-setup-code acc))))
         (setf (pair-session-salt session) salt
               (pair-session-v session) v
               (pair-session-b session) b)
         (tlv8-encode (list (cons +tlv-state+ 2)
                            (cons +tlv-public-key+ (srp-pad group (srp-b-pub group v b)))
                            (cons +tlv-salt+ salt))))))))

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
         (expected (srp-m1 group "Pair-Setup" salt a-pub b-pub k))
         (acc (pair-session-accessory session)))
    (cond
      ((ct-equal client-proof expected)          ; constant-time, like the AEAD tag
       (setf (pair-session-shared-key session) k
             (pair-session-encrypt-key session)
             (hkdf-key +ps-encrypt-salt+ k +ps-encrypt-info+))
       (tlv8-encode (list (cons +tlv-state+ 4)
                          (cons +tlv-proof+ (srp-m2 group a-pub expected k)))))
      (t
       ;; wrong setup code: count it, free the setup slot so a retry can begin,
       ;; and lock out once the cap is hit.
       (incf (accessory-pair-attempts acc))
       (pair-setup-end acc session)
       (error-tlv 4 (if (>= (accessory-pair-attempts acc) *max-pair-attempts*)
                        +tlv-error-max-tries+
                        +tlv-error-authentication+))))))

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
        (incf (accessory-pair-attempts acc))
        (pair-setup-end acc session)
        (return-from pair-setup-m6 (error-tlv 6 +tlv-error-authentication+)))
      ;; Controller authenticated — remember it as the first (admin) pairing.
      (let ((id (octets->string ios-id)))
        (setf (gethash id (accessory-paired-controllers acc)) ios-ltpk
              (gethash id (accessory-paired-permissions acc)) t   ; first pairing is admin
              (accessory-paired acc) t))
      (pair-setup-end acc session)
      (maybe-persist acc)
      ;; Re-advertise now that we're paired: the TXT status flag (sf) must flip
      ;; from 1 (unpaired) to 0, or HomeKit sees a paired accessory still claiming
      ;; to be unpaired and shows "No Response".
      (update-accessory-advertisement acc)
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
;;; Pairings — add / remove / list additional controllers (HAP §5.10-5.12)
;;; These run over the *encrypted* session; only an admin controller may use them.
;;; ==========================================================================

(defun accessory-controller-admin-p (acc id)
  "Is the controller with pairing id ID an admin on ACC?"
  (and id (gethash id (accessory-paired-permissions acc))))

(defun ps-add-pairing (acc admin items)
  "AddPairing (HAP §5.10): store an additional controller's id + LTPK + permission."
  (unless admin (return-from ps-add-pairing (error-tlv 2 +tlv-error-authentication+)))
  (let* ((id (octets->string (tlv8-get items +tlv-identifier+)))
         (ltpk (tlv8-get items +tlv-public-key+))
         (perm (tlv8-get-integer items +tlv-permissions+))
         (existing (gethash id (accessory-paired-controllers acc))))
    (cond
      ((and existing (not (equalp existing ltpk)))     ; id reused with a different key
       (error-tlv 2 +tlv-error-unknown+))
      (t (setf (gethash id (accessory-paired-controllers acc)) ltpk
               (gethash id (accessory-paired-permissions acc)) (eql perm 1))
         (maybe-persist acc)
         (tlv8-encode (list (cons +tlv-state+ 2)))))))

(defun ps-remove-pairing (acc admin items)
  "RemovePairing (HAP §5.11): forget a controller.  Idempotent; when the last
pairing goes the accessory reverts to unpaired."
  (unless admin (return-from ps-remove-pairing (error-tlv 2 +tlv-error-authentication+)))
  (let ((id (octets->string (tlv8-get items +tlv-identifier+))))
    (remhash id (accessory-paired-controllers acc))
    (remhash id (accessory-paired-permissions acc))
    (when (zerop (hash-table-count (accessory-paired-controllers acc)))
      (setf (accessory-paired acc) nil)
      (update-accessory-advertisement acc))       ; sf back to 1 (unpaired)
    (maybe-persist acc)
    (tlv8-encode (list (cons +tlv-state+ 2)))))

(defun ps-list-pairings (acc admin)
  "ListPairings (HAP §5.12): every controller's id, LTPK, and permission, the
entries separated by a Separator TLV."
  (unless admin (return-from ps-list-pairings (error-tlv 2 +tlv-error-authentication+)))
  (let ((out (list (cons +tlv-state+ 2)))
        (first t))
    (maphash (lambda (id ltpk)
               (unless first
                 (setf out (append out (list (cons +tlv-separator+
                                                   (make-array 0 :element-type '(unsigned-byte 8)))))))
               (setf first nil)
               (setf out (append out (list (cons +tlv-identifier+ (s->octets id))
                                           (cons +tlv-public-key+ ltpk)
                                           (cons +tlv-permissions+
                                                 (if (gethash id (accessory-paired-permissions acc)) 1 0))))))
             (accessory-paired-controllers acc))
    (tlv8-encode out)))

(defun dispatch-pairings (acc controller-id body)
  "Route a decrypted /pairings request by its Method.  CONTROLLER-ID identifies the
verified controller on this connection (for the admin check)."
  (let* ((items (tlv8-decode body))
         (method (tlv8-get-integer items +tlv-method+))
         (admin (accessory-controller-admin-p acc controller-id)))
    (cond
      ((eql method +pairing-method-add+)    (ps-add-pairing acc admin items))
      ((eql method +pairing-method-remove+) (ps-remove-pairing acc admin items))
      ((eql method +pairing-method-list+)   (ps-list-pairings acc admin))
      (t (error-tlv 2 +tlv-error-authentication+)))))

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
