;;;; secure.lisp — HAP Pair-Verify (§5.7) and the encrypted session (§6.5).
;;;;
;;;; Pair-Verify runs on every reconnect: an ephemeral X25519 exchange, each side
;;;; signing its ephemeral key with its long-term Ed25519 key and checking the
;;;; other against the LTPK stored at Pair-Setup.  It yields a shared secret from
;;;; which two directional ChaCha20-Poly1305 keys are derived; all subsequent
;;;; HTTP is then carried as length-prefixed encrypted frames.  A Gray stream
;;;; wraps the socket so the plaintext HTTP code runs unchanged over the tunnel.

(in-package #:hap)

(defparameter +pv-encrypt-salt+ "Pair-Verify-Encrypt-Salt")
(defparameter +pv-encrypt-info+ "Pair-Verify-Encrypt-Info")
(defparameter +control-salt+ "Control-Salt")
(defparameter +control-read-info+ "Control-Read-Encryption-Key")
(defparameter +control-write-info+ "Control-Write-Encryption-Key")

;;; --- session keys + frame codec --------------------------------------------

(defstruct (hap-session (:constructor %make-hap-session))
  read-key write-key (read-counter 0) (write-counter 0))

(defun make-session-keys (shared role)
  "Derive the two directional keys.  ROLE :ACCESSORY or :CONTROLLER — the labels
are named from the accessory's view (Read = accessory->controller)."
  (flet ((k (info) (hkdf-key +control-salt+ shared info)))
    (if (eq role :accessory)
        (%make-hap-session :read-key (k +control-write-info+) :write-key (k +control-read-info+))
        (%make-hap-session :read-key (k +control-read-info+) :write-key (k +control-write-info+)))))

(defun session-nonce (counter)
  "12-byte nonce: 4 zero bytes then the 64-bit little-endian frame counter."
  (let ((v (make-array 12 :element-type '(unsigned-byte 8) :initial-element 0)))
    (dotimes (i 8 v) (setf (aref v (+ 4 i)) (ldb (byte 8 (* 8 i)) counter)))))

(defun session-encrypt (session plaintext)
  "Frame PLAINTEXT into <=1024-byte ChaCha20-Poly1305 blocks (2-byte LE length as
AAD, then ciphertext, then the 16-byte tag)."
  (let ((out (0conf:make-writer))
        (n (length plaintext)))
    (loop for i from 0 below n by 1024
          for len = (min 1024 (- n i))
          for aad = (make-array 2 :element-type '(unsigned-byte 8)
                                  :initial-contents (list (ldb (byte 8 0) len) (ldb (byte 8 8) len)))
          do (multiple-value-bind (ct tag)
                 (chacha20-poly1305-encrypt (hap-session-write-key session)
                                            (session-nonce (hap-session-write-counter session))
                                            aad (subseq plaintext i (+ i len)))
               (0conf:write-octets out aad)
               (0conf:write-octets out ct)
               (0conf:write-octets out tag)
               (incf (hap-session-write-counter session))))
    (0conf:writer-result out)))

(defun session-read-frame (session stream)
  "Read + decrypt one frame from STREAM.  Returns the plaintext, or NIL at EOF or
on authentication failure."
  (let ((lb (make-array 2 :element-type '(unsigned-byte 8))))
    (unless (= 2 (read-sequence lb stream)) (return-from session-read-frame nil))
    (let* ((len (logior (aref lb 0) (ash (aref lb 1) 8)))
           (buf (make-array (+ len 16) :element-type '(unsigned-byte 8))))
      (unless (= (+ len 16) (read-sequence buf stream)) (return-from session-read-frame nil))
      (prog1 (chacha20-poly1305-decrypt (hap-session-read-key session)
                                        (session-nonce (hap-session-read-counter session))
                                        lb (subseq buf 0 len) (subseq buf len))
        (incf (hap-session-read-counter session))))))

(defun session-decrypt (session framed)
  "Decrypt every frame in the octet vector FRAMED; return the concatenated
plaintext.  (The streaming path uses SESSION-READ-FRAME; this is for whole
buffers and tests.)"
  (let ((out (0conf:make-writer)) (i 0) (n (length framed)))
    (loop while (< i n)
          do (let* ((len (logior (aref framed i) (ash (aref framed (1+ i)) 8)))
                    (aad (subseq framed i (+ i 2)))
                    (ct (subseq framed (+ i 2) (+ i 2 len)))
                    (tag (subseq framed (+ i 2 len) (+ i 2 len 16)))
                    (pt (chacha20-poly1305-decrypt (hap-session-read-key session)
                          (session-nonce (hap-session-read-counter session)) aad ct tag)))
               (unless pt (error "frame authentication failed"))
               (0conf:write-octets out pt)
               (incf (hap-session-read-counter session))
               (setf i (+ i 2 len 16))))
    (0conf:writer-result out)))

;;; --- Gray stream so plaintext HTTP flows over the encrypted tunnel ---------

(defclass secure-stream (sb-gray:fundamental-binary-input-stream
                         sb-gray:fundamental-binary-output-stream)
  ((raw :initarg :raw :reader ss-raw)
   (session :initarg :session :reader ss-session)
   (inbuf :initform nil) (inpos :initform 0)
   (outbuf :initform (make-array 256 :element-type '(unsigned-byte 8)
                                     :adjustable t :fill-pointer 0))))

(defun make-secure-stream (raw session) (make-instance 'secure-stream :raw raw :session session))

(defmethod sb-gray:stream-read-byte ((s secure-stream))
  (with-slots (raw session inbuf inpos) s
    (loop while (or (null inbuf) (>= inpos (length inbuf)))
          do (let ((frame (session-read-frame session raw)))
               (unless frame (return-from sb-gray:stream-read-byte :eof))
               (setf inbuf frame inpos 0)))
    (prog1 (aref inbuf inpos) (incf inpos))))

(defmethod sb-gray:stream-write-byte ((s secure-stream) byte)
  (vector-push-extend byte (slot-value s 'outbuf)) byte)

(defmethod stream-element-type ((s secure-stream)) '(unsigned-byte 8))

(defmethod sb-gray:stream-force-output ((s secure-stream)) (ss-flush s))
(defmethod sb-gray:stream-finish-output ((s secure-stream)) (ss-flush s))

(defun ss-flush (s)
  (with-slots (raw session outbuf) s
    (when (plusp (length outbuf))
      (write-sequence (session-encrypt session (coerce outbuf '(simple-array (unsigned-byte 8) (*)))) raw)
      (finish-output raw)
      (setf (fill-pointer outbuf) 0))))

;;; ==========================================================================
;;; Pair-Verify — accessory side
;;; ==========================================================================

(defstruct verify-session accessory ephemeral shared session-key controller-pub session)

(defun pair-verify-m2 (vs m1-tlv)
  "Respond to the controller's M1 (its ephemeral pubkey) with M2: the accessory's
ephemeral pubkey plus its encrypted, signed identity."
  (let* ((acc (verify-session-accessory vs))
         (ctrl-pub (tlv8-get (tlv8-decode m1-tlv) +tlv-public-key+))
         (eph (x25519-generate))
         (acc-eph-pub (x25519-keypair-public-bytes eph))
         (shared (x25519-shared-secret eph ctrl-pub))
         (skey (hkdf-key +pv-encrypt-salt+ shared +pv-encrypt-info+))
         (acc-id (s->octets (accessory-id acc)))
         (acc-info (cat acc-eph-pub acc-id ctrl-pub))
         (acc-sig (ed25519-sign (accessory-seed acc) acc-info))
         (sub (tlv8-encode (list (cons +tlv-identifier+ acc-id) (cons +tlv-signature+ acc-sig)))))
    (setf (verify-session-ephemeral vs) eph (verify-session-shared vs) shared
          (verify-session-session-key vs) skey (verify-session-controller-pub vs) ctrl-pub)
    (multiple-value-bind (ct tag) (chacha20-poly1305-encrypt skey (ps-nonce "PV-Msg02") nil sub)
      (tlv8-encode (list (cons +tlv-state+ 2)
                         (cons +tlv-public-key+ acc-eph-pub)
                         (cons +tlv-encrypted-data+ (cat ct tag)))))))

(defun pair-verify-m4 (vs m3-tlv)
  "Verify the controller's signed identity (M3) against the LTPK stored at
Pair-Setup and, on success, establish the encrypted session."
  (let* ((acc (verify-session-accessory vs))
         (enc (tlv8-get (tlv8-decode m3-tlv) +tlv-encrypted-data+))
         (skey (verify-session-session-key vs))
         (plain (chacha20-poly1305-decrypt skey (ps-nonce "PV-Msg03") nil
                                           (subseq enc 0 (- (length enc) 16))
                                           (subseq enc (- (length enc) 16)))))
    (unless plain (return-from pair-verify-m4 (error-tlv 4 +tlv-error-authentication+)))
    (let* ((sub (tlv8-decode plain))
           (ctrl-id (octets->string (tlv8-get sub +tlv-identifier+)))
           (ctrl-sig (tlv8-get sub +tlv-signature+))
           (ctrl-ltpk (gethash ctrl-id (accessory-paired-controllers acc))))
      (unless ctrl-ltpk (return-from pair-verify-m4 (error-tlv 4 +tlv-error-authentication+)))
      (let ((ctrl-info (cat (verify-session-controller-pub vs) (s->octets ctrl-id)
                            (x25519-keypair-public-bytes (verify-session-ephemeral vs)))))
        (unless (ed25519-verify ctrl-ltpk ctrl-info ctrl-sig)
          (return-from pair-verify-m4 (error-tlv 4 +tlv-error-authentication+)))
        (setf (verify-session-session vs)
              (make-session-keys (verify-session-shared vs) :accessory))
        (tlv8-encode (list (cons +tlv-state+ 4)))))))

;;; ==========================================================================
;;; Pair-Verify — controller side
;;; ==========================================================================

(defstruct verify-controller controller ephemeral shared accessory-ltpk session)

(defun pair-verify-controller-m1 (vc)
  (let ((eph (x25519-generate)))
    (setf (verify-controller-ephemeral vc) eph)
    (tlv8-encode (list (cons +tlv-state+ 1)
                       (cons +tlv-public-key+ (x25519-keypair-public-bytes eph))))))

(defun pair-verify-controller-m3 (vc m2-tlv)
  (let* ((items (tlv8-decode m2-tlv))
         (acc-eph-pub (tlv8-get items +tlv-public-key+))
         (enc (tlv8-get items +tlv-encrypted-data+))
         (eph (verify-controller-ephemeral vc))
         (shared (x25519-shared-secret eph acc-eph-pub))
         (skey (hkdf-key +pv-encrypt-salt+ shared +pv-encrypt-info+))
         (plain (chacha20-poly1305-decrypt skey (ps-nonce "PV-Msg02") nil
                                           (subseq enc 0 (- (length enc) 16))
                                           (subseq enc (- (length enc) 16)))))
    (unless plain (error "Pair-Verify M2 decryption failed"))
    (let* ((sub (tlv8-decode plain))
           (acc-id (tlv8-get sub +tlv-identifier+))
           (acc-sig (tlv8-get sub +tlv-signature+))
           (acc-info (cat acc-eph-pub acc-id (x25519-keypair-public-bytes eph))))
      (unless (ed25519-verify (verify-controller-accessory-ltpk vc) acc-info acc-sig)
        (error "Accessory signature invalid in Pair-Verify"))
      (setf (verify-controller-shared vc) shared)
      (let* ((ctrl (verify-controller-controller vc))
             (ctrl-id (s->octets (controller-pairing-id ctrl)))
             (ctrl-info (cat (x25519-keypair-public-bytes eph) ctrl-id acc-eph-pub))
             (ctrl-sig (ed25519-sign (controller-seed ctrl) ctrl-info))
             (sub-out (tlv8-encode (list (cons +tlv-identifier+ ctrl-id)
                                         (cons +tlv-signature+ ctrl-sig)))))
        (multiple-value-bind (ct tag) (chacha20-poly1305-encrypt skey (ps-nonce "PV-Msg03") nil sub-out)
          (tlv8-encode (list (cons +tlv-state+ 3) (cons +tlv-encrypted-data+ (cat ct tag)))))))))

(defun pair-verify-controller-finish (vc m4-tlv)
  (when (tlv8-get (tlv8-decode m4-tlv) +tlv-error+)
    (error "Pair-Verify rejected by accessory"))
  (setf (verify-controller-session vc)
        (make-session-keys (verify-controller-shared vc) :controller))
  vc)
