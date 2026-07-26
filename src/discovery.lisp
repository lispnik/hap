;;;; discovery.lisp — HAP discovery over 0conf (the ONLY 0conf dependency).
;;;;
;;;; An accessory advertises "_hap._tcp" with the HAP TXT record (HAP spec §6.4)
;;;; so it appears in the iPhone Home app's "Add Accessory" screen.  All of this
;;;; is composition of 0conf's public API — no new mDNS primitives.

(in-package #:hap)

(defun random-device-id ()
  "A random HAP accessory pairing id, e.g. \"A1:B2:C3:D4:E5:F6\"."
  (let ((b (ironclad:random-data 6)))
    (format nil "~{~2,'0X~^:~}" (coerce b 'list))))

(defun random-setup-id ()
  "A random 4-character setup id (uppercase alphanumeric)."
  (let ((alphabet "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        (b (ironclad:random-data 4)))
    (map 'string (lambda (x) (char alphabet (mod x 36))) b)))

(defparameter +invalid-setup-codes+
  '("000-00-000" "111-11-111" "222-22-222" "333-33-333" "444-44-444"
    "555-55-555" "666-66-666" "777-77-777" "888-88-888" "999-99-999"
    "123-45-678" "876-54-321")
  "Setup codes HAP forbids (all-same-digit and the two obvious sequences).")

(defun random-setup-code ()
  "A random HAP setup code formatted DDD-DD-DDD, avoiding the disallowed codes.
A per-accessory random code (not a fixed default) is what a real accessory must
present to the user for pairing."
  (loop for d = (map 'list (lambda (b) (digit-char (mod b 10))) (ironclad:random-data 8))
        for code = (format nil "~C~C~C-~C~C-~C~C~C"
                           (nth 0 d) (nth 1 d) (nth 2 d) (nth 3 d)
                           (nth 4 d) (nth 5 d) (nth 6 d) (nth 7 d))
        unless (member code +invalid-setup-codes+ :test #'string=)
          return code))

(defun base64-encode (bytes)
  "Standard base64 (with padding)."
  (let ((chars "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
        (out (make-string-output-stream))
        (n (length bytes)))
    (loop for i from 0 below n by 3
          do (let* ((b0 (aref bytes i))
                    (b1 (if (< (+ i 1) n) (aref bytes (+ i 1)) 0))
                    (b2 (if (< (+ i 2) n) (aref bytes (+ i 2)) 0))
                    (word (logior (ash b0 16) (ash b1 8) b2)))
               (write-char (char chars (ldb (byte 6 18) word)) out)
               (write-char (char chars (ldb (byte 6 12) word)) out)
               (write-char (if (< (+ i 1) n) (char chars (ldb (byte 6 6) word)) #\=) out)
               (write-char (if (< (+ i 2) n) (char chars (ldb (byte 6 0) word)) #\=) out)))
    (get-output-stream-string out)))

(defun setup-hash (setup-id device-id)
  "HAP `sh` TXT value: base64 of the first 4 bytes of SHA-512(setupID || deviceID)."
  (base64-encode (subseq (sha512 (sb-ext:string-to-octets
                                  (concatenate 'string setup-id device-id)
                                  :external-format :utf-8))
                         0 4)))

(defstruct accessory
  (id (random-device-id))          ; pairing id "AA:BB:CC:DD:EE:FF"
  (name "Lisp Accessory")
  (model "cl-hap")
  (category 2)                     ; HAP accessory category (2 = bridge; 5 = lightbulb …)
  (config-number 1)               ; c# — bump when the accessory database changes
  (state-number 1)                ; s#
  (setup-code (random-setup-code)) ; the 8-digit code (used at pairing, M2)
  (setup-id (random-setup-id))
  (port 51826)                    ; HAP TCP port
  (paired nil)
  seed public                      ; Ed25519 long-term identity (raw octets)
  (paired-controllers (make-hash-table :test 'equal))  ; pairingID -> controller LTPK
  (paired-permissions (make-hash-table :test 'equal))  ; pairingID -> admin-p
  (aid 1)                          ; this accessory's aid in its own database
  (services '())                   ; list of HAP-SERVICE (the accessory model, M4)
  (bridged '())                    ; child accessories exposed through this one (bridge)
  (iid-counter 10)                 ; next free instance-id block for added services
  ;; Pair-Setup guarding (HAP §5.6): one attempt at a time, with a wrong-code cap.
  (pairing-lock (bordeaux-threads:make-lock "hap-pairing"))
  (pairing-owner nil)              ; the PAIR-SESSION currently running Pair-Setup
  (pair-attempts 0)                ; failed setup-code attempts (for lockout)
  (on-identify nil)                ; optional (lambda ()) run on POST /identify
  (store-path nil)                 ; when set, auto-persist on pair/unpair
  responder service-info)          ; live 0conf state

(defun make-hap-accessory (&rest args)
  "Create an accessory with a fresh Ed25519 identity."
  (multiple-value-bind (seed pub) (ed25519-generate)
    (apply #'make-accessory :seed seed :public pub args)))

(defun accessory-txt (acc)
  "The HAP `_hap._tcp` TXT record as an alist (HAP spec §6.4)."
  (list (cons "c#" (princ-to-string (accessory-config-number acc)))
        (cons "ff" "0")                                         ; feature flags
        (cons "id" (accessory-id acc))
        (cons "md" (accessory-model acc))
        (cons "pv" "1.1")                                       ; protocol version
        (cons "s#" (princ-to-string (accessory-state-number acc)))
        (cons "sf" (if (accessory-paired acc) "0" "1"))         ; bit0=1 -> unpaired
        (cons "ci" (princ-to-string (accessory-category acc)))
        (cons "sh" (setup-hash (accessory-setup-id acc) (accessory-id acc)))))

(defun advertise-accessory (acc &key (probe nil))
  "Start advertising ACC as `_hap._tcp` on the LAN via 0conf.  (Live visibility in
the Home app needs working multicast — blocked by the macOS entitlement here, but
the record set is correct and works on an entitled/Linux host.)"
  (let ((responder (0conf:start-responder (0conf:make-responder)))
        (info (0conf:make-service-info :type "_hap._tcp.local"
                                       :name (accessory-name acc)
                                       :port (accessory-port acc)
                                       :txt (accessory-txt acc))))
    (setf (accessory-responder acc) responder
          (accessory-service-info acc) info)
    (0conf:register-service responder info :probe probe)
    acc))

(defun update-accessory-advertisement (acc)
  "Re-publish the TXT after a config/state/paired change (bumps propagate)."
  (when (accessory-responder acc)
    (0conf:update-service-txt (accessory-responder acc)
                              (accessory-service-info acc)
                              (accessory-txt acc)))
  acc)

(defun stop-advertising (acc)
  (when (accessory-responder acc)
    (0conf:stop-responder (accessory-responder acc))
    (setf (accessory-responder acc) nil))
  acc)
