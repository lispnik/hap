;;;; test/discovery-tests.lisp

(in-package #:hap/test)

(in-suite hap-tests)

(test base64-known-vectors
  (flet ((b (s) (hap::base64-encode (ascii s))))
    (is (string= "TWFu" (b "Man")))
    (is (string= "TWE=" (b "Ma")))
    (is (string= "TQ==" (b "M")))
    (is (string= "" (b "")))))

(test device-id-format
  (let ((id (hap::random-device-id)))
    (is (= 17 (length id)))                       ; AA:BB:CC:DD:EE:FF
    (is (= 5 (count #\: id)))
    (is (every (lambda (c) (or (digit-char-p c 16) (char= c #\:))) id))))

(test setup-hash-deterministic
  (is (string= (hap::setup-hash "7OSX" "AA:BB:CC:DD:EE:FF")
               (hap::setup-hash "7OSX" "AA:BB:CC:DD:EE:FF")))
  (is (not (string= (hap::setup-hash "7OSX" "AA:BB:CC:DD:EE:FF")
                    (hap::setup-hash "ZZZZ" "AA:BB:CC:DD:EE:FF")))))

(test accessory-txt-has-required-hap-keys
  (let* ((acc (make-hap-accessory :name "Test Light" :model "cl-hap" :category 5))
         (txt (accessory-txt acc)))
    (flet ((v (k) (cdr (assoc k txt :test #'string=))))
      (is (string= "1.1" (v "pv")))
      (is (string= "1" (v "sf")))               ; unpaired -> discoverable
      (is (string= "5" (v "ci")))               ; category
      (is (string= "cl-hap" (v "md")))
      (is (string= (accessory-id acc) (v "id")))
      (is (string= "1" (v "c#")))
      (is (string= "1" (v "s#")))
      (is (not (null (v "sh")))))
    ;; once paired, sf flips to 0
    (setf (accessory-paired acc) t)
    (is (string= "0" (cdr (assoc "sf" (accessory-txt acc) :test #'string=))))))

(test accessory-identity-round-trips
  ;; the Ed25519 identity is usable: sign with the seed, verify with the public
  (let ((acc (make-hap-accessory)))
    (let ((sig (hap::ed25519-sign (hap::accessory-seed acc) (ascii "proof"))))
      (is (hap::ed25519-verify (hap::accessory-public acc) (ascii "proof") sig)))))

(test advertise-and-stop-lifecycle
  "Advertise over 0conf and tear down cleanly.  (Live Home-app visibility needs
working multicast, blocked here by the macOS entitlement; this checks the
responder lifecycle.)  Skips if the sandbox forbids binding 5353."
  (handler-case
      (let ((acc (make-hap-accessory :name "Lifecycle Test")))
        (advertise-accessory acc :probe nil)
        (is (not (null (hap::accessory-responder acc))))
        (update-accessory-advertisement acc)
        (stop-advertising acc)
        (is (null (hap::accessory-responder acc))))
    (error (e) (skip "advertising unavailable in this environment: ~A" e))))

(test discovered-accessory-info-parses-hap-txt
  "M6: a controller parses a discovered accessory's `_hap._tcp` TXT record into
usable metadata (this is the read side of discovery; live browsing needs the
multicast entitlement)."
  (let* ((acc (make-hap-accessory :name "Discoverable" :model "cl-hap" :category 5))
         (si (0conf:make-service-info :type "_hap._tcp.local" :name "Discoverable"
                                      :host "disc.local" :port 51999
                                      :txt (accessory-txt acc)))
         (info (accessory-advertisement-info si)))
    (is (string= "Discoverable" (getf info :name)))
    (is (= 51999 (getf info :port)))
    (is (string= (accessory-id acc) (getf info :id)))
    (is (string= "cl-hap" (getf info :model)))
    (is (eql 5 (getf info :category)))
    (is (null (getf info :paired)))            ; sf bit0=1 (unpaired) -> :paired NIL
    (is (string= "1.1" (getf info :protocol-version)))
    ;; once paired, sf bit0 clears and :paired flips true
    (setf (accessory-paired acc) t)
    (let ((info2 (accessory-advertisement-info
                  (0conf:make-service-info :type "_hap._tcp.local" :name "Discoverable"
                                           :port 51999 :txt (accessory-txt acc)))))
      (is (eq t (getf info2 :paired))))))
