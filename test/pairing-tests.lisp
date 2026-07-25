;;;; test/pairing-tests.lisp — full Pair-Setup between a Lisp accessory and
;;;; controller, in-process (no transport), proving the whole protocol.

(in-package #:hap/test)

(in-suite hap-tests)

(test pair-setup-full-handshake
  "Run all six Pair-Setup messages between a Lisp accessory (server) and a Lisp
controller (client) with the correct setup code — pairing must complete, both
sides agreeing on the key and each storing the other's long-term public key."
  (let* ((code "123-45-678")
         (acc (make-hap-accessory :name "Test Light" :category 5 :setup-code code))
         (ctrl (make-hap-controller))
         (as (hap::make-pair-session :accessory acc))
         (cs (hap::make-controller-session :controller ctrl :setup-code code)))
    (hap::pair-setup-controller-m1)                     ; M1: controller -> accessory
    (let* ((m2 (hap::pair-setup-m2 as))                 ; M2: B, salt
           (m3 (hap::pair-setup-controller-m3 cs m2))   ; M3: A, client proof
           (m4 (hap::pair-setup-m4 as m3))              ; M4: server proof
           (m5 (hap::pair-setup-controller-m5 cs m4))   ; M5: encrypted device info
           (m6 (hap::pair-setup-m6 as m5))              ; M6: accessory device info
           (acc-id (hap::pair-setup-controller-finish cs m6)))
      ;; both derived the same SRP session key
      (is (equalp (hap::pair-session-shared-key as)
                  (hap::controller-session-shared-key cs)))
      ;; accessory recorded the controller's LTPK under its pairing id
      (is (equalp (controller-public ctrl)
                  (gethash (controller-pairing-id ctrl)
                           (accessory-paired-controllers acc))))
      (is (accessory-paired acc))
      ;; controller learned the accessory's identity and LTPK
      (is (string= (accessory-id acc) acc-id))
      (is (equalp (hap::accessory-public acc)
                  (hap::controller-session-accessory-ltpk cs))))))

(test pair-setup-wrong-code-rejected
  "A controller with the wrong setup code fails at M4 with an authentication
error, and the accessory records no pairing."
  (let* ((acc (make-hap-accessory :setup-code "111-11-111"))
         (ctrl (make-hap-controller))
         (as (hap::make-pair-session :accessory acc))
         (cs (hap::make-controller-session :controller ctrl :setup-code "999-99-999")))
    (let* ((m2 (hap::pair-setup-m2 as))
           (m3 (hap::pair-setup-controller-m3 cs m2))
           (m4 (hap::pair-setup-m4 as m3)))
      (is (= hap::+tlv-error-authentication+
             (tlv8-get-integer (tlv8-decode m4) +tlv-error+)))
      (signals error (hap::pair-setup-controller-m5 cs m4))
      (is (not (accessory-paired acc)))
      (is (= 0 (hash-table-count (accessory-paired-controllers acc)))))))
