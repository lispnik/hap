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

(test pair-setup-already-paired-rejected
  "Once paired, a fresh Pair-Setup is refused (kTLVError_Unavailable) — additional
controllers must come through AddPairing, not Pair-Setup."
  (let ((acc (make-hap-accessory :setup-code "111-22-333")))
    (setf (accessory-paired acc) t)
    (is (= hap::+tlv-error-unavailable+
           (tlv8-get-integer (tlv8-decode (hap::pair-setup-m2 (hap::make-pair-session :accessory acc)))
                             +tlv-error+)))))

(test pair-setup-busy-when-another-in-progress
  "Only one Pair-Setup may be in flight; a second concurrent one gets kTLVError_Busy."
  (let* ((acc (make-hap-accessory :setup-code "111-22-333"))
         (s1 (hap::make-pair-session :accessory acc))
         (s2 (hap::make-pair-session :accessory acc)))
    (hap::pair-setup-m2 s1)                                     ; s1 claims the slot
    (is (= hap::+tlv-error-busy+
           (tlv8-get-integer (tlv8-decode (hap::pair-setup-m2 s2)) +tlv-error+)))
    (hap::pair-setup-end acc s1)                               ; s1 disconnects
    (is (= 2 (tlv8-get-integer (tlv8-decode (hap::pair-setup-m2 s2)) +tlv-state+)))))

(test pair-setup-locks-out-after-max-tries
  "After the wrong-code cap the accessory stops answering M2 with kTLVError_MaxTries,
and a wrong proof both increments the counter and frees the setup slot."
  (let* ((acc (make-hap-accessory :setup-code "111-11-111"))
         (ctrl (make-hap-controller))
         (as (hap::make-pair-session :accessory acc))
         (cs (hap::make-controller-session :controller ctrl :setup-code "999-99-999")))
    ;; one wrong attempt increments the counter and releases the slot
    (hap::pair-setup-m4 as (hap::pair-setup-controller-m3 cs (hap::pair-setup-m2 as)))
    (is (= 1 (hap::accessory-pair-attempts acc)))
    (is (null (hap::accessory-pairing-owner acc)))
    ;; drive the counter to the cap; M2 then locks out
    (setf (hap::accessory-pair-attempts acc) hap::*max-pair-attempts*)
    (is (= hap::+tlv-error-max-tries+
           (tlv8-get-integer (tlv8-decode (hap::pair-setup-m2 (hap::make-pair-session :accessory acc)))
                             +tlv-error+)))))
