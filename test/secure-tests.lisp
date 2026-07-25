;;;; test/secure-tests.lisp — Pair-Verify + the encrypted session.

(in-package #:hap/test)

(in-suite hap-tests)

(defun run-pair-setup (acc ctrl code)
  "Run a full in-process Pair-Setup; return the controller-session."
  (let ((as (hap::make-pair-session :accessory acc))
        (cs (hap::make-controller-session :controller ctrl :setup-code code)))
    (let* ((m2 (hap::pair-setup-m2 as))
           (m3 (hap::pair-setup-controller-m3 cs m2))
           (m4 (hap::pair-setup-m4 as m3))
           (m5 (hap::pair-setup-controller-m5 cs m4))
           (m6 (hap::pair-setup-m6 as m5)))
      (hap::pair-setup-controller-finish cs m6)
      cs)))

(test pair-verify-establishes-matching-session
  "After Pair-Setup, Pair-Verify establishes a session whose directional keys
cross-match, and a frame written by one side decrypts on the other."
  (let* ((code "112-23-334")
         (acc (make-hap-accessory :setup-code code))
         (ctrl (make-hap-controller))
         (cs (run-pair-setup acc ctrl code))
         (vs (hap::make-verify-session :accessory acc))
         (vc (hap::make-verify-controller
              :controller ctrl
              :accessory-ltpk (hap::controller-session-accessory-ltpk cs))))
    (let* ((v1 (hap::pair-verify-controller-m1 vc))
           (v2 (hap::pair-verify-m2 vs v1))
           (v3 (hap::pair-verify-controller-m3 vc v2))
           (v4 (hap::pair-verify-m4 vs v3)))
      (hap::pair-verify-controller-finish vc v4)
      (let ((asess (hap::verify-session-session vs))
            (csess (hap::verify-controller-session vc)))
        (is (not (null asess)))
        ;; the two directions cross-match
        (is (equalp (hap::hap-session-read-key asess) (hap::hap-session-write-key csess)))
        (is (equalp (hap::hap-session-write-key asess) (hap::hap-session-read-key csess)))
        ;; an accessory->controller frame decrypts on the controller
        (let* ((msg (ascii "hello over the encrypted HAP session"))
               (framed (hap::session-encrypt asess msg)))
          (is (equalp msg (hap::session-decrypt csess framed))))
        ;; and controller->accessory the other way (fresh counters)
        (let* ((msg2 (ascii "a request from the controller"))
               (framed2 (hap::session-encrypt csess msg2)))
          (is (equalp msg2 (hap::session-decrypt asess framed2))))))))

(test pair-verify-unknown-controller-rejected
  "Pair-Verify from a controller that never paired (accessory has no LTPK for it)
is rejected at M4."
  (let* ((acc (make-hap-accessory :setup-code "000-00-000"))  ; no paired controllers
         (ctrl (make-hap-controller))
         (vs (hap::make-verify-session :accessory acc))
         ;; controller fakes an accessory LTPK; it still can't be verified by acc
         (vc (hap::make-verify-controller :controller ctrl
                                          :accessory-ltpk (hap::accessory-public acc))))
    (let* ((v1 (hap::pair-verify-controller-m1 vc))
           (v2 (hap::pair-verify-m2 vs v1))
           (v3 (hap::pair-verify-controller-m3 vc v2))
           (v4 (hap::pair-verify-m4 vs v3)))
      (is (= hap::+tlv-error-authentication+
             (tlv8-get-integer (tlv8-decode v4) +tlv-error+)))
      (is (null (hap::verify-session-session vs))))))
