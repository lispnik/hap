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

(test pairings-add-list-remove-with-admin-gating
  "AddPairing/ListPairings/RemovePairing (§5.10-5.12): the first controller is an
admin, can add a second (regular) controller and list both, a non-admin is refused,
and removing every controller reverts the accessory to unpaired."
  (let* ((code "111-22-333")
         (acc (make-hap-accessory :setup-code code))
         (ctrl (make-hap-controller))
         (cs (run-pair-setup acc ctrl code))
         (admin-id (controller-pairing-id ctrl))
         (c2 (make-hap-controller))
         (c2-id (controller-pairing-id c2)))
    (declare (ignore cs))
    (is (hap::accessory-controller-admin-p acc admin-id))     ; setup controller is admin
    ;; admin adds a second, regular-user controller
    (let ((add (hap::dispatch-pairings acc admin-id
                (tlv8-encode (list (cons +tlv-method+ hap::+pairing-method-add+)
                                   (cons +tlv-identifier+ (hap::s->octets c2-id))
                                   (cons +tlv-public-key+ (controller-public c2))
                                   (cons +tlv-permissions+ 0))))))
      (is (= 2 (tlv8-get-integer (tlv8-decode add) +tlv-state+)))
      (is (equalp (controller-public c2) (gethash c2-id (accessory-paired-controllers acc))))
      (is (not (hap::accessory-controller-admin-p acc c2-id))))
    ;; list shows both
    (let* ((items (tlv8-decode (hap::dispatch-pairings acc admin-id
                    (tlv8-encode (list (cons +tlv-method+ hap::+pairing-method-list+))))))
           (ids (loop for i in items when (= (car i) +tlv-identifier+)
                      collect (hap::octets->string (cdr i)))))
      (is (= 2 (length ids)))
      (is (member admin-id ids :test #'string=))
      (is (member c2-id ids :test #'string=)))
    ;; a non-admin controller is refused
    (is (= hap::+tlv-error-authentication+
           (tlv8-get-integer (tlv8-decode
             (hap::dispatch-pairings acc c2-id
               (tlv8-encode (list (cons +tlv-method+ hap::+pairing-method-list+)))))
             +tlv-error+)))
    ;; remove the second controller — still paired (admin remains)
    (hap::dispatch-pairings acc admin-id
      (tlv8-encode (list (cons +tlv-method+ hap::+pairing-method-remove+)
                         (cons +tlv-identifier+ (hap::s->octets c2-id)))))
    (is (null (gethash c2-id (accessory-paired-controllers acc))))
    (is (accessory-paired acc))
    ;; remove the last (admin) controller — now unpaired
    (hap::dispatch-pairings acc admin-id
      (tlv8-encode (list (cons +tlv-method+ hap::+pairing-method-remove+)
                         (cons +tlv-identifier+ (hap::s->octets admin-id)))))
    (is (not (accessory-paired acc)))))

(test session-frames-large-payload-across-multiple-frames
  "A payload larger than one 1024-byte frame is split into several and the peer
reassembles it (the >1024B path the loopback capstone didn't reach)."
  (let* ((shared (ironclad:random-data 32))
         (a (hap::make-session-keys shared :accessory))
         (c (hap::make-session-keys shared :controller))
         (msg (hap::s->octets (make-string 5000 :initial-element #\z))))
    (let ((framed (hap::session-encrypt a msg)))
      (is (= (+ 5000 (* 5 18)) (length framed)))   ; 5 frames, each +2 len +16 tag
      (is (equalp msg (hap::session-decrypt c framed))))))

(test pairing-auto-persists-when-store-path-set
  "With a STORE-PATH set, completing Pair-Setup writes the pairing to disk, and the
reloaded accessory keeps its admin controller and continues persisting there."
  (let* ((code "111-22-333")
         (path (format nil "/tmp/hap-persist-~A.lisp" (random 1000000 (make-random-state t))))
         (acc (make-hap-accessory :setup-code code :store-path path))
         (ctrl (make-hap-controller)))
    (unwind-protect
         (progn
           (run-pair-setup acc ctrl code)                 ; M6 -> maybe-persist
           (is (probe-file path))
           (let ((back (load-accessory path)))
             (is (accessory-paired back))
             (is (equalp (controller-public ctrl)
                         (gethash (controller-pairing-id ctrl) (accessory-paired-controllers back))))
             (is (hap::accessory-controller-admin-p back (controller-pairing-id ctrl)))
             (is (string= path (accessory-store-path back)))))
      (ignore-errors (delete-file path)))))

(test session-rejects-corrupted-and-replayed-frames
  "A frame with a flipped tag byte fails authentication (NIL), and replaying a
frame fails because the receiver's counter has advanced."
  (let ((msg (hap::s->octets "sensitive")))
    ;; corrupt the last byte (inside the Poly1305 tag) -> decrypt returns NIL
    (let* ((shared (ironclad:random-data 32))
           (a (hap::make-session-keys shared :accessory))
           (c (hap::make-session-keys shared :controller))
           (bad (copy-seq (hap::session-encrypt a msg))))
      (setf (aref bad (1- (length bad))) (logxor 255 (aref bad (1- (length bad)))))
      (let ((len (logior (aref bad 0) (ash (aref bad 1) 8))))
        (is (null (hap::chacha20-poly1305-decrypt
                   (hap::hap-session-read-key c) (hap::session-nonce 0)
                   (subseq bad 0 2) (subseq bad 2 (+ 2 len)) (subseq bad (+ 2 len)))))))
    ;; a good frame decrypts once; replaying it fails (the receiver's counter has moved)
    (let* ((shared (ironclad:random-data 32))
           (a (hap::make-session-keys shared :accessory))
           (c (hap::make-session-keys shared :controller))
           (framed (hap::session-encrypt a msg)))
      (is (equalp msg (hap::session-decrypt c framed)))
      (signals error (hap::session-decrypt c framed)))))

(test dispatch-rejects-unexpected-pair-setup-state
  "An out-of-sequence Pair-Setup state is answered with an error TLV, not a crash."
  (let* ((acc (make-hap-accessory :setup-code "111-22-333"))
         (session (hap::make-pair-session :accessory acc))
         ;; State=9 is not a real Pair-Setup step
         (resp (hap::dispatch-pair-setup session
                 (tlv8-encode (list (cons +tlv-state+ 9))))))
    (is (integerp (tlv8-get-integer (tlv8-decode resp) +tlv-error+)))))
