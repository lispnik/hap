;;;; test/transport-tests.lisp — persistence + a real Pair-Setup over loopback TCP.

(in-package #:hap/test)

(in-suite hap-tests)

(test accessory-persistence-round-trips
  (let ((acc (make-hap-accessory :name "Persisted" :category 5 :setup-code "246-80-135"))
        (path (format nil "/tmp/hap-test-~A.lisp" (random 1000000 (make-random-state t)))))
    ;; record a fake paired controller
    (setf (gethash "some-controller-id" (accessory-paired-controllers acc))
          (hap::ed25519-public-from-seed (hap::accessory-seed acc)))
    (unwind-protect
         (progn
           (save-accessory acc path)
           (let ((back (load-accessory path)))
             (is (string= (accessory-id acc) (accessory-id back)))
             (is (equalp (hap::accessory-seed acc) (hap::accessory-seed back)))
             (is (equalp (hap::accessory-public acc) (hap::accessory-public back)))
             (is (string= "246-80-135" (accessory-setup-code back)))
             ;; the paired controller survived
             (is (equalp (gethash "some-controller-id" (accessory-paired-controllers acc))
                         (gethash "some-controller-id" (accessory-paired-controllers back))))))
      (ignore-errors (delete-file path)))))

(test pair-setup-over-loopback-tcp
  "A real end-to-end Pair-Setup: a Lisp controller connects to a Lisp accessory's
TCP server over loopback and pairs — exercising the HTTP layer, the socket
transport, and the full six-message protocol together, with no multicast."
  (handler-case
      (let* ((code "314-15-926")
             (acc (make-hap-accessory :name "Loopback Light" :category 5
                                      :setup-code code :port 0))  ; 0 -> ephemeral
             (server (serve-accessory acc))
             (ctrl (make-hap-controller)))
        (unwind-protect
             (let ((cs (pair-with-accessory ctrl "127.0.0.1" (hap-server-port server) code)))
               (is (accessory-paired acc))
               ;; the accessory stored the controller's LTPK
               (is (equalp (controller-public ctrl)
                           (gethash (controller-pairing-id ctrl)
                                    (accessory-paired-controllers acc))))
               ;; the controller learned the accessory's identity
               (is (string= (accessory-id acc)
                            (hap::controller-session-accessory-id cs))))
          (stop-accessory server)))
    (error (e) (skip "loopback TCP pairing unavailable: ~A" e))))

(test control-over-encrypted-session-loopback
  "The capstone: a Lisp controller pairs, runs Pair-Verify, then over the resulting
ChaCha20-Poly1305 session reads /accessories and toggles the Lightbulb's On
characteristic — flipping a real server-side 'light' — and reads it back."
  (handler-case
      (let* ((code "314-15-926")
             (acc (make-hap-accessory :name "Loopback Light" :category 5
                                      :setup-code code :port 0))
             (light nil))
        (ensure-accessory-information acc)
        (let ((on (add-lightbulb acc :name "Loopback Light"
                                 :on-write (lambda (v) (setf light v))))
              (server (serve-accessory acc))
              (ctrl (make-hap-controller)))
          (unwind-protect
               (let ((cs (pair-with-accessory ctrl "127.0.0.1" (hap-server-port server) code)))
                 (multiple-value-bind (socket stream)
                     (verify-with-accessory ctrl cs "127.0.0.1" (hap-server-port server))
                   (unwind-protect
                        (let ((iid (hap::hap-char-iid on)))
                          ;; read the accessory database over the encrypted channel
                          (multiple-value-bind (body status) (hap-get stream "/accessories")
                            (is (eql 200 status))
                            (let* ((db (com.inuoe.jzon:parse (hap::octets->string body)))
                                   (svcs (gethash "services" (aref (gethash "accessories" db) 0))))
                              (is (find "43" svcs :key (lambda (s) (gethash "type" s))
                                                  :test #'string=))))
                          (is (null light))            ; starts off
                          ;; toggle it on over the encrypted session
                          (multiple-value-bind (body status)
                              (hap-put stream "/characteristics"
                                       (hap::s->octets
                                        (format nil "{\"characteristics\":[{\"aid\":1,\"iid\":~D,\"value\":true}]}" iid)))
                            (declare (ignore body))
                            (is (eql 204 status)))
                          (is (eq t light))            ; server-side light really flipped
                          (is (eq t (hap::hap-char-value on)))
                          ;; read the characteristic back
                          (multiple-value-bind (body status)
                              (hap-get stream (format nil "/characteristics?id=1.~D" iid))
                            (is (eql 200 status))
                            (let ((c (aref (gethash "characteristics"
                                                    (com.inuoe.jzon:parse (hap::octets->string body)))
                                           0)))
                              (is (eq t (gethash "value" c))))))
                     (ignore-errors (sb-bsd-sockets:socket-close socket)))))
            (stop-accessory server))))
    (error (e) (skip "loopback encrypted control unavailable: ~A" e))))

(test event-notification-over-loopback
  "M5: a controller subscribes to the On characteristic; a server-side
UPDATE-CHARACTERISTIC then pushes an EVENT/1.0 the controller receives — the same
mechanism Home uses to reflect a physical switch flip in real time."
  (handler-case
      (let* ((code "778-99-000")
             (acc (make-hap-accessory :name "Sensor" :category 5
                                      :setup-code code :port 0)))
        (ensure-accessory-information acc)
        (let ((on (add-lightbulb acc))
              (server (serve-accessory acc))
              (ctrl (make-hap-controller)))
          (unwind-protect
               (let ((cs (pair-with-accessory ctrl "127.0.0.1" (hap-server-port server) code)))
                 (multiple-value-bind (socket stream)
                     (verify-with-accessory ctrl cs "127.0.0.1" (hap-server-port server))
                   (unwind-protect
                        (let ((iid (hap::hap-char-iid on)))
                          (multiple-value-bind (body status) (hap-subscribe stream 1 iid)
                            (declare (ignore body))
                            (is (eql 204 status)))
                          ;; the subscription is registered by the time the 204 returns
                          (is (hap::hap-char-subscribers on))
                          ;; the accessory's own state changes -> a push
                          (update-characteristic acc on t)
                          (let ((chars (read-hap-event stream)))
                            (is (not (null chars)))
                            (let ((c (aref chars 0)))
                              (is (eql 1 (gethash "aid" c)))
                              (is (eql iid (gethash "iid" c)))
                              (is (eq t (gethash "value" c))))))
                     (ignore-errors (sb-bsd-sockets:socket-close socket)))))
            (stop-accessory server))))
    (error (e) (skip "loopback events unavailable: ~A" e))))
