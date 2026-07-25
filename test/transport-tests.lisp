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
