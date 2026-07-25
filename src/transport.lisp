;;;; transport.lisp — TCP server (accessory) and client (controller) for HAP.
;;;;
;;;; The accessory listens on its HAP port and serves Pair-Setup over HTTP; the
;;;; controller connects and drives the same six-message exchange.  A whole
;;;; Pair-Setup runs on one persistent connection, so each connection carries its
;;;; own pairing session.

(in-package #:hap)

(defun socket-stream (socket)
  (sb-bsd-sockets:socket-make-stream socket :input t :output t
                                            :element-type '(unsigned-byte 8)))

;;; --- accessory (server) ----------------------------------------------------

(defstruct hap-server socket thread port (running t) accessory)

(defun dispatch-pair-setup (session body)
  "Route a /pair-setup request (by its TLV State) through the state machine."
  (let ((state (tlv8-get-integer (tlv8-decode body) +tlv-state+)))
    (case state
      (1 (pair-setup-m2 session))
      (3 (pair-setup-m4 session body))
      (5 (pair-setup-m6 session body))
      (t (error-tlv (if state (1+ state) 2) +tlv-error-authentication+)))))

(defun handle-connection (acc conn)
  (let ((stream (socket-stream conn))
        (session (make-pair-session :accessory acc)))
    (unwind-protect
         (loop
           (multiple-value-bind (method path body) (read-http-request stream)
             (when (null method) (return))            ; connection closed
             (let ((response
                     (cond ((and (string= method "POST") (string= path "/pair-setup"))
                            (dispatch-pair-setup session body))
                           (t (error-tlv 2 +tlv-error-authentication+)))))
               (write-http-response stream response))))
      (ignore-errors (sb-bsd-sockets:socket-close conn)))))

(defun accept-loop (server)
  (loop while (hap-server-running server)
        do (handler-case
               (let ((conn (sb-bsd-sockets:socket-accept (hap-server-socket server))))
                 (when conn
                   (bordeaux-threads:make-thread
                    (lambda () (ignore-errors (handle-connection (hap-server-accessory server) conn)))
                    :name "hap-conn")))
             (error () (return)))))          ; listen socket closed -> exit

(defun serve-accessory (acc)
  "Start a TCP server for ACC on its port (0 = ephemeral).  Returns a HAP-SERVER;
its PORT slot is the actually-bound port.  Stop it with STOP-ACCESSORY."
  (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (setf (sb-bsd-sockets:sockopt-reuse-address socket) t)
    (sb-bsd-sockets:socket-bind socket #(0 0 0 0) (accessory-port acc))
    (sb-bsd-sockets:socket-listen socket 5)
    (let ((server (make-hap-server
                   :socket socket :accessory acc
                   :port (nth-value 1 (sb-bsd-sockets:socket-name socket)))))
      (setf (hap-server-thread server)
            (bordeaux-threads:make-thread (lambda () (accept-loop server))
                                          :name "hap-accessory"))
      server)))

(defun stop-accessory (server)
  (setf (hap-server-running server) nil)
  (ignore-errors (sb-bsd-sockets:socket-close (hap-server-socket server)))
  (let ((th (hap-server-thread server)))
    (when (and th (bordeaux-threads:thread-alive-p th))
      (ignore-errors (bordeaux-threads:join-thread th))))
  server)

;;; --- controller (client) ---------------------------------------------------

(defun pair-with-accessory (controller host port setup-code)
  "Connect to a HAP accessory over TCP and complete Pair-Setup as CONTROLLER,
entering SETUP-CODE.  Returns the CONTROLLER-SESSION on success (which carries the
learned accessory identity + LTPK); signals on rejection."
  (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (sb-bsd-sockets:socket-connect socket (0conf:parse-ipv4 host) port)
    (let ((stream (socket-stream socket))
          (cs (make-controller-session :controller controller :setup-code setup-code)))
      (unwind-protect
           (flet ((exchange (tlv)
                    (write-http-post stream "/pair-setup" tlv)
                    (read-http-response stream)))
             (let* ((m2 (exchange (pair-setup-controller-m1)))
                    (m4 (exchange (pair-setup-controller-m3 cs m2)))
                    (m6 (exchange (pair-setup-controller-m5 cs m4))))
               (pair-setup-controller-finish cs m6)
               cs))
        (ignore-errors (sb-bsd-sockets:socket-close socket))))))
