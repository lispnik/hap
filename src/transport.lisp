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

(defvar *hap-trace* nil
  "When bound to a function of (control-string &rest args), the accessory server
logs its activity through it — useful for debugging pairing with a real iPhone.")

(defun htrace (fmt &rest args)
  (when *hap-trace* (apply *hap-trace* fmt args)))

(defun trace-response (label resp)
  "Log a pairing RESPONSE, noting an error TLV if present.  Returns RESP."
  (let ((err (ignore-errors (tlv8-get-integer (tlv8-decode resp) +tlv-error+))))
    (if err
        (htrace "  ~A -> ERROR ~A" label err)
        (htrace "  ~A -> ok" label)))
  resp)

(defun dispatch-pair-setup (session body)
  "Route a /pair-setup request (by its TLV State) through the state machine."
  (let ((state (tlv8-get-integer (tlv8-decode body) +tlv-state+)))
    (htrace "pair-setup M~A (~D bytes)" state (length body))
    (trace-response
     (format nil "pair-setup M~A" (if state (1+ state) '?))
     (case state
       (1 (pair-setup-m2 session))
       (3 (pair-setup-m4 session body))
       (5 (pair-setup-m6 session body))
       (t (error-tlv (if state (1+ state) 2) +tlv-error-authentication+))))))

(defun dispatch-pair-verify (verify body)
  "Route a /pair-verify request (by its TLV State) through Pair-Verify."
  (let ((state (tlv8-get-integer (tlv8-decode body) +tlv-state+)))
    (htrace "pair-verify M~A (~D bytes)" state (length body))
    (trace-response
     (format nil "pair-verify M~A" (if state (1+ state) '?))
     (case state
       (1 (pair-verify-m2 verify body))
       (3 (pair-verify-m4 verify body))
       (t (error-tlv (if state (1+ state) 2) +tlv-error-authentication+))))))

(defun handle-connection (acc conn)
  "Serve one persistent connection.  Pair-Setup and Pair-Verify run in plaintext;
once Pair-Verify establishes a session the connection switches to the encrypted
SECURE-STREAM, over which the /accessories and /characteristics traffic flows."
  (let ((raw (socket-stream conn))
        (pair-session (make-pair-session :accessory acc))
        (verify (make-verify-session :accessory acc))
        (secure nil)
        (connection nil))                  ; a HAP-CONNECTION once the session is up
    (htrace "connection opened")
    (unwind-protect
         (loop
           (multiple-value-bind (method path body)
               (read-http-request (or secure raw))
             (when (null method) (htrace "connection closed") (return))
             (when secure (htrace "~A ~A (encrypted, ~D bytes)" method path (length body)))
             (cond
               ;; pairing traffic — plaintext, TLV8
               ((string= path "/pair-setup")
                (write-http-response raw (dispatch-pair-setup pair-session body)))
               ;; POST /identify (unpaired only) — plaintext, before any session
               ((and (string= method "POST") (eql 0 (search "/identify" path)) (not secure))
                (if (accessory-paired acc)
                    (write-reply raw (make-reply "400 Bad Request" nil nil))
                    (progn (run-identify acc) (write-reply raw (no-content)))))
               ((eql 0 (search "/pair-verify" path))
                (write-http-response raw (dispatch-pair-verify verify body))
                (when (and (verify-session-session verify) (not secure))
                  (setf secure (make-secure-stream raw (verify-session-session verify))
                        connection (make-hap-connection
                                    :stream secure
                                    :controller-id (verify-session-controller-id verify)))
                  (htrace "  encrypted session established")))
               ;; the accessory model — only over the encrypted session.  The
               ;; reply goes out under the connection lock so a concurrent
               ;; UPDATE-CHARACTERISTIC event push can't interleave with it.
               (secure
                (let ((reply (handle-accessory-request acc method path body connection)))
                  (htrace "  ~A -> ~A" path (reply-status reply))
                  (bordeaux-threads:with-lock-held ((hap-connection-lock connection))
                    (write-reply secure reply))))
               (t (write-reply raw (make-reply "470 Connection Authorization Required"
                                               nil nil))))))
      (when connection (connection-unsubscribe-all connection))
      (pair-setup-end acc pair-session)   ; free the setup slot if we held it
      (ignore-errors (sb-bsd-sockets:socket-close conn)))))

(defun accept-loop (server)
  "Accept connections until the server stops.  The listen socket is non-blocking
and polled, rather than blocking in accept(): on Linux, closing a socket does NOT
wake an accept() blocked in another thread, so a blocking accept would hang the
join in STOP-ACCESSORY (macOS/BSD wake it, which is why this only bites on Linux)."
  (let ((socket (hap-server-socket server)))
    (setf (sb-bsd-sockets:non-blocking-mode socket) t)
    (loop while (hap-server-running server)
          do (let ((conn (ignore-errors (sb-bsd-sockets:socket-accept socket))))
               (cond
                 (conn
                  ;; a BSD-accepted socket inherits non-blocking mode; force it
                  ;; back to blocking so the per-connection reads work everywhere
                  (setf (sb-bsd-sockets:non-blocking-mode conn) nil)
                  (bordeaux-threads:make-thread
                   (lambda () (ignore-errors (handle-connection (hap-server-accessory server) conn)))
                   :name "hap-conn"))
                 (t (sleep 0.02)))))))          ; nothing pending -> yield briefly

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
  ;; Clear the flag and join first: the polling accept loop exits within one poll
  ;; interval on its own, so the join never blocks.  THEN close the socket.
  (setf (hap-server-running server) nil)
  (let ((th (hap-server-thread server)))
    (when (and th (bordeaux-threads:thread-alive-p th))
      (ignore-errors (bordeaux-threads:join-thread th))))
  (ignore-errors (sb-bsd-sockets:socket-close (hap-server-socket server)))
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

(defun verify-with-accessory (controller cs host port)
  "Open a fresh connection to HOST:PORT and run Pair-Verify as CONTROLLER, using the
identity in the CONTROLLER-SESSION CS from a prior Pair-Setup.  On success returns
(values socket secure-stream): plaintext HAP requests written to the stream are
transparently ChaCha20-Poly1305-encrypted.  Caller closes the socket when done."
  (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (sb-bsd-sockets:socket-connect socket (0conf:parse-ipv4 host) port)
    (let* ((raw (socket-stream socket))
           (vc (make-verify-controller
                :controller controller
                :accessory-ltpk (controller-session-accessory-ltpk cs))))
      (flet ((exchange (tlv)
               (write-http-post raw "/pair-verify" tlv)
               (read-http-response raw)))
        (let* ((m2 (exchange (pair-verify-controller-m1 vc)))
               (m4 (exchange (pair-verify-controller-m3 vc m2))))
          (pair-verify-controller-finish vc m4)
          (unless (verify-controller-session vc)
            (ignore-errors (sb-bsd-sockets:socket-close socket))
            (error "Pair-Verify failed: accessory rejected the controller"))
          (values socket (make-secure-stream raw (verify-controller-session vc))))))))

(defun hap-get (stream path)
  "GET PATH over the (encrypted) STREAM.  Returns (values body-octets status-code)."
  (write-http-get stream path)
  (read-http-response stream))

(defun hap-put (stream path json-octets)
  "PUT JSON-OCTETS to PATH over STREAM.  Returns (values body-octets status-code)."
  (write-http-put stream path json-octets)
  (read-http-response stream))

(defun hap-subscribe (stream aid iid)
  "Subscribe to EVENT notifications for characteristic AID.IID (PUT ev:true)."
  (hap-put stream "/characteristics"
           (s->octets (format nil "{\"characteristics\":[{\"aid\":~D,\"iid\":~D,\"ev\":true}]}"
                              aid iid))))

;;; --- controller /pairings helpers (over the encrypted session) -------------

(defun hap-list-pairings (stream)
  "As an admin controller, list every controller paired to the accessory.  Returns
a list of plists (:id :ltpk :admin)."
  (write-http-post stream "/pairings"
                   (tlv8-encode (list (cons +tlv-state+ 1)
                                      (cons +tlv-method+ +pairing-method-list+))))
  (let* ((items (tlv8-decode (read-http-response stream)))
         (out '()) (current '()))
    ;; items are id/ltpk/perm groups split by Separator (0xFF)
    (dolist (item items)
      (cond
        ((= (car item) +tlv-separator+)
         (when current (push (nreverse current) out) (setf current '())))
        ((= (car item) +tlv-identifier+) (push (cons :id (octets->string (cdr item))) current))
        ((= (car item) +tlv-public-key+) (push (cons :ltpk (cdr item)) current))
        ((= (car item) +tlv-permissions+)
         (push (cons :admin (eql 1 (if (integerp (cdr item))
                                       (cdr item) (le-octets->integer (cdr item)))))
               current))))
    (when current (push (nreverse current) out))
    (mapcar (lambda (g) (list :id (cdr (assoc :id g)) :ltpk (cdr (assoc :ltpk g))
                              :admin (cdr (assoc :admin g))))
            (nreverse out))))

(defun hap-remove-pairing (stream id)
  "As an admin controller, remove the controller with pairing id ID.  Returns the
accessory's response body octets (State=2 on success)."
  (write-http-post stream "/pairings"
                   (tlv8-encode (list (cons +tlv-state+ 1)
                                      (cons +tlv-method+ +pairing-method-remove+)
                                      (cons +tlv-identifier+ (s->octets id)))))
  (read-http-response stream))

(defun hap-add-pairing (stream id ltpk &key admin)
  "As an admin controller, add controller ID with long-term public key LTPK."
  (write-http-post stream "/pairings"
                   (tlv8-encode (list (cons +tlv-state+ 1)
                                      (cons +tlv-method+ +pairing-method-add+)
                                      (cons +tlv-identifier+ (s->octets id))
                                      (cons +tlv-public-key+ ltpk)
                                      (cons +tlv-permissions+ (if admin 1 0)))))
  (read-http-response stream))

(defun read-hap-event (stream)
  "Read one pushed EVENT/1.0 (or response) message from STREAM.  Returns its parsed
characteristics as a vector of hash-tables (jzon), or NIL at EOF."
  (multiple-value-bind (body code) (read-http-response stream)
    (declare (ignore code))
    (when (and body (plusp (length body)))
      (gethash "characteristics" (com.inuoe.jzon:parse (octets->string body))))))

;;; --- controller discovery (M6): find accessories via 0conf -----------------

(defun txt->string (v)
  "TXT values arrive as strings (local) or octet vectors (off the wire)."
  (cond ((null v) nil)
        ((stringp v) v)
        (t (octets->string (coerce v '(simple-array (unsigned-byte 8) (*)))))))

(defun accessory-advertisement-info (service-info)
  "Parse the HAP TXT keys of a discovered 0conf:SERVICE-INFO into a plist
(:name :host :port :id :model :category :paired :config-number :protocol-version)."
  (flet ((txt (k) (txt->string (cdr (assoc k (0conf:service-info-txt service-info)
                                           :test #'string=)))))
    (list :name (0conf:service-info-name service-info)
          :host (0conf:service-info-host service-info)
          :port (0conf:service-info-port service-info)
          :id (txt "id")
          :model (txt "md")
          :category (let ((c (txt "ci"))) (and c (ignore-errors (parse-integer c))))
          :paired (let ((sf (txt "sf"))) (and sf (string= sf "0"))) ; sf bit0=0 -> paired
          :config-number (let ((c (txt "c#"))) (and c (ignore-errors (parse-integer c))))
          :protocol-version (txt "pv"))))

(defun discover-accessories (&key (timeout 3.0) interface)
  "Browse the LAN for `_hap._tcp` accessories via 0conf; return a list of plists
(see ACCESSORY-ADVERTISEMENT-INFO).  Needs working multicast — blocked for
unentitled SBCL on macOS here, so this runs live on entitled/Linux hosts."
  (mapcar #'accessory-advertisement-info
          (0conf:browse-once "_hap._tcp.local" :timeout timeout :interface interface)))
