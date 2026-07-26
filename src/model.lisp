;;;; model.lisp — the HAP accessory object model + the /accessories and
;;;; /characteristics endpoints (served over the encrypted session, M4).
;;;;
;;;; An accessory exposes a list of SERVICES, each a list of CHARACTERISTICS.
;;;; A characteristic is addressed by (aid . iid) — accessory id and instance
;;;; id.  /accessories returns the whole database as HAP JSON; /characteristics
;;;; reads (GET ?id=aid.iid,…) and writes (PUT {"characteristics":[…]}) values.

(in-package #:hap)

;;; --- the model ------------------------------------------------------------

(defstruct hap-char
  iid                       ; instance id (unique within the accessory)
  type                      ; characteristic UUID, short HAP form e.g. "25" (On)
  (value nil)               ; current value (bool t/nil, string, or number)
  (perms '("pr"))           ; permissions: "pr" read, "pw" write, "ev" events
  (format "bool")           ; HAP format: bool / string / int / uint8 / float …
  (min-value nil)           ; numeric metadata — emitted in /accessories when set
  (max-value nil)
  (min-step nil)
  (unit nil)                ; e.g. "percentage", "celsius", "arcdegrees"
  (valid-values nil)        ; a list of the allowed enum values
  (on-write nil)            ; optional (lambda (value) …) called on a PUT
  (subscribers '()))        ; HAP-CONNECTIONs subscribed to EVENT notifications

(defstruct hap-service
  iid                       ; instance id
  type                      ; service UUID, short HAP form e.g. "43" (Lightbulb)
  (characteristics '()))

(defstruct hap-connection
  "One verified, encrypted controller connection (used for event delivery and the
admin check on /pairings)."
  stream                                   ; the encrypted SECURE-STREAM
  controller-id                            ; pairing id of the verified controller
  (lock (bordeaux-threads:make-lock "hap-conn"))
  (subscribed '()))                        ; HAP-CHARs this connection watches

;;; Standard short UUIDs (HAP spec §8/§9).
(defparameter +svc-accessory-information+ "3E")
(defparameter +svc-protocol-information+ "A2")
(defparameter +svc-lightbulb+ "43")
(defparameter +svc-switch+    "49")
(defparameter +svc-outlet+    "47")
(defparameter +svc-temperature-sensor+ "8A")
(defparameter +svc-humidity-sensor+    "82")
(defparameter +svc-contact-sensor+     "80")
(defparameter +svc-motion-sensor+      "85")
(defparameter +char-identify+ "14")
(defparameter +char-manufacturer+ "20")
(defparameter +char-model+    "21")
(defparameter +char-name+     "23")
(defparameter +char-serial+   "30")
(defparameter +char-firmware+ "52")
(defparameter +char-version+  "37")
(defparameter +char-on+       "25")
(defparameter +char-outlet-in-use+ "26")
(defparameter +char-current-temperature+ "11")
(defparameter +char-current-humidity+    "10")
(defparameter +char-contact-state+       "6A")
(defparameter +char-motion-detected+     "22")

(defun accessory-information-service (acc &key (iid 1))
  "The mandatory Accessory Information service (HAP §8.1)."
  (make-hap-service
   :iid iid :type +svc-accessory-information+
   :characteristics
   (list (make-hap-char :iid (+ iid 1) :type +char-identify+ :perms '("pw") :format "bool")
         (make-hap-char :iid (+ iid 2) :type +char-manufacturer+ :value "cl-hap" :perms '("pr") :format "string")
         (make-hap-char :iid (+ iid 3) :type +char-model+ :value (accessory-model acc) :perms '("pr") :format "string")
         (make-hap-char :iid (+ iid 4) :type +char-name+ :value (accessory-name acc) :perms '("pr") :format "string")
         (make-hap-char :iid (+ iid 5) :type +char-serial+ :value (accessory-id acc) :perms '("pr") :format "string")
         (make-hap-char :iid (+ iid 6) :type +char-firmware+ :value "1.0" :perms '("pr") :format "string"))))

(defun note-database-change (acc)
  "Call after the accessory database changes.  While the accessory is advertising,
bump the config number (c#) and re-publish so controllers know to re-read
/accessories (HAP §6.4).  Before advertising it is a no-op, so building the model
at startup doesn't inflate c#."
  (when (accessory-responder acc)
    (incf (accessory-config-number acc))
    (update-accessory-advertisement acc)
    (maybe-persist acc))
  acc)

(defun alloc-iids (acc)
  "Reserve the next block of instance ids for a service, returning its base iid."
  (prog1 (accessory-iid-counter acc)
    (incf (accessory-iid-counter acc) 10)))

(defun %add-service (acc svc-type name primary-char &key extra-chars)
  "Append a service of SVC-TYPE (with a Name characteristic) whose first
characteristic is PRIMARY-CHAR, and return PRIMARY-CHAR.  Instance ids are
allocated automatically.  PRIMARY-CHAR and EXTRA-CHARS are HAP-CHARs whose iid
slots this fills in from the allocated block."
  (let* ((base (alloc-iids acc))
         (chars (append (list primary-char) extra-chars))
         (name-char (make-hap-char :type +char-name+ :value name
                                   :perms '("pr") :format "string")))
    ;; assign iids: base = service, base+1.. = characteristics
    (loop for c in (append chars (list name-char))
          for i from 1
          do (setf (hap-char-iid c) (+ base i)))
    (setf (accessory-services acc)
          (append (accessory-services acc)
                  (list (make-hap-service :iid base :type svc-type
                                          :characteristics (append chars (list name-char))))))
    (note-database-change acc)
    primary-char))

(defun add-lightbulb (acc &key (name "Lisp Light") on-write)
  "Give ACC a Lightbulb service (an On characteristic).  Returns the On HAP-CHAR."
  (%add-service acc +svc-lightbulb+ name
                (make-hap-char :type +char-on+ :value nil
                               :perms '("pr" "pw" "ev") :format "bool" :on-write on-write)))

(defun add-switch (acc &key (name "Lisp Switch") on-write)
  "Give ACC a Switch service (an On characteristic).  Returns the On HAP-CHAR."
  (%add-service acc +svc-switch+ name
                (make-hap-char :type +char-on+ :value nil
                               :perms '("pr" "pw" "ev") :format "bool" :on-write on-write)))

(defun add-outlet (acc &key (name "Lisp Outlet") on-write)
  "Give ACC an Outlet service (On + read-only OutletInUse).  Returns the On char."
  (%add-service acc +svc-outlet+ name
                (make-hap-char :type +char-on+ :value nil
                               :perms '("pr" "pw" "ev") :format "bool" :on-write on-write)
                :extra-chars (list (make-hap-char :type +char-outlet-in-use+ :value nil
                                                  :perms '("pr" "ev") :format "bool"))))

(defun add-temperature-sensor (acc &key (name "Lisp Temperature"))
  "Give ACC a Temperature Sensor service.  Returns the CurrentTemperature char
(0–100 °C); update it with UPDATE-CHARACTERISTIC as readings change."
  (%add-service acc +svc-temperature-sensor+ name
                (make-hap-char :type +char-current-temperature+ :value 0.0
                               :perms '("pr" "ev") :format "float"
                               :min-value 0.0 :max-value 100.0 :min-step 0.1 :unit "celsius")))

(defun add-humidity-sensor (acc &key (name "Lisp Humidity"))
  "Give ACC a Humidity Sensor service.  Returns the CurrentRelativeHumidity char."
  (%add-service acc +svc-humidity-sensor+ name
                (make-hap-char :type +char-current-humidity+ :value 0.0
                               :perms '("pr" "ev") :format "float"
                               :min-value 0.0 :max-value 100.0 :min-step 1.0 :unit "percentage")))

(defun add-contact-sensor (acc &key (name "Lisp Contact"))
  "Give ACC a Contact Sensor service.  Returns the ContactSensorState char
(0 = contact detected, 1 = not detected)."
  (%add-service acc +svc-contact-sensor+ name
                (make-hap-char :type +char-contact-state+ :value 0
                               :perms '("pr" "ev") :format "uint8"
                               :min-value 0 :max-value 1 :min-step 1 :valid-values '(0 1))))

(defun add-motion-sensor (acc &key (name "Lisp Motion"))
  "Give ACC a Motion Sensor service.  Returns the MotionDetected char."
  (%add-service acc +svc-motion-sensor+ name
                (make-hap-char :type +char-motion-detected+ :value nil
                               :perms '("pr" "ev") :format "bool")))

(defun protocol-information-service (&key (iid 1000))
  "The HAP Protocol Information service (§8.15): a Version characteristic
advertising the HAP version the accessory speaks."
  (make-hap-service
   :iid iid :type +svc-protocol-information+
   :characteristics
   (list (make-hap-char :iid (+ iid 1) :type +char-version+ :value "1.1.0"
                        :perms '("pr") :format "string"))))

(defun ensure-accessory-information (acc)
  "Make sure ACC has the two mandatory services — Accessory Information (first)
and Protocol Information."
  (unless (find +svc-protocol-information+ (accessory-services acc)
                :key #'hap-service-type :test #'string=)
    (push (protocol-information-service) (accessory-services acc)))
  (unless (find +svc-accessory-information+ (accessory-services acc)
                :key #'hap-service-type :test #'string=)
    (push (accessory-information-service acc) (accessory-services acc)))
  acc)

;;; --- bridges: several accessories behind one connection (HAP §2.5) ---------

(defun accessory-database (root)
  "The full list of accessories ROOT exposes: itself first (aid 1), then any
bridged children.  This is what /accessories enumerates."
  (cons root (accessory-bridged root)))

(defun add-bridged-accessory (bridge child)
  "Expose CHILD through BRIDGE, assigning it the next aid.  CHILD gets the mandatory
services if it lacks them.  Returns CHILD."
  (ensure-accessory-information child)
  (setf (accessory-aid child)
        (+ 2 (length (accessory-bridged bridge))))     ; 1 is the bridge itself
  (setf (accessory-bridged bridge)
        (append (accessory-bridged bridge) (list child)))
  (note-database-change bridge)
  child)

;;; --- declarative construction ----------------------------------------------

(defparameter *service-builders*
  '((:lightbulb . add-lightbulb) (:switch . add-switch) (:outlet . add-outlet)
    (:temperature-sensor . add-temperature-sensor) (:humidity-sensor . add-humidity-sensor)
    (:contact-sensor . add-contact-sensor) (:motion-sensor . add-motion-sensor))
  "Maps a DEFINE-ACCESSORY service keyword to its add-* builder.")

(defmacro define-accessory ((&rest accessory-args) &body service-forms)
  "Build and return an accessory declaratively.  ACCESSORY-ARGS go to
MAKE-HAP-ACCESSORY; each SERVICE-FORM is (:keyword . args) naming a builder in
*SERVICE-BUILDERS*, e.g.

  (define-accessory (:name \"Desk\" :category 5)
    (:lightbulb :name \"Lamp\")
    (:switch :name \"Fan\"))"
  (let ((acc (gensym "ACC")))
    `(let ((,acc (make-hap-accessory ,@accessory-args)))
       (ensure-accessory-information ,acc)
       ,@(loop for form in service-forms
               for builder = (cdr (assoc (car form) *service-builders*))
               do (unless builder
                    (error "define-accessory: unknown service ~S" (car form)))
               collect `(,builder ,acc ,@(cdr form)))
       ,acc)))

;;; --- characteristic lookup -------------------------------------------------

(defun find-characteristic (acc iid)
  "The HAP-CHAR with instance id IID in ACC, or NIL."
  (dolist (svc (accessory-services acc))
    (let ((c (find iid (hap-service-characteristics svc) :key #'hap-char-iid)))
      (when c (return-from find-characteristic c))))
  nil)

(defun char-readable-p (c) (member "pr" (hap-char-perms c) :test #'string=))
(defun char-writable-p (c) (member "pw" (hap-char-perms c) :test #'string=))

;;; --- JSON views ------------------------------------------------------------
;;;
;;; jzon maps hash-tables -> objects, vectors -> arrays, T/NIL -> true/false,
;;; 'NULL -> null.  We build the HAP structures out of those.

(defun %obj (&rest kv)
  (let ((h (make-hash-table :test 'equal)))
    (loop for (k v) on kv by #'cddr do (setf (gethash k h) v))
    h))

(defun char->json (c)
  (let ((h (%obj "iid" (hap-char-iid c)
                 "type" (hap-char-type c)
                 "perms" (coerce (hap-char-perms c) 'vector)
                 "format" (hap-char-format c))))
    (when (char-readable-p c)
      (setf (gethash "value" h) (hap-char-value c)))   ; NIL -> false, for bool
    ;; numeric/enum metadata — controllers need these for non-bool characteristics
    (when (hap-char-min-value c) (setf (gethash "minValue" h) (hap-char-min-value c)))
    (when (hap-char-max-value c) (setf (gethash "maxValue" h) (hap-char-max-value c)))
    (when (hap-char-min-step c)  (setf (gethash "minStep" h)  (hap-char-min-step c)))
    (when (hap-char-unit c)      (setf (gethash "unit" h)     (hap-char-unit c)))
    (when (hap-char-valid-values c)
      (setf (gethash "valid-values" h) (coerce (hap-char-valid-values c) 'vector)))
    h))

(defun service->json (svc)
  (%obj "iid" (hap-service-iid svc)
        "type" (hap-service-type svc)
        "characteristics" (map 'vector #'char->json (hap-service-characteristics svc))))

(defun accessory->json (a)
  (%obj "aid" (accessory-aid a)
        "services" (map 'vector #'service->json (accessory-services a))))

(defun accessories-json (acc)
  "The full /accessories database (the accessory and any bridged children) as
HAP+JSON octets."
  (s->octets
   (com.inuoe.jzon:stringify
    (%obj "accessories" (map 'vector #'accessory->json (accessory-database acc))))))

;;; --- endpoint handlers (called with the *decrypted* request) --------------

(defun parse-id-query (path)
  "Parse the aid.iid pairs from a /characteristics?id=1.9,1.10 query.
Returns a list of (aid . iid)."
  (let ((q (position #\? path)))
    (when q
      (let* ((query (subseq path (1+ q)))
             (id (loop for kv in (uiop:split-string query :separator '(#\&))
                       for eq = (position #\= kv)
                       when (and eq (string= "id" (subseq kv 0 eq)))
                         return (subseq kv (1+ eq)))))
        (when id
          (loop for pair in (uiop:split-string id :separator '(#\,))
                for dot = (position #\. pair)
                when dot
                  collect (cons (parse-integer pair :end dot)
                                (parse-integer pair :start (1+ dot)))))))))

(defun db-find-characteristic (root aid iid)
  "Find characteristic AID.IID anywhere in ROOT's accessory database."
  (let ((a (find aid (accessory-database root) :key #'accessory-aid)))
    (and a (find-characteristic a iid))))

(defun handle-get-characteristics (acc path)
  "GET /characteristics?id=… → 200 hap+json with the requested values."
  (let ((results
          (loop for (aid . iid) in (parse-id-query path)
                for c = (db-find-characteristic acc aid iid)
                collect (if (and c (char-readable-p c))
                            (%obj "aid" aid "iid" iid "value" (hap-char-value c))
                            (%obj "aid" aid "iid" iid "status" -70402))))) ; unable to read
    (json-reply (s->octets
                 (com.inuoe.jzon:stringify
                  (%obj "characteristics" (coerce results 'vector)))))))

(defun char-notifies-p (c) (member "ev" (hap-char-perms c) :test #'string=))

(defun handle-put-characteristics (acc body &optional connection)
  "PUT /characteristics — apply each {aid,iid,value} write and each {aid,iid,ev}
event subscription/unsubscription (needs CONNECTION).  204 on full success, 400 on
a malformed body."
  (let ((req (handler-case (com.inuoe.jzon:parse (octets->string body))
               (error () (return-from handle-put-characteristics
                           (make-reply "400 Bad Request" nil nil))))))
   (let ((chars (and (hash-table-p req) (gethash "characteristics" req)))
         (ok t))
    (unless (and chars (vectorp chars))
      (return-from handle-put-characteristics (make-reply "400 Bad Request" nil nil)))
    (loop for entry across chars
          for aid = (gethash "aid" entry)
          for iid = (gethash "iid" entry)
          for has-value = (nth-value 1 (gethash "value" entry))
          for has-ev = (nth-value 1 (gethash "ev" entry))
          for c = (db-find-characteristic acc aid iid)
          do (cond
               ((and c (char-writable-p c) has-value)
                (let ((v (gethash "value" entry)))
                  (setf (hap-char-value c) v)
                  (when (hap-char-on-write c)
                    (ignore-errors (funcall (hap-char-on-write c) v)))))
               ((and has-value (not (and c (char-writable-p c)))) (setf ok nil)))
             ;; an entry may also (or instead) toggle event notifications
             (when (and has-ev connection c (char-notifies-p c))
               (if (gethash "ev" entry)
                   (subscribe-characteristic connection c)
                   (unsubscribe-characteristic connection c))))
    (if ok
        (no-content)
        (json-reply (s->octets "{\"status\":-70404}") "207 Multi-Status")))))

(defun run-identify (acc)
  "Run the accessory's identify routine (blink an LED, etc.), if it has one."
  (when (accessory-on-identify acc)
    (ignore-errors (funcall (accessory-on-identify acc))))
  acc)

(defun handle-accessory-request (acc method path body &optional connection)
  "Dispatch a decrypted request to the accessory model.  Returns a REPLY."
  (cond
    ((and (string= method "GET") (eql 0 (search "/accessories" path)))
     (json-reply (accessories-json acc)))
    ((and (string= method "GET") (eql 0 (search "/characteristics" path)))
     (handle-get-characteristics acc path))
    ((and (string= method "PUT") (eql 0 (search "/characteristics" path)))
     (handle-put-characteristics acc body connection))
    ;; /pairings is TLV8 over the session; only an admin controller may use it
    ((and (string= method "POST") (eql 0 (search "/pairings" path)))
     (tlv-reply (dispatch-pairings acc (and connection (hap-connection-controller-id connection)) body)))
    ;; a paired controller identifying via POST /identify is refused here — once
    ;; paired, identify is the Identify *characteristic*, not this endpoint
    ((and (string= method "POST") (eql 0 (search "/identify" path)))
     (make-reply "400 Bad Request" nil nil))
    (t (make-reply "404 Not Found" nil nil))))

;;; --- events (M5): per-connection subscriptions + server push (HAP §6.8) -----
;;;
;;; A controller subscribes with PUT {"aid","iid","ev":true}; when the value
;;; later changes the accessory pushes an EVENT/1.0 message — an HTTP-shaped
;;; frame with an EVENT/1.0 status line — down the same encrypted connection.

(defvar *subscription-lock* (bordeaux-threads:make-lock "hap-subscriptions")
  "Guards the char<->connection subscription lists (touched by the connection
thread on PUT and by whatever thread calls UPDATE-CHARACTERISTIC).")

(defun subscribe-characteristic (conn char)
  (bordeaux-threads:with-lock-held (*subscription-lock*)
    (pushnew conn (hap-char-subscribers char))
    (pushnew char (hap-connection-subscribed conn))))

(defun unsubscribe-characteristic (conn char)
  (bordeaux-threads:with-lock-held (*subscription-lock*)
    (setf (hap-char-subscribers char) (remove conn (hap-char-subscribers char)))
    (setf (hap-connection-subscribed conn) (remove char (hap-connection-subscribed conn)))))

(defun connection-unsubscribe-all (conn)
  "Drop every subscription held by CONN (called when its connection closes)."
  (bordeaux-threads:with-lock-held (*subscription-lock*)
    (dolist (char (hap-connection-subscribed conn))
      (setf (hap-char-subscribers char) (remove conn (hap-char-subscribers char))))
    (setf (hap-connection-subscribed conn) '())))

(defun event-octets (acc chars)
  (s->octets
   (com.inuoe.jzon:stringify
    (%obj "characteristics"
          (map 'vector (lambda (c) (%obj "aid" (accessory-aid acc)
                                         "iid" (hap-char-iid c)
                                         "value" (hap-char-value c)))
               chars)))))

(defun write-event (conn acc chars)
  "Push an EVENT/1.0 notification carrying CHARS' current values to CONN, under
the connection's write lock so it can't interleave with a response."
  (let ((body (event-octets acc chars))
        (stream (hap-connection-stream conn)))
    (bordeaux-threads:with-lock-held ((hap-connection-lock conn))
      (write-sequence
       (s->octets (format nil "EVENT/1.0 200 OK~C~CContent-Type: application/hap+json~C~C~
                               Content-Length: ~D~C~C~C~C"
                          #\Return #\Newline #\Return #\Newline
                          (length body) #\Return #\Newline #\Return #\Newline))
       stream)
      (write-sequence body stream)
      (finish-output stream))))

(defun update-characteristic (acc char value)
  "Set CHAR's value and push an EVENT to every subscribed connection.  This is the
server-side API a real accessory calls when its own state changes (a sensor
reading, a physical switch, a timer)."
  (setf (hap-char-value char) value)
  (dolist (conn (bordeaux-threads:with-lock-held (*subscription-lock*)
                  (copy-list (hap-char-subscribers char))))
    (ignore-errors (write-event conn acc (list char)))))
