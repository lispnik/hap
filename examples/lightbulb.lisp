;;;; examples/lightbulb.lisp — a Lisp HomeKit light bulb you can add to the Home app.
;;;;
;;;; Advertises a HAP Lightbulb accessory over `_hap._tcp` and serves the pairing
;;;; + control protocol, so an iPhone can pair with it and toggle it from the Home
;;;; app, Control Center, and Siri.  The "bulb" is virtual — flipping it just
;;;; prints its new state — but everything an accessory needs is real.
;;;;
;;;; Build a standalone binary (needed for multicast on macOS — see
;;;; scripts/build-lightbulb.sh) and run it:
;;;;
;;;;   scripts/build-lightbulb.sh
;;;;   ./hap-lightbulb                 # or:  ./hap-lightbulb "Desk Lamp" 842-19-736
;;;;
;;;; then add it on your iPhone with the setup code it prints.

(defpackage #:hap-lightbulb
  (:use #:cl)
  (:export #:run #:toplevel))

(in-package #:hap-lightbulb)

(defun banner (acc)
  (format t "~2%  ~A — a Lisp HomeKit light bulb~%" (hap:accessory-name acc))
  (format t "  advertised as _hap._tcp  ·  port ~A  ·  id ~A~2%"
          (hap:accessory-port acc) (hap:accessory-id acc))
  (format t "  On your iPhone:~%")
  (format t "    Home  →  +  →  Add Accessory  →  \"More options…\"~%")
  (format t "    pick  \"~A\",  then enter this setup code:~2%" (hap:accessory-name acc))
  (format t "        ┌─────────────────┐~%")
  (format t "        │    ~A    │~%" (hap:accessory-setup-code acc))
  (format t "        └─────────────────┘~2%")
  (format t "  (Home will warn it's an \"uncertified accessory\" — that's expected.)~%")
  (format t "  Ctrl-C to stop.~2%")
  (finish-output))

(defparameter *state-file*
  (merge-pathnames ".hap-lightbulb.state" (user-homedir-pathname))
  "Where the accessory's identity + pairings are kept, so it survives restarts.")

(defun run (&key (name "Lisp Bulb") setup-code (state-file *state-file*) (trace t))
  "Advertise and serve a Lightbulb accessory until Ctrl-C.  The accessory's
identity, setup code, and pairings persist in STATE-FILE across restarts (so you
pair once); delete that file to reset to a fresh, unpaired accessory.  When TRACE,
logs each pairing step so you can see how far a controller (e.g. an iPhone) gets."
  (when trace
    (setf hap:*hap-trace*
          (lambda (fmt &rest args)
            (format t "~&  [hap] ~?~%" fmt args) (finish-output))))
  (let ((acc (if (probe-file state-file)
                 (hap:load-accessory state-file)                     ; keep identity + pairings
                 (hap:make-hap-accessory :name name :category 5      ; 5 = lightbulb
                                         :setup-code (or setup-code (hap:random-setup-code))
                                         :port 0))))
    (setf (hap:accessory-store-path acc) state-file)                 ; auto-save on pair/unpair
    ;; the service model isn't persisted (only the identity/pairings are), so
    ;; (re)build it each run — identical each time, so the config number is stable.
    (setf (hap:accessory-services acc) '())
    (hap:ensure-accessory-information acc)
    (hap:add-lightbulb acc :name (hap:accessory-name acc)
                       :on-write (lambda (v)
                                   (format t "~&  ~A  ~A~%"
                                           (if v "💡 ON " "· OFF")
                                           (hap:accessory-name acc))
                                   (finish-output)))
    (let ((server (hap:serve-accessory acc)))
      (setf (hap:accessory-port acc) (hap:hap-server-port server))   ; advertise the bound port
      (unwind-protect
           (handler-case
               (progn
                 (hap:advertise-accessory acc)
                 (banner acc)
                 (when (plusp (hash-table-count (hap:accessory-paired-controllers acc)))
                   (format t "  (already paired with ~D controller~:P — reusing that pairing)~2%"
                           (hash-table-count (hap:accessory-paired-controllers acc)))
                   (finish-output))
                 (loop (sleep 1)))
             (sb-sys:interactive-interrupt () (format t "~&Stopping…~%")))
        (ignore-errors (hap:stop-advertising acc))
        (ignore-errors (hap:stop-accessory server))
        (ignore-errors (hap:save-accessory acc state-file))))))

(defun toplevel ()
  "Executable entry point.  Optional args: <name> <setup-code>."
  (let* ((args (rest sb-ext:*posix-argv*))
         (name (or (first args) "Lisp Bulb"))
         (code (second args)))
    (handler-case
        (if code (run :name name :setup-code code) (run :name name))
      (error (e)
        (format *error-output* "~&hap-lightbulb: ~A~%~
                                (advertising needs multicast — on macOS grant the ~
                                binary Local Network access; see doc/macos-multicast.md ~
                                in the 0conf repo)~%" e))))
  (ignore-errors (finish-output))
  (sb-ext:exit :code 0 :abort t))
