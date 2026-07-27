;;;; hap.asd — HomeKit Accessory Protocol (HAP) in Common Lisp.
;;;; Discovery is delegated to 0conf; everything else (TLV8, crypto, pairing,
;;;; sessions, the accessory model) lives here.  SBCL only.

(defsystem "hap"
  :description "HomeKit Accessory Protocol (HAP R2) — accessory + controller, pure CL on 0conf."
  :author "Matthew Kennedy"
  :license "MIT"
  :version "0.0.1"
  :depends-on ("0conf" "ironclad" "alexandria" "nibbles" "bordeaux-threads"
               "com.inuoe.jzon")
  :serial t
  :pathname "src"
  :components ((:file "package")
               (:file "tlv8")
               (:file "crypto")
               (:file "discovery")
               (:file "srp")
               (:file "store")
               (:file "pairing")
               (:file "secure")
               (:file "http")
               (:file "model")
               (:file "transport"))
  :in-order-to ((test-op (test-op "hap/test"))))

(defsystem "hap/lightbulb"
  :description "Example: a HomeKit Lightbulb accessory you can add to the Home app."
  :author "Matthew Kennedy"
  :license "MIT"
  :depends-on ("hap")
  :pathname "examples"
  :components ((:file "lightbulb"))
  :build-operation "program-op"
  :build-pathname "../hap-lightbulb"
  :entry-point "hap-lightbulb:toplevel")

(defsystem "hap/test"
  :description "FiveAM tests for HAP."
  :depends-on ("hap" "fiveam")
  :serial t
  :pathname "test"
  :components ((:file "package")
               (:file "tlv8-tests")
               (:file "crypto-tests")
               (:file "discovery-tests")
               (:file "srp-tests")
               (:file "pairing-tests")
               (:file "secure-tests")
               (:file "model-tests")
               (:file "transport-tests"))
  :perform (test-op (o c)
             (uiop:symbol-call :hap/test '#:run-tests)))
