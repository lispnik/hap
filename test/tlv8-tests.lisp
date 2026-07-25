;;;; test/tlv8-tests.lisp

(in-package #:hap/test)

(def-suite hap-tests :description "HAP test suite.")
(in-suite hap-tests)

(defun run-tests ()
  "Entry point for (asdf:test-system :hap).  Signals on failure."
  ;; Silence 0conf's announce/response sleeps so advertising tests are instant.
  (let ((0conf::*announce-interval* 0)
        (0conf::*response-delay* nil))
    (unless (run! 'hap-tests)
      (error "HAP test suite failed."))))

(defun octets (&rest bytes)
  (make-array (length bytes) :element-type '(unsigned-byte 8) :initial-contents bytes))

(test integer-le-round-trips
  (is (equalp #(6) (hap::integer->le-octets 6)))
  (is (equalp #(0 1) (hap::integer->le-octets 256)))
  (is (equalp #(0) (hap::integer->le-octets 0)))
  (is (= 256 (hap::le-octets->integer (octets 0 1))))
  (is (= 0 (hap::le-octets->integer (octets 0)))))

(test tlv8-basic-round-trips
  (let* ((salt (make-array 16 :element-type '(unsigned-byte 8) :initial-element 7))
         (items (list (cons +tlv-state+ 3)
                      (cons +tlv-identifier+ "Pair-Setup")
                      (cons +tlv-salt+ salt)))
         (decoded (tlv8-decode (tlv8-encode items))))
    (is (= 3 (tlv8-get-integer decoded +tlv-state+)))
    (is (string= "Pair-Setup"
                 (sb-ext:octets-to-string (tlv8-get decoded +tlv-identifier+)
                                          :external-format :utf-8)))
    (is (equalp salt (tlv8-get decoded +tlv-salt+)))))

(test tlv8-fragmentation-round-trips
  ;; A 384-byte value (SRP-3072 public key size) must fragment (255+129) and
  ;; reassemble — this is the load-bearing TLV8 behaviour for pairing.
  (let ((big (make-array 384 :element-type '(unsigned-byte 8))))
    (dotimes (i 384) (setf (aref big i) (mod (* i 7) 256)))
    (let* ((encoded (tlv8-encode (list (cons +tlv-public-key+ big))))
           (decoded (tlv8-decode encoded)))
      (is (= (+ 2 255 2 129) (length encoded)))   ; two fragments + two headers
      (is (equalp big (tlv8-get decoded +tlv-public-key+))))))

(test tlv8-empty-value
  (let* ((empty (make-array 0 :element-type '(unsigned-byte 8)))
         (decoded (tlv8-decode (tlv8-encode (list (cons +tlv-separator+ empty))))))
    (is (not (null (assoc +tlv-separator+ decoded))))
    (is (= 0 (length (tlv8-get decoded +tlv-separator+))))))
