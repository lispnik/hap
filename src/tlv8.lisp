;;;; tlv8.lisp — HomeKit TLV8 encoding (HAP spec §14.1 / Table 5-6).
;;;;
;;;; Each item is a 1-byte type, a 1-byte length (0–255), then that many value
;;;; bytes.  A value longer than 255 bytes is split into consecutive items of the
;;;; SAME type where every fragment except the last is exactly 255 bytes; the
;;;; decoder reassembles them.  This fragmentation is essential — SRP public keys
;;;; and proofs for the 3072-bit group are 384 bytes.
;;;;
;;;; We reuse 0conf's exported octet read/write cursor rather than reinventing it.

(in-package #:hap)

;;; HAP TLV item types.
(defconstant +tlv-method+         #x00)
(defconstant +tlv-identifier+     #x01)
(defconstant +tlv-salt+           #x02)
(defconstant +tlv-public-key+     #x03)
(defconstant +tlv-proof+          #x04)
(defconstant +tlv-encrypted-data+ #x05)
(defconstant +tlv-state+          #x06)
(defconstant +tlv-error+          #x07)
(defconstant +tlv-retry-delay+    #x08)
(defconstant +tlv-certificate+    #x09)
(defconstant +tlv-signature+      #x0a)
(defconstant +tlv-permissions+    #x0b)
(defconstant +tlv-fragment-data+  #x0c)
(defconstant +tlv-fragment-last+  #x0d)
(defconstant +tlv-flags+          #x13)
(defconstant +tlv-separator+      #xff)

(defun integer->le-octets (n)
  "Little-endian minimal-length octets for a non-negative integer (>=1 byte)."
  (let ((bytes (loop for x = n then (ash x -8)
                     while (plusp x) collect (logand x #xff))))
    (coerce (or bytes '(0)) '(vector (unsigned-byte 8)))))

(defun le-octets->integer (octets)
  "Interpret OCTETS as a little-endian unsigned integer."
  (loop for b across octets for shift from 0 by 8
        sum (ash b shift)))

(defun tlv8-value->octets (value)
  "Coerce a TLV value (octet vector, string, or integer) to octets."
  (etypecase value
    ((vector (unsigned-byte 8)) value)
    (string (sb-ext:string-to-octets value :external-format :utf-8))
    (integer (integer->le-octets value))))

(defun tlv8-encode (items)
  "Encode ITEMS — a list of (TYPE . VALUE), VALUE an octet vector / string /
integer — into a TLV8 octet vector, fragmenting values longer than 255 bytes."
  (let ((w (0conf:make-writer)))
    (dolist (item items)
      (destructuring-bind (type . value) item
        (let* ((bytes (tlv8-value->octets value))
               (n (length bytes)))
          (if (zerop n)
              (progn (0conf:write-u8 w type) (0conf:write-u8 w 0))
              (loop for i from 0 below n by 255
                    for chunk = (min 255 (- n i))
                    do (0conf:write-u8 w type)
                       (0conf:write-u8 w chunk)
                       (0conf:write-octets w (subseq bytes i (+ i chunk))))))))
    (0conf:writer-result w)))

(defun tlv8-decode (octets)
  "Decode a TLV8 octet vector into an ordered list of (TYPE . octet-vector),
reassembling fragmented values (consecutive same-type items whose non-final
fragments are exactly 255 bytes)."
  (let* ((bytes (coerce octets '(simple-array (unsigned-byte 8) (*))))
         (r (0conf:make-reader bytes))
         (end (length bytes))
         (items '())
         (last-len nil))
    (loop while (< (0conf:reader-pos r) end)
          do (let* ((type (0conf:read-u8 r))
                    (len (0conf:read-u8 r))
                    (val (0conf:read-octets r len)))
               (if (and items (= (car (first items)) type) (eql last-len 255))
                   ;; continuation fragment of the item we're building
                   (setf (cdr (first items))
                         (concatenate '(vector (unsigned-byte 8))
                                      (cdr (first items)) val))
                   (push (cons type (coerce val '(vector (unsigned-byte 8)))) items))
               (setf last-len len)))
    (nreverse items)))

(defun tlv8-get (items type)
  "The octet-vector value for TYPE in a decoded TLV list, or NIL."
  (cdr (assoc type items)))

(defun tlv8-get-integer (items type)
  "The little-endian integer value for TYPE, or NIL."
  (let ((v (tlv8-get items type)))
    (when v (le-octets->integer v))))
