;;;; package.lisp

(defpackage #:hap
  (:use #:cl)
  (:export
   ;; TLV8 codec
   #:tlv8-encode #:tlv8-decode #:tlv8-get #:tlv8-get-integer
   ;; HAP TLV types (RFC-less; HAP spec Table 5-6)
   #:+tlv-method+ #:+tlv-identifier+ #:+tlv-salt+ #:+tlv-public-key+
   #:+tlv-proof+ #:+tlv-encrypted-data+ #:+tlv-state+ #:+tlv-error+
   #:+tlv-retry-delay+ #:+tlv-certificate+ #:+tlv-signature+
   #:+tlv-permissions+ #:+tlv-fragment-data+ #:+tlv-fragment-last+
   #:+tlv-flags+ #:+tlv-separator+
   ;; discovery / accessory
   #:accessory #:make-hap-accessory
   #:accessory-id #:accessory-name #:accessory-model #:accessory-category
   #:accessory-config-number #:accessory-state-number
   #:accessory-setup-code #:accessory-setup-id #:accessory-port #:accessory-paired
   #:accessory-txt #:advertise-accessory #:update-accessory-advertisement
   #:stop-advertising #:accessory-paired #:accessory-paired-controllers
   ;; pairing (controller role)
   #:controller #:make-hap-controller #:controller-pairing-id #:controller-public))
