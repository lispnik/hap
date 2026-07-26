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
   #:accessory-paired-permissions #:accessory-aid #:accessory-services
   #:accessory-on-identify #:accessory-store-path #:random-setup-code
   ;; accessory model (services / characteristics)
   #:hap-service #:make-hap-service #:hap-service-iid #:hap-service-type
   #:hap-service-characteristics
   #:hap-char #:make-hap-char #:hap-char-iid #:hap-char-type #:hap-char-value
   #:hap-char-perms #:hap-char-format #:hap-char-on-write
   #:hap-char-min-value #:hap-char-max-value #:hap-char-min-step
   #:hap-char-unit #:hap-char-valid-values
   #:accessory-information-service #:protocol-information-service
   #:ensure-accessory-information
   #:add-lightbulb #:add-switch #:add-outlet #:add-temperature-sensor
   #:add-humidity-sensor #:add-contact-sensor #:add-motion-sensor
   #:define-accessory #:add-bridged-accessory #:accessory-database #:accessory-bridged
   #:find-characteristic #:db-find-characteristic
   #:update-characteristic #:note-database-change #:run-identify
   ;; events (server push)
   #:hap-connection #:subscribe-characteristic #:unsubscribe-characteristic
   ;; pairing (controller role)
   #:controller #:make-hap-controller #:controller-pairing-id #:controller-public
   ;; persistence + transport
   #:save-accessory #:load-accessory
   #:serve-accessory #:stop-accessory #:hap-server #:hap-server-port
   #:pair-with-accessory #:verify-with-accessory #:hap-get #:hap-put
   #:hap-subscribe #:read-hap-event
   #:hap-list-pairings #:hap-add-pairing #:hap-remove-pairing
   ;; controller discovery (M6)
   #:discover-accessories #:accessory-advertisement-info))
