;;;; test/model-tests.lisp — the accessory model and its JSON views.

(in-package #:hap/test)

(in-suite hap-tests)

(defun json-parse (octets)
  (com.inuoe.jzon:parse (hap::octets->string octets)))

(test accessories-json-has-mandatory-shape
  "The /accessories view is a well-formed HAP database with the Accessory
Information service and the Lightbulb we added."
  (let* ((acc (make-hap-accessory :name "Test Light" :category 5)))
    (ensure-accessory-information acc)
    (let ((on (add-lightbulb acc :name "Test Light")))
      (is (string= "25" (hap::hap-char-type on)))
      (let* ((db (json-parse (hap::accessories-json acc)))
             (accs (gethash "accessories" db))
             (a0 (aref accs 0))
             (svcs (gethash "services" a0))
             (types (map 'list (lambda (s) (gethash "type" s)) svcs)))
        (is (eql 1 (gethash "aid" a0)))
        (is (member "3E" types :test #'string=))    ; Accessory Information
        (is (member "43" types :test #'string=))    ; Lightbulb
        ;; the On characteristic serializes value:false, format bool, pr/pw/ev
        (let* ((light (find "43" svcs :key (lambda (s) (gethash "type" s)) :test #'string=))
               (onc (find "25" (gethash "characteristics" light)
                          :key (lambda (c) (gethash "type" c)) :test #'string=)))
          (is (eq nil (gethash "value" onc)))       ; JSON false <-> NIL
          (is (string= "bool" (gethash "format" onc)))
          (is (equalp #("pr" "pw" "ev") (gethash "perms" onc))))))))

(test put-then-get-characteristic-round-trips
  "A PUT that flips the On characteristic changes the value and fires on-write;
a subsequent GET reports the new value."
  (let* ((acc (make-hap-accessory :category 5))
         (fired nil))
    (ensure-accessory-information acc)
    (let ((on (add-lightbulb acc :on-write (lambda (v) (setf fired v)))))
      (let ((iid (hap::hap-char-iid on)))
        ;; PUT value:true
        (let ((reply (hap::handle-put-characteristics
                      acc (hap::s->octets
                           (format nil "{\"characteristics\":[{\"aid\":1,\"iid\":~D,\"value\":true}]}" iid)))))
          (is (string= "204 No Content" (hap::reply-status reply)))
          (is (eq t (hap::hap-char-value on)))
          (is (eq t fired)))
        ;; GET it back
        (let* ((reply (hap::handle-get-characteristics
                       acc (format nil "/characteristics?id=1.~D" iid)))
               (parsed (json-parse (hap::reply-body reply)))
               (c (aref (gethash "characteristics" parsed) 0)))
          (is (eql 1 (gethash "aid" c)))
          (is (eql iid (gethash "iid" c)))
          (is (eq t (gethash "value" c))))))))

(test put-to-read-only-characteristic-fails
  "Writing a read-only characteristic (Model) is rejected."
  (let ((acc (make-hap-accessory)))
    (ensure-accessory-information acc)
    ;; Model characteristic (type 21) is pr-only; iid 4 in the info service.
    (let* ((model (find-characteristic acc 4))
           (reply (hap::handle-put-characteristics
                   acc (hap::s->octets
                        "{\"characteristics\":[{\"aid\":1,\"iid\":4,\"value\":\"hacked\"}]}"))))
      (is (not (string= "204 No Content" (hap::reply-status reply))))
      (is (string= "cl-hap" (hap::hap-char-value model))))))  ; unchanged
