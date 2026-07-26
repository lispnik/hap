;;;; store.lisp — persist the accessory identity and its pairings across restarts.
;;;;
;;;; Written as a readable Lisp plist with hex-encoded keys.  An accessory MUST
;;;; keep the same Ed25519 identity and its paired controllers' public keys, or
;;;; every controller would have to re-pair after a restart.

(in-package #:hap)

(defun %hex (bytes) (ironclad:byte-array-to-hex-string bytes))
(defun %unhex (s) (ironclad:hex-string-to-byte-array s))

(defun maybe-persist (acc)
  "If ACC has a STORE-PATH, re-save it (called after pair/unpair changes).  Errors
are swallowed — a persistence failure must not break the live protocol."
  (when (accessory-store-path acc)
    (ignore-errors (save-accessory acc (accessory-store-path acc))))
  acc)

(defun save-accessory (acc path)
  "Persist ACC (identity, config, and paired controllers) to PATH."
  (with-open-file (out path :direction :output :if-exists :supersede
                            :if-does-not-exist :create)
    (with-standard-io-syntax
      (prin1 (list :id (accessory-id acc)
                   :name (accessory-name acc)
                   :model (accessory-model acc)
                   :category (accessory-category acc)
                   :config (accessory-config-number acc)
                   :state (accessory-state-number acc)
                   :setup-code (accessory-setup-code acc)
                   :setup-id (accessory-setup-id acc)
                   :port (accessory-port acc)
                   :seed (%hex (accessory-seed acc))
                   :public (%hex (accessory-public acc))
                   :controllers (loop for id being the hash-keys
                                        of (accessory-paired-controllers acc)
                                          using (hash-value ltpk)
                                      collect (list id (%hex ltpk)
                                                    (and (gethash id (accessory-paired-permissions acc)) t))))
             out)))
  acc)

(defun load-accessory (path)
  "Reconstruct an accessory saved with SAVE-ACCESSORY."
  (let ((p (with-open-file (in path) (with-standard-io-syntax (read in)))))
    (let ((acc (make-accessory :id (getf p :id) :name (getf p :name)
                               :model (getf p :model) :category (getf p :category)
                               :config-number (getf p :config)
                               :state-number (getf p :state)
                               :setup-code (getf p :setup-code)
                               :setup-id (getf p :setup-id)
                               :port (getf p :port)
                               :seed (%unhex (getf p :seed))
                               :public (%unhex (getf p :public))
                               :paired (and (getf p :controllers) t)
                               ;; keep persisting to the file it was loaded from
                               :store-path path)))
      (loop for entry in (getf p :controllers)
            ;; new format (id hex admin-p); tolerate the old (id . hex) too
            for id = (first entry)
            for hex = (if (consp (cdr entry)) (second entry) (cdr entry))
            for admin = (and (consp (cdr entry)) (third entry))
            do (setf (gethash id (accessory-paired-controllers acc)) (%unhex hex)
                     (gethash id (accessory-paired-permissions acc)) admin))
      acc)))
