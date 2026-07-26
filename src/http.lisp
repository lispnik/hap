;;;; http.lisp — the minimal HAP HTTP/1.1 needed for pairing.
;;;;
;;;; HAP runs HTTP/1.1 over a single persistent TCP connection, and after
;;;; Pair-Verify wraps it in a ChaCha20-Poly1305 layer.  A general HTTP server
;;;; doesn't fit (persistent connection, the encryption wrap, EVENT pushes), so
;;;; we read/write requests directly over the octet stream.  Content bodies are
;;;; TLV8 (Content-Type: application/pairing+tlv8).

(in-package #:hap)

(defun read-crlf-line (stream)
  "Read one CRLF-terminated line as a string, or NIL at end of stream."
  (let ((out (make-array 16 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (loop for b = (read-byte stream nil nil)
          do (cond
               ((null b) (return (if (zerop (length out))
                                     nil
                                     (octets->string (coerce out '(simple-array (unsigned-byte 8) (*)))))))
               ((= b 13) (read-byte stream nil nil)      ; CR, consume the LF
                         (return (octets->string (coerce out '(simple-array (unsigned-byte 8) (*))))))
               (t (vector-push-extend b out))))))

(defun read-http-headers (stream)
  "Read headers up to the blank line into an alist (name . value)."
  (loop for line = (read-crlf-line stream)
        until (or (null line) (string= line ""))
        for colon = (position #\: line)
        when colon
          collect (cons (string-trim " " (subseq line 0 colon))
                        (string-trim " " (subseq line (1+ colon))))))

(defun header-value (headers name)
  (cdr (assoc name headers :test #'string-equal)))

(defun read-http-body (stream headers)
  (let ((len (let ((cl (header-value headers "Content-Length")))
               (or (and cl (parse-integer cl :junk-allowed t)) 0))))
    (let ((body (make-array len :element-type '(unsigned-byte 8))))
      (when (plusp len)
        (let ((got (read-sequence body stream)))
          (unless (= got len)
            ;; a truncated/closed connection must not masquerade as a
            ;; zero-padded body — fail loudly so the caller drops the message.
            (error "short HTTP body: Content-Length ~D but only ~D bytes read" len got))))
      body)))

(defun read-http-request (stream)
  "Read one HAP request.  Returns (values method path body) or NIL at EOF."
  (let ((line (read-crlf-line stream)))
    (when (and line (plusp (length line)))
      (let* ((parts (uiop:split-string line :separator '(#\Space)))
             (headers (read-http-headers stream)))
        (values (first parts) (second parts) (read-http-body stream headers))))))

(defun read-http-response (stream)
  "Read a response.  Returns (values body-octets status-code)."
  (let* ((status-line (read-crlf-line stream))
         (code (when status-line
                 (let ((parts (uiop:split-string status-line :separator '(#\Space))))
                   (ignore-errors (parse-integer (second parts))))))
         (body (read-http-body stream (read-http-headers stream))))
    (values body code)))

(defun write-http (stream start-line body)
  "Write START-LINE + the pairing+tlv8 headers + BODY."
  (write-sequence
   (s->octets (format nil "~A~C~CContent-Type: application/pairing+tlv8~C~C~
                           Content-Length: ~D~C~C~C~C"
                      start-line #\Return #\Newline #\Return #\Newline
                      (length body) #\Return #\Newline #\Return #\Newline))
   stream)
  (write-sequence body stream)
  (finish-output stream))

(defun write-http-response (stream body &optional (status "HTTP/1.1 200 OK"))
  (write-http stream status body))

(defun write-http-post (stream path body)
  (write-http stream (format nil "POST ~A HTTP/1.1" path) body))

;;; --- generic replies (M4: JSON accessory/characteristic traffic) -----------

(defstruct (reply (:constructor make-reply (status content-type body)))
  "A ready-to-send HTTP response: STATUS (\"200 OK\"), CONTENT-TYPE (NIL for none),
BODY (octets or NIL)."
  status content-type body)

(defun tlv-reply (body) (make-reply "200 OK" "application/pairing+tlv8" body))
(defun json-reply (body &optional (status "200 OK"))
  (make-reply status "application/hap+json" body))
(defun no-content () (make-reply "204 No Content" nil nil))

(defun write-reply (stream reply)
  "Write a REPLY struct: status line, optional Content-Type/-Length, optional body."
  (let ((body (reply-body reply)))
    (write-sequence
     (s->octets
      (if (and body (plusp (length body)))
          (format nil "HTTP/1.1 ~A~C~CContent-Type: ~A~C~CContent-Length: ~D~C~C~C~C"
                  (reply-status reply) #\Return #\Newline
                  (reply-content-type reply) #\Return #\Newline
                  (length body) #\Return #\Newline #\Return #\Newline)
          (format nil "HTTP/1.1 ~A~C~CContent-Length: 0~C~C~C~C"
                  (reply-status reply) #\Return #\Newline
                  #\Return #\Newline #\Return #\Newline)))
     stream)
    (when (and body (plusp (length body))) (write-sequence body stream))
    (finish-output stream)))

(defun write-http-get (stream path)
  "Write a bodyless GET request."
  (write-sequence
   (s->octets (format nil "GET ~A HTTP/1.1~C~CContent-Length: 0~C~C~C~C"
                      path #\Return #\Newline #\Return #\Newline #\Return #\Newline))
   stream)
  (finish-output stream))

(defun write-http-put (stream path body)
  "Write a PUT request carrying a hap+json BODY."
  (write-sequence
   (s->octets (format nil "PUT ~A HTTP/1.1~C~CContent-Type: application/hap+json~C~C~
                           Content-Length: ~D~C~C~C~C"
                      path #\Return #\Newline #\Return #\Newline
                      (length body) #\Return #\Newline #\Return #\Newline))
   stream)
  (write-sequence body stream)
  (finish-output stream))
