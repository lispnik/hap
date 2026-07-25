;;;; test/srp-tests.lisp

(in-package #:hap/test)

(in-suite hap-tests)

(defun bigint (s) (parse-integer s :radix 16))

(test srp-rfc5054-1024-vector
  ;; RFC 5054 Appendix B — the authoritative SRP-6a test vector (1024-bit, SHA-1).
  ;; Reproducing x/v/A/B/u/S proves the algorithm is byte-exact correct.
  (let* ((n (bigint "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3"))
         (group (hap::make-srp-group n 2 :sha1))
         (salt (hex "BEB25379D1A8581EB5A727673A2441EE"))
         (a (bigint "60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393"))
         (b (bigint "E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20"))
         (want-x (bigint "94B7555AABE9127CC58CCF4993DB6CF84D16C124"))
         (want-v (bigint "7E273DE8696FFC4F4E337D05B4B375BEB0DDE1569E8FA00A9886D8129BADA1F1822223CA1A605B530E379BA4729FDC59F105B4787E5186F5C671085A1447B52A48CF1970B4FB6F8400BBF4CEBFBB168152E08AB5EA53D15C1AFF87B2B9DA6E04E058AD51CC72BFC9033B564E26480D78E955A5E29E7AB245DB2BE315E2099AFB"))
         (want-a-pub (bigint "61D5E490F6F1B79547B0704C436F523DD0E560F0C64115BB72557EC44352E8903211C04692272D8B2D1A5358A2CF1B6E0BFCF99F921530EC8E39356179EAE45E42BA92AEACED825171E1E8B9AF6D9C03E1327F44BE087EF06530E69F66615261EEF54073CA11CF5858F0EDFDFE15EFEAB349EF5D76988A3672FAC47B0769447B"))
         (want-b-pub (bigint "BD0C61512C692C0CB6D041FA01BB152D4916A1E77AF46AE105393011BAF38964DC46A0670DD125B95A981652236F99D9B681CBF87837EC996C6DA04453728610D0C6DDB58B318885D7D82C7F8DEB75CE7BD4FBAA37089E6F9C6059F388838E7A00030B331EB76840910440B1B27AAEAEEB4012B7D7665238A8E3FB004B117B58"))
         (want-u (bigint "CE38B9593487DA98554ED47D70A7AE5F462EF019"))
         (want-s (bigint "B0DC82BABCF30674AE450C0287745E7990A3381F63B387AAF271A10D233861E359B48220F7C4693C9AE12B0A6F67809F0876E2D013800D6C41BB59B6D5979B5C00A172B4A2A5903A0BDCAF8A709585EB2AFAFA8F3499B200210DCC1F10EB33943CD67FC88A2F39A4BE5BEC4EC0A3212DC346D7E474B29EDE8A469FFECA686E5A")))
    (multiple-value-bind (v x) (hap::srp-verifier group salt "alice" "password123")
      (is (= want-x x))
      (is (= want-v v))
      (is (= want-a-pub (hap::srp-a-pub group a)))
      (is (= want-b-pub (hap::srp-b-pub group v b)))
      (is (= want-u (hap::srp-u group want-a-pub want-b-pub)))
      (is (= want-s (hap::srp-client-secret group a want-b-pub x)))
      (is (= want-s (hap::srp-server-secret group b want-a-pub v))))))

(test srp-3072-prime-intact
  ;; the embedded 3072-bit group prime is exactly 3072 bits (catches truncation)
  (is (= 3072 (integer-length (hap::srp-group-prime hap::*hap-srp-group*)))))

(test srp-hap-3072-handshake
  ;; The HAP instantiation (3072-bit, SHA-512): a full client<->server exchange
  ;; must agree on the premaster secret, the session key, and the proofs.
  (let* ((group hap::*hap-srp-group*)
         (salt (ironclad:random-data 16))
         (user "Pair-Setup")
         (pass "123-45-678"))
    (multiple-value-bind (v x) (hap::srp-verifier group salt user pass)
      (let* ((a (hap::bytes->int (ironclad:random-data 32)))
             (b (hap::bytes->int (ironclad:random-data 32)))
             (a-pub (hap::srp-a-pub group a))
             (b-pub (hap::srp-b-pub group v b))
             (client-s (hap::srp-client-secret group a b-pub x))
             (server-s (hap::srp-server-secret group b a-pub v)))
        (is (= client-s server-s))                       ; same premaster secret
        (let ((kc (hap::srp-session-key group client-s))
              (ks (hap::srp-session-key group server-s)))
          (is (equalp kc ks))                            ; same session key
          ;; client's M1 verifies on the server side; server produces M2
          (let ((m1 (hap::srp-m1 group user salt a-pub b-pub kc)))
            (is (equalp m1 (hap::srp-m1 group user salt a-pub b-pub ks)))
            (is (= 64 (length (hap::srp-m2 group a-pub m1 ks))))))))))
