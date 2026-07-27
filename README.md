# cl-hap

[![CI](https://github.com/lispnik/hap/actions/workflows/ci.yml/badge.svg)](https://github.com/lispnik/hap/actions/workflows/ci.yml)

A pure Common Lisp implementation of Apple's **HomeKit Accessory Protocol**
(HAP, the R2 non-commercial spec) over IP — both the **accessory** and
**controller** roles. Discovery is delegated to
[0conf](https://github.com/lispnik/0conf); everything else (TLV8, the pairing
crypto, the encrypted session, the accessory model) is implemented here with no
CFFI — the only external crypto is [ironclad](https://github.com/sharplispers/ironclad).

SBCL only (the transport uses `sb-bsd-sockets` and SBCL Gray streams).

> **Not MFi-certified**, and the crypto is not constant-time — this is a
> reference/hobby implementation. Uncertified accessories pair fine with the Home
> app for personal use (with an "uncertified accessory" prompt).

## Layout

| File | Layer | Status |
|------|-------|--------|
| `src/tlv8.lisp` | HomeKit TLV8 codec (with >255-byte fragmentation) | ✅ |
| `src/crypto.lisp` | ironclad facade + hand-built ChaCha20-Poly1305 (RFC 8439) & HKDF (RFC 5869) | ✅ |
| `src/srp.lisp` | SRP-6a, 3072-bit group, SHA-512 (RFC 5054) | ✅ |
| `src/discovery.lisp` | `_hap._tcp` advertisement + TXT, on 0conf | ✅ |
| `src/pairing.lisp` | Pair-Setup M1–M6 (SRP + Ed25519) + Pairings add/remove/list, lockout | ✅ |
| `src/secure.lisp` | Pair-Verify M1–M4 (X25519 + Ed25519) + the encrypted session | ✅ |
| `src/store.lisp` | File-backed persistence (identity, pairings, permissions), auto-save | ✅ |
| `src/http.lisp` | The minimal HAP HTTP/1.1 (persistent, TLV8 + hap+json + EVENT) | ✅ |
| `src/model.lisp` | Accessory / service / characteristic model, JSON, metadata, events, /identify | ✅ |
| `src/transport.lisp` | TCP server (accessory) + client (controller) | ✅ |

Every crypto primitive is gated on published test vectors (RFC 8439, RFC 5869,
RFC 5054) before anything is built on it.

## Status

Milestones **M1–M6 complete**, plus a real-accessory hardening pass: an accessory
advertises, pairs (Pair-Setup, with attempt lockout + single-session + a random
per-accessory setup code), verifies (Pair-Verify), serves its accessory database
and characteristics (with numeric/enum metadata) over a ChaCha20-Poly1305 session,
pushes `EVENT` change notifications, manages additional controllers via
`/pairings` (add/remove/list with admin gating), answers `/identify`, advertises
the Protocol Information service, bumps `c#` on database changes, and persists
pairings on change; the controller side pairs, verifies, reads, writes,
subscribes, discovers, and manages pairings. A standard-service library
(lightbulb, switch, outlet, temperature/humidity/contact/motion sensors), a
`define-accessory` DSL, and **bridge** support (many accessories over one
connection) round out the model. **436 tests, all green** — including a full
loopback capstone (a Lisp controller pairs → verifies → reads `/accessories` →
toggles a Lightbulb → receives the pushed event, all over the encrypted channel,
no multicast required) — and a literate tutorial CI tangles and runs.

## Use

```lisp
(asdf:load-system :hap)

;;; --- accessory ---------------------------------------------------------
(let ((acc (hap:make-hap-accessory :name "Lisp Light" :category 5
                                   :setup-code "111-22-333")))
  (hap:ensure-accessory-information acc)
  (let ((on (hap:add-lightbulb acc :name "Lisp Light"
                               :on-write (lambda (v) (format t "light -> ~A~%" v)))))
    (hap:advertise-accessory acc)            ; _hap._tcp on the LAN (needs multicast)
    (let ((server (hap:serve-accessory acc)))
      ;; the accessory's own state can change and push an EVENT to subscribers:
      (hap:update-characteristic acc on t)
      ;; ... later ...
      (hap:stop-accessory server))))

;;; --- controller --------------------------------------------------------
(let ((ctrl (hap:make-hap-controller)))
  ;; discover (needs multicast), or connect to a known host/port directly:
  (let ((cs (hap:pair-with-accessory ctrl "127.0.0.1" 51826 "111-22-333")))
    (multiple-value-bind (socket stream)
        (hap:verify-with-accessory ctrl cs "127.0.0.1" 51826)
      (hap:hap-get stream "/accessories")                       ; read the DB
      (hap:hap-put stream "/characteristics"
                   (hap::s->octets "{\"characteristics\":[{\"aid\":1,\"iid\":9,\"value\":true}]}"))
      (hap:hap-subscribe stream 1 9)                            ; subscribe to events
      (hap:read-hap-event stream)                               ; receive a push
      (sb-bsd-sockets:socket-close socket))))
```

## Add a light bulb to your iPhone

[`examples/lightbulb.lisp`](examples/lightbulb.lisp) is a complete, runnable
HomeKit Lightbulb accessory. Build it as a standalone binary (a raw `sbcl` can't
send mDNS multicast on macOS, so it wouldn't be discoverable) and run it:

```sh
scripts/build-lightbulb.sh
./hap-lightbulb                     # or:  ./hap-lightbulb "Desk Lamp"
```

It prints a setup code and advertises itself as `_hap._tcp` on the LAN:

```
  Lisp Bulb — a Lisp HomeKit light bulb
  advertised as _hap._tcp  ·  port 59775  ·  id 8F:45:58:55:D4:0A

  On your iPhone:
    Home  →  +  →  Add Accessory  →  "More options…"
    pick  "Lisp Bulb",  then enter this setup code:  266-62-381
```

On the iPhone, **Home → + → Add Accessory → "More options…"**, pick **Lisp Bulb**,
and enter the code (Home warns it's an "uncertified accessory" — expected). Then
toggling it in Home / Control Center / Siri flips the Lisp bulb, printing its new
state in the terminal. The accessory's identity, code, and pairings persist in
`~/.hap-lightbulb.state`, so you pair once and it stays paired across restarts
(delete that file to reset). Verify discovery with `dns-sd -B _hap._tcp` or
`0conf browse _hap._tcp` while it runs.

## Tutorial

[`doc/tutorial.org`](doc/tutorial.org) is a literate, tangle-able tour of the API —
TLV8, building an accessory (helpers and the `define-accessory` DSL), Pair-Setup,
Pair-Verify, the encrypted session, characteristics, events, and bridges. It
tangles into a self-checking `doc/tutorial.lisp` that CI runs on every push:

```sh
emacs --batch --eval "(require 'org)" \
      --eval '(org-babel-tangle-file "doc/tutorial.org")'
sbcl --non-interactive --load doc/tutorial.lisp
```

## Environment note

On macOS, unentitled SBCL cannot send/receive mDNS multicast, so live discovery
and Home-app pairing can't be demonstrated from a raw `sbcl` here — but the entire
protocol (pairing, the encrypted session, the model, events) is exercised
end-to-end over loopback TCP in the test suite, and discovery works on an
entitled/Linux host.

## Test

```sh
ocicl install          # restore deps from ocicl.csv (needs 0conf on the source registry)
sbcl --eval '(asdf:test-system :hap)' --quit
```

## License

MIT.
