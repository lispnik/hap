# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A pure Common Lisp implementation of Apple's HomeKit Accessory Protocol (HAP R2, over IP) — both the **accessory** (server) and **controller** (client) roles. **SBCL only** (uses `sb-bsd-sockets` and SBCL Gray streams). No CFFI: the only external crypto is ironclad; ChaCha20-Poly1305 and HKDF are hand-built in `src/crypto.lisp`. mDNS discovery is delegated to the sibling `0conf` project (github.com/lispnik/0conf), which is **not on any registry** — it must be on the ASDF source registry (CI checks it out as a sibling dir).

## Commands

```sh
ocicl install                                              # restore deps from ocicl.csv into ./ocicl/
sbcl --non-interactive --eval '(asdf:test-system :hap)'    # full FiveAM suite (signals on failure)
scripts/build-lightbulb.sh                                 # builds ./hap-lightbulb (asdf:make :hap/lightbulb)
```

Run a single test from a REPL (all tests live in one suite, `hap/test::hap-tests`):

```lisp
(asdf:load-system :hap/test)
(fiveam:run! 'hap/test::pair-setup-full-handshake)
```

`hap/test:run-tests` (defined in `test/tlv8-tests.lisp`) binds `0conf::*announce-interval*` etc. to 0 so advertising tests are instant — if running tests directly rather than via `asdf:test-system`, use `run-tests` or bind those yourself.

Literate tutorial (CI runs this on Linux; `doc/tutorial.org` is the source of truth, `doc/tutorial.lisp` is generated and gitignored):

```sh
emacs --batch --eval "(require 'org)" --eval '(org-babel-tangle-file "doc/tutorial.org")'
sbcl --non-interactive --load doc/tutorial.lisp
```

Keep `doc/tutorial.org` working when changing the public API — CI will fail otherwise.

## Architecture

`hap.asd` loads `src/` with `:serial t`, in layer order — each file depends only on those before it:

`tlv8` → `crypto` → `discovery` → `srp` → `store` → `pairing` → `secure` → `http` → `model` → `transport`

- **tlv8** — HomeKit TLV8 codec, including >255-byte fragmentation. Used by every pairing message.
- **crypto / srp** — primitives gated on RFC test vectors (8439, 5869, 5054). SRP-6a, 3072-bit group, SHA-512.
- **discovery** — `_hap._tcp` advertisement + TXT record on 0conf. Advertises under its own `hap-<id>.local` host with only the routable LAN IPv4 (not the system host record, which includes loopback/link-local addresses iOS may pick and fail on).
- **pairing** — Pair-Setup M1–M6 state machine (accessory and controller sides), `/pairings` add/remove/list with admin gating, attempt lockout. Changes in paired state must re-publish the TXT record (`sf` flag) via `update-accessory-advertisement`.
- **secure** — Pair-Verify M1–M4 (X25519 + Ed25519) and the ChaCha20-Poly1305 framed session (`hap-session`). Also defines `*hap-trace*` / `htrace`.
- **store** — file-backed persistence of identity, pairings, permissions; auto-saves on change.
- **http** — minimal HAP HTTP/1.1: persistent connections, TLV8 and `application/hap+json` bodies, and `EVENT/1.0` pushes.
- **model** — accessory → service → characteristic tree, JSON serialization, metadata, subscriptions/events, `/identify`, standard-service helpers (`add-lightbulb`, sensors, …), the `define-accessory` DSL, and bridges. Service/characteristic UUIDs are the short-form `+svc-*+` / `+char-*+` constants.
- **transport** — the TCP server (dual-stack IPv6 socket with `IPV6_V6ONLY=0`; one thread per connection, each connection carries its own pairing/verify session and upgrades to encrypted after Pair-Verify) and the controller client (`pair-with-accessory`, `verify-with-accessory`, `hap-get`/`hap-put`/`hap-subscribe`).

Everything is in the single `hap` package (`src/package.lisp` is the export list); tests use `hap::` for internals.

## Testing caveat: loopback can hide spec mismatches

The suite's capstone runs a Lisp controller against a Lisp accessory over loopback TCP — no multicast needed. Because both sides share the same code, a symmetric deviation from what iOS does will pass every test (e.g. a past bug padded `g` in SRP's M1 `H(g)` term; iOS/HAP-python/HAP-NodeJS hash it **unpadded**). When touching pairing/crypto, compare against reference implementations (HAP-python, HAP-NodeJS), not just our own controller.

For real-device debugging, bind `hap::*hap-trace*` to a logging function (the lightbulb example enables it by default) to see how far an iPhone gets through Pair-Setup / Pair-Verify / encrypted requests.

## Real-device / macOS notes

- On macOS, a raw `sbcl` cannot send mDNS multicast, so live discovery needs the built `./hap-lightbulb` binary (first run may prompt for Local Network access). Loopback tests work anywhere.
- The example persists state in `~/.hap-lightbulb.state`; delete it to reset pairing.
- A hub-less HomeKit home may show "No Response" after successful pairing — that is environmental (a home hub is required), not necessarily a bug.
