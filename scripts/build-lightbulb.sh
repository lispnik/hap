#!/bin/sh
# Build the standalone `hap-lightbulb` HomeKit accessory.
#
#   scripts/build-lightbulb.sh          # build ./hap-lightbulb
#
# A built binary is used (not raw `sbcl`) because on macOS the interpreter can't
# send mDNS multicast, so the accessory wouldn't be discoverable.  The first run
# may prompt for Local Network access — allow it (see the 0conf repo's
# doc/macos-multicast.md).  Needs SBCL + ocicl, with the sibling 0conf on the
# ASDF source registry.
set -eu

cd "$(dirname "$0")/.."

echo "Building hap-lightbulb ..."
sbcl --non-interactive --eval '(asdf:make :hap/lightbulb)'

if [ ! -x ./hap-lightbulb ]; then
  echo "build failed: ./hap-lightbulb not produced" >&2
  exit 1
fi
echo "Built ./hap-lightbulb"
echo "Run it:  ./hap-lightbulb   (or:  ./hap-lightbulb \"Desk Lamp\" 842-19-736)"
