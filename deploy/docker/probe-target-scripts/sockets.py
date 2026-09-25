#!/usr/bin/env python3
"""Verification-target helper for the Sensor probe (kestrelynx sensor
--probe): opens a writable /tmp plus one listening UNIX stream socket and
one bound UNIX datagram socket at fixed, well-known paths, then idles.

This is deliberately not part of the KestreLynx product: it exists only so
deploy/docker/probe-targets.sh has something to connect the Sensor probe's
denied-connect/denied-sendto checks against. It never reads or writes
anything the Sensor probe sends it — the probe's checks only care whether
the connect(2)/sendto(2) call itself was denied, not what a real peer would
do with the message.
"""
import os
import socket
import time

STREAM_PATH = "/tmp/kestrelynx-probe.sock"
DGRAM_PATH = "/tmp/kestrelynx-probe.sock.dgram"

for path in (STREAM_PATH, DGRAM_PATH):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass

stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
stream.bind(STREAM_PATH)
stream.listen(1)

dgram = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
dgram.bind(DGRAM_PATH)

# World-writable, matching a container image's ordinary /tmp: the Sensor
# probe's read-only checks (root-directory listing) and its denied-write
# check both exercise this directory.
os.chmod("/tmp", 0o1777)

while True:
    time.sleep(3600)
