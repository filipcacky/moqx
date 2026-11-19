#!/usr/bin/env python3
"""test_relay_goaway.py — SIGTERM sends GOAWAY to every session, then the relay exits early.

Unpeered relays, one per session shape:
  A: a publisher with no subscription, so the session has no open requests and
     drains at once. Its GOAWAY must still reach the wire before the close.
  B: a publisher plus a live subscriber, so the subscriber session carries a
     request when GOAWAY arrives.

The GOAWAY carries no New Session URI. The drain timeout is long and the exit
bound short, so each relay must notice that its last session closed rather than
wait the drain out. The clients log the GOAWAY they receive (moqdateserver
"Processing goaway uri=", moqtextclient "Goaway uri=").

Usage: python3 test/test_relay_goaway.py [path/to/moqx] [--save-logs [DIR]]
"""

from lib.moq_harness import main

NAMESPACE = "moq-date"
TRACK = "date"
DRAIN_TIMEOUT_MS = 10000
# Far below the drain timeout: the relay must finish as soon as its sessions
# close. Covers teardown plus sanitizer and loaded-CI headroom.
EXIT_WITHIN_S = 5
SHUTDOWN = {"drain_timeout_ms": DRAIN_TIMEOUT_MS}


def stop_and_check(h, relay):
    h.relay_stop(relay, within=EXIT_WITHIN_S)
    h.expect_relay_log(relay, r"Sending GOAWAY")
    h.expect_relay_log(relay, r"Drain complete")


def run(h):
    for name in ("A", "B"):
        h.relay(name, shutdown=SHUTDOWN)
    h.start()

    # TODO: enable on picoquic. See the optimistic delivery callback in moxygen's
    # PicoWebTransportBase::onJitProvideData.
    idle_goaway_arrives = h.quic_stack != "picoquic"

    h.case("An idle session receives GOAWAY before the relay closes it")

    idle_pub = h.actor("idle-pub", "publisher", relay="A", ns=NAMESPACE, track=TRACK)
    idle_pub.start()
    h.wait_namespace("A", NAMESPACE)

    stop_and_check(h, "A")
    if idle_goaway_arrives:
        h.expect_actor_output(idle_pub, r"Processing goaway uri=$")
    idle_pub.stop()

    h.case("A subscriber receives GOAWAY and leaves")

    pub = h.actor("pub", "publisher", relay="B", ns=NAMESPACE, track=TRACK)
    # The deadline is a backstop: on GOAWAY moqtextclient stops by itself.
    sub = h.actor("sub", "subscriber", relay="B", ns=NAMESPACE, track=TRACK, timeout=30)
    pub.start()
    h.wait_namespace("B", NAMESPACE)
    sub.start()
    h.wait_subscription("B", NAMESPACE, TRACK)

    stop_and_check(h, "B")
    sub.wait()
    h.expect_actor_output(sub, r"Goaway uri=$")
    h.expect_exited(sub)
    h.expect_actor_output(pub, r"Processing goaway uri=$")
    pub.stop()


main(run, base_port_key="goaway")
