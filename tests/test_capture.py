from typing import ClassVar

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from netscope.capture import CaptureController, CaptureError


class FakeSniffer:
    instances: ClassVar[list] = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.started = False
        self.stopped = False
        self.__class__.instances.append(self)

    def start(self):
        self.started = True

    def stop(self, join=True):
        self.stopped = True

    def emit(self, packet):
        self.kwargs["prn"](packet)


def test_start_capture_stop_and_restart() -> None:
    FakeSniffer.instances.clear()
    controller = CaptureController(sniffer_factory=FakeSniffer)
    controller.start("test0")
    assert controller.status().state == "capturing"
    FakeSniffer.instances[-1].emit(Ether() / IP() / TCP())
    assert len(controller.drain()) == 1
    controller.stop()
    assert controller.status().state == "stopped"
    controller.start("test0")
    controller.stop()
    assert len(FakeSniffer.instances) == 2


def test_duplicate_start_and_idle_stop() -> None:
    controller = CaptureController(sniffer_factory=FakeSniffer)
    controller.stop()
    controller.start("test0")
    with pytest.raises(CaptureError, match="already running"):
        controller.start("test0")
    controller.stop()


def test_queue_and_retention_are_bounded() -> None:
    controller = CaptureController(queue_size=2, max_retained=1, sniffer_factory=FakeSniffer)
    controller.start("test0")
    sniffer = FakeSniffer.instances[-1]
    for _ in range(4):
        sniffer.emit(Ether() / IP() / TCP())
    assert controller.status().dropped_queue == 2
    controller.drain()
    assert len(controller.records()) == 1
    assert controller.status().dropped_retention == 1
    controller.stop()


def test_start_failure_is_friendly_and_recoverable() -> None:
    def broken_factory(**_kwargs):
        raise PermissionError("access denied")

    controller = CaptureController(sniffer_factory=broken_factory)
    with pytest.raises(CaptureError, match="Npcap"):
        controller.start("test0")
    assert controller.status().state == "error"
    controller.clear()
    assert controller.status().state == "idle"
