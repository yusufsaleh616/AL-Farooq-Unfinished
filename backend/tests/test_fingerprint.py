import uuid

import fingerprint
import pytest
from tests.conftest import REAL_FINGERPRINT_HASH


def test_made_up_mac_is_ignored(monkeypatch):
    # Python invents a random MAC (multicast bit set) when the PC has none
    monkeypatch.setattr(uuid, "getnode", lambda: 0x010203040506 | (1 << 40))
    assert fingerprint._real_mac() == ""


def test_real_mac_is_kept(monkeypatch):
    monkeypatch.setattr(uuid, "getnode", lambda: 0x001A2B3C4D5E)
    assert fingerprint._real_mac() == "001a2b3c4d5e"


def test_fingerprint_is_stable_when_mac_is_random(monkeypatch):
    monkeypatch.setattr(fingerprint, "_powershell", lambda cmd: "same-value")
    monkeypatch.setattr(fingerprint.platform, "system", lambda: "Windows")
    values = iter([0x010000000001, 0x010000000002])           # different "random" MAC each call
    monkeypatch.setattr(uuid, "getnode", lambda: next(values))
    assert REAL_FINGERPRINT_HASH() == REAL_FINGERPRINT_HASH()


def test_empty_fingerprint_is_refused(monkeypatch):
    monkeypatch.setattr(fingerprint, "raw_parts", lambda: ("", "", ""))
    with pytest.raises(RuntimeError):
        REAL_FINGERPRINT_HASH()
