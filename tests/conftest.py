import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DEMO_PCAP = ROOT / "samples" / "demo.pcap"


@pytest.fixture(scope="session")
def demo_tracker():
    """Tracker chargé une fois avec la capture de démonstration (lecture seule)."""
    from sniffer import ConnectionTracker
    tracker = ConnectionTracker()
    tracker.load_pcap(DEMO_PCAP, name="demo.pcap")
    return tracker


@pytest.fixture
def tracker():
    from sniffer import ConnectionTracker
    return ConnectionTracker()
