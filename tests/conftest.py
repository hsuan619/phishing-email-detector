import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from detector import Detector  # noqa: E402
from rules import load_keywords_csv, load_senders_csv  # noqa: E402


@pytest.fixture(scope="session")
def detector() -> Detector:
    return Detector(load_senders_csv(), load_keywords_csv())
