import os
import sys
from pathlib import Path

# Ensure backend/ is importable and the offline mock provider is used in tests.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ["AI_PROVIDER"] = "mock"

SAMPLES = Path(__file__).resolve().parents[2] / "samples" / "generated"
