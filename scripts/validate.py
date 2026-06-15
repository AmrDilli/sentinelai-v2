"""Detection validation harness.

Runs every sample in a labeled corpus through the SentinelAI pipeline and scores
the engine against ground truth: does it flag the malicious samples (recall) and
leave the benign ones alone (false-positive rate)?

  python scripts/make_validation_corpus.py     # build the labeled corpus
  python scripts/validate.py                    # run + print metrics

A sample is counted as "flagged as a threat" when the overall severity is
medium or higher (the same threshold the SOAR/alerting layer uses). Runs fully
offline with the deterministic mock provider and enrichment disabled, so the
numbers are reproducible.

To validate against a real labeled dataset (CTU-13 PCAPs, EVTX-ATTACK-SAMPLES,
MalwareBazaar hashes, etc.), drop the files into a directory with a manifest.json
of {"file","label","module"} entries and point CORPUS at it.
"""
import json
import os
import sys
from pathlib import Path

os.environ.setdefault("AI_PROVIDER", "mock")          # deterministic, offline
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app.pipeline import orchestrator                  # noqa: E402

CORPUS = Path(__file__).resolve().parent.parent / "samples" / "validation"
FLAG_LEVELS = {"medium", "high", "critical"}           # >= medium = "flagged"


def main():
    manifest = json.loads((CORPUS / "manifest.json").read_text())
    tp = fp = tn = fn = 0
    rows = []
    for entry in manifest:
        path = CORPUS / entry["file"]
        report = orchestrator.run_analysis(str(path), entry.get("module"),
                                           enable_enrichment=False)
        flagged = report.severity in FLAG_LEVELS
        truth = entry["label"] == "malicious"
        if truth and flagged:
            tp += 1; outcome = "TP"
        elif truth and not flagged:
            fn += 1; outcome = "FN (missed)"
        elif not truth and flagged:
            fp += 1; outcome = "FP (false alarm)"
        else:
            tn += 1; outcome = "TN"
        rows.append((entry["file"], entry["label"], report.severity, report.score, outcome))

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    acc = (tp + tn) / len(manifest) if manifest else 0.0

    print(f"{'sample':<24}{'label':<11}{'severity':<10}{'score':>6}  outcome")
    print("-" * 70)
    for f, lab, sev, sc, out in rows:
        print(f"{f:<24}{lab:<11}{sev:<10}{sc:>6}  {out}")

    print("\nConfusion matrix")
    print(f"                 flagged   not-flagged")
    print(f"  malicious   {tp:>8}   {fn:>11}")
    print(f"  benign      {fp:>8}   {tn:>11}")

    print("\nMetrics")
    print(f"  Precision           {precision:.0%}   (of flagged, how many were truly malicious)")
    print(f"  Recall              {recall:.0%}   (of malicious, how many were caught)")
    print(f"  F1                  {f1:.0%}")
    print(f"  False-positive rate {fpr_fmt(fpr)}   (of benign, how many false alarms)")
    print(f"  Accuracy            {acc:.0%}   over {len(manifest)} samples")


def fpr_fmt(x):
    return f"{x:.0%}"


if __name__ == "__main__":
    main()
