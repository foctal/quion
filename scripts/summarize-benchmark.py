#!/usr/bin/env python3
"""Summarize retained trials with a distribution-free median interval.

Input is QUION_COMPARE_TRIAL_OUTPUT JSONL from a single benchmark invocation.
Intervals describe trial medians, not percentiles of pooled request samples.
"""

import argparse
import json
import math
import statistics


def summarize(record):
    samples = record["samples"]
    if not samples or not all(isinstance(x, (int, float)) and math.isfinite(x) for x in samples):
        raise ValueError("samples must be a nonempty array of finite numbers")
    ordered = sorted(samples)
    n = len(samples)
    # The number of observations below the population median is Binomial(n, .5).
    # Choose the tightest central order-statistic interval with >=95% coverage.
    k = 0
    tail = 0
    for candidate in range(1, n // 2 + 1):
        tail += math.comb(n, candidate - 1)
        if 2 * tail / (2 ** n) <= 0.05:
            k = candidate
        else:
            break
    return {
        "benchmark": record["benchmark"],
        "stack": record["stack"],
        "metric": record["metric"],
        "trials": n,
        "median": statistics.median(samples),
        "min": ordered[0],
        "max": ordered[-1],
        "median_ci95": [ordered[k - 1], ordered[n - k]] if k else None,
        "interval_note": "independent trials assumed; insufficient trials" if not k
        else "distribution-free; independent trials assumed",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=argparse.FileType("r"))
    args = parser.parse_args()
    seen = set()
    results = []
    for line in args.input:
        record = json.loads(line)
        key = (record["benchmark"], record["stack"], record["metric"])
        if key in seen:
            raise ValueError(f"duplicate metric {key}; use one invocation per artifact")
        seen.add(key)
        results.append(summarize(record))
    if not results:
        raise ValueError("no trial records")
    for result in results:
        print(json.dumps(result, allow_nan=False))


if __name__ == "__main__":
    main()
