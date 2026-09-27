#!/usr/bin/env python3
"""Check uncertainty reporting at small-sample boundaries."""

import importlib.util
from pathlib import Path
import unittest
import sys

sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location(
    "summary", Path(__file__).with_name("summarize-benchmark.py")
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SummaryTests(unittest.TestCase):
    def summary(self, samples):
        return module.summarize({
            "benchmark": "echo", "stack": "quion", "metric": "p99_ns",
            "samples": samples,
        })

    def test_five_trials_cannot_provide_finite_95_percent_interval(self):
        self.assertIsNone(self.summary([1, 2, 3, 4, 5])["median_ci95"])

    def test_six_trials_use_full_range(self):
        result = self.summary([6, 2, 1, 5, 4, 3])
        self.assertEqual(result["median_ci95"], [1, 6])
        self.assertEqual(result["median"], 3.5)

    def test_fifteen_trials_exclude_three_extremes_per_side(self):
        self.assertEqual(self.summary(list(range(15)))["median_ci95"], [3, 11])

    def test_invalid_measurements_fail_closed(self):
        for samples in [[], [float("nan")], [float("inf")]]:
            with self.assertRaises(ValueError):
                self.summary(samples)


if __name__ == "__main__":
    unittest.main()
