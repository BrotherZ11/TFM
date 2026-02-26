import unittest

import pandas as pd

from metrics.experiment_plan import build_plan
from metrics.analyze_phase4 import summarize


class MetricsPhase4Tests(unittest.TestCase):
    def test_build_plan_size(self):
        rows = build_plan(["A", "B"], "K", repetitions=3, seed=1)
        self.assertEqual(len(rows), 6)
        self.assertEqual({r["sig_alg"] for r in rows}, {"A", "B"})

    def test_summarize_basic(self):
        df = pd.DataFrame(
            {
                "sig_alg": ["A", "A", "B", "B"],
                "metric": [1.0, 3.0, 2.0, 4.0],
            }
        )
        out = summarize(df, "sig_alg", "metric")
        self.assertEqual(set(out["sig_alg"].tolist()), {"A", "B"})
        self.assertIn("mean", out.columns)
        self.assertIn("p95", out.columns)


if __name__ == "__main__":
    unittest.main()
