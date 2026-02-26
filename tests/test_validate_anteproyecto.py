import unittest

from metrics.validate_anteproyecto import REQUIRED_PATHS, OPTIONAL_ARTIFACTS


class ValidateAnteproyectoTests(unittest.TestCase):
    def test_required_paths_non_empty(self):
        self.assertGreater(len(REQUIRED_PATHS), 5)

    def test_optional_artifacts_declared(self):
        self.assertIn("artifacts/pcap", OPTIONAL_ARTIFACTS)
        self.assertIn("artifacts/figs", OPTIONAL_ARTIFACTS)


if __name__ == "__main__":
    unittest.main()
