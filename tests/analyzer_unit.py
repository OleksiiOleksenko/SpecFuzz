import unittest
import sys

sys.path.append('..')
from postprocessing import analyzer


class TestCollection(unittest.TestCase):
    def setUp(self) -> None:
        fault = analyzer.Fault(1)
        fault.branch_sequences = {
            (1, 2, 3, 6), (1, 2, 3), (1, 2, 4), (2, 3, 1), (1, 1, 2, 3), (1, 2, 3, 4),
            (5,), (5, 5), }

        self.results = analyzer.CollectedResults()
        self.results.faults = {1: fault}

    def test_minimize(self):
        self.results.minimize_sequences()
        self.assertEqual(self.results.faults[1].branch_sequences, {(1, 2, 3), (1, 2, 4), (5,)})


if __name__ == '__main__':
    unittest.main()
