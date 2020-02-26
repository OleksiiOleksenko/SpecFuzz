import unittest
import sys

sys.path.append('..')
from postprocessing import analyzer


class TestCollection(unittest.TestCase):
    def setUp(self) -> None:
        fault = analyzer.Fault(1)
        fault.branch_sequences = {
            (1, 2, 3, 6), (1, 2, 3), (1, 2, 4), (2, 3, 1), (1, 1, 2, 3), (1, 2, 3, 4),
            (5,), (5, 5),
            (6, 8), (6, 7, 8)}
        fault.accessed_addresses = {1, 2, 3, 4, 100, 200, 300, 301, 400, 401, 402, 500, 501}

        self.results = analyzer.CollectedResults()
        self.results.faults = {1: fault}

    def test_minimize_sequences(self):
        self.results.minimize_sequences()
        minimized = set([tuple(sorted(s)) for s in self.results.faults[1].branch_sequences])
        self.assertEqual(minimized, {(1, 2, 3), (1, 2, 4), (5,), (6, 8)})

    def test_minimize_accessed(self):
        self.results.minimize_accessed_addresses()
        minimized = self.results.faults[1].accessed_addresses
        self.assertEqual(minimized, {1, 4, 100, 200, 300, 301, 400, 402, 500, 501})


if __name__ == '__main__':
    unittest.main()
