import unittest
import sys
import json

sys.path.append('..')
from postprocessing import analyzer


class TestCollection(unittest.TestCase):
    def setUp(self) -> None:
        pass

    def test_minimize_sequences(self):
        results = analyzer.CollectedResults()
        fault = analyzer.Fault(1)
        fault.branch_sequences = {
            (1, 2, 3, 6), (1, 2, 3), (1, 2, 4), (2, 3, 1), (1, 1, 2, 3), (1, 2, 3, 4),
            (5,), (5, 5),
            (6, 8), (6, 7, 8)}
        results.faults = {1: fault}

        results.minimize_sequences()
        minimized = set([tuple(sorted(s)) for s in results.faults[1].branch_sequences])
        self.assertEqual(minimized, {(1, 2, 3), (1, 2, 4), (5,), (6, 8)})

    def test_minimize_accessed(self):
        results = analyzer.CollectedResults()
        fault = analyzer.Fault(1)
        fault.accessed_addresses = {1, 2, 3, 4, 100, 200, 300, 301, 400, 401, 402, 500, 501}
        results.faults = {1: fault}

        results.minimize_accessed_addresses()
        minimized = results.faults[1].accessed_addresses
        self.assertEqual(minimized, {1, 4, 100, 200, 300, 301, 400, 402, 500, 501})

    def test_load_raw(self):
        results = analyzer.CollectedResults()
        with open("./raw-sample.json", 'r') as in_file:
            data = json.load(in_file)
        results.load(data)
        loaded = results.get_dict()
        for key, f in loaded["faults"].items():
            loaded["faults"][key] = f.get_dict()
        for key, f in loaded["branches"].items():
            loaded["branches"][key] = f.get_dict()

        self.assertEqual(data["faults"], loaded["faults"])
        self.assertEqual(data["branches"], loaded["branches"])

    def test_load_aggregated(self):
        symbolized_results = analyzer.SymbolizedResults()
        with open("./aggregated-sample.json", 'r') as in_file:
            data = json.load(in_file)
        symbolized_results.load(data)
        loaded = symbolized_results.get_dict()
        for key, f in loaded["faults"].items():
            loaded["faults"][key] = f.get_dict()
        for key, f in loaded["branches"].items():
            loaded["branches"][key] = f.get_dict()

        self.assertEqual(data["faults"], loaded["faults"])
        self.assertEqual(data["branches"], loaded["branches"])

    def test_whitelist(self):
        expected_controlled = ['loc-10b', 'loc-12b', 'loc-13b', 'loc-15b', 'loc-16b', 'loc-17b',
                               'loc-18b', 'loc-4b', 'loc-5b', 'loc-6b', 'loc-8b', 'loc-9b']
        expected_controlled_offset = ['loc-10b', 'loc-12b', 'loc-13b', 'loc-15b', 'loc-16b',
                                      'loc-17b', 'loc-18b', 'loc-4b', 'loc-5b', 'loc-6b', 'loc-8b']
        expected_uncontrolled = ['loc-10b', 'loc-12b', 'loc-13b', 'loc-15b', 'loc-16b', 'loc-17b',
                                 'loc-18b', 'loc-4b', 'loc-5b', 'loc-6b', 'loc-9b']

        args = {}
        query = analyzer.Query("./aggregated-sample.json", args)
        whitelist = query.build_whitelist(exec_threshold=10, fault_threshold=10, include_controlled_offset=False)
        self.assertEqual(whitelist, expected_controlled)

        whitelist = query.build_whitelist(exec_threshold=10, fault_threshold=10)
        self.assertEqual(whitelist, expected_controlled_offset)

        whitelist = query.build_whitelist(exec_threshold=10, fault_threshold=10,
                                          include_controlled_offset=True, include_uncontrolled=True)
        self.assertEqual(whitelist, expected_uncontrolled)


if __name__ == '__main__':
    unittest.main()
