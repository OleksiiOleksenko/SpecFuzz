#!/usr/bin/env python3
import sys
from pprint import pprint
from typing import Dict, Set, List, Tuple
from argparse import ArgumentParser
import subprocess
import re
import json
from operator import itemgetter


class SaneJSONEncoder(json.JSONEncoder):
    def default(self, o):
        get_dict = getattr(o, "get_dict", None)
        if callable(get_dict):
            return get_dict()
        else:
            return o.__dict__


# ====================
# Data Collection
# ====================
class Fault:
    address: int
    accessed_addresses: Set[int]
    offsets: Set[int]
    branch_sequences: Set[Tuple[int]]
    order: int = 0
    fault_count: int = 0
    controlled: bool = False
    controlled_offset: bool = False
    types: Set[int]

    def __init__(self, address: int):
        self.address = address
        self.accessed_addresses = set()
        self.offsets = set()
        self.branch_sequences = set()
        self.types = set()

    def __lt__(self, other):
        return self.address < other.address

    def get_dict(self):
        sequences = []
        for seq in self.branch_sequences:
            sequences.append(list([hex(b) for b in seq]))

        return {
            "address": hex(self.address),
            "accessed_addresses": sorted(list([a for a in self.accessed_addresses])),
            "offsets": sorted(list([a for a in self.offsets])),
            "branch_sequences": sequences,
            "order": self.order,
            "fault_count": self.fault_count,
            "controlled": self.controlled,
            "controlled_offset": self.controlled_offset,
            "types": list(self.types)
        }

    def load(self, data: Dict):
        self.accessed_addresses = set([int(i) for i in data["accessed_addresses"]])
        self.offsets = set([int(i) for i in data["offsets"]])
        for branch_sequence in data["branch_sequences"]:
            self.branch_sequences.add(tuple([int(b, 16) for b in branch_sequence]))
        self.order = int(data["order"])
        self.fault_count = int(data["fault_count"])
        self.controlled = bool(data["controlled"])
        self.controlled_offset = bool(data["controlled_offset"])
        self.types = set([int(i) for i in data["types"]])

    def update(self, update):
        assert (self.address == update.address), \
            "Updated address does not match: {} and {}".format(self.address, update.address)

        # define controllability:
        # a fault is controllable if there is at least one experiment where the accessed addresses
        # or their offsets differ
        if update.accessed_addresses and self.accessed_addresses and \
                update.accessed_addresses != self.accessed_addresses:
            self.controlled = True
        if update.offsets and self.offsets and update.offsets != self.offsets:
            self.controlled_offset = True

        self.accessed_addresses |= update.accessed_addresses
        self.offsets |= update.offsets
        self.branch_sequences |= update.branch_sequences
        self.fault_count += 1
        self.types |= update.types


class Branch:
    address: int
    faults: Set[int]
    fault_count: int = 0
    nonspeculative_execution_count: int = 0

    def __init__(self, address):
        self.address = address
        self.faults = set()

    def __lt__(self, other):
        return self.address < other.address

    def get_dict(self):
        return {
            "address": hex(self.address),
            "faults": list([hex(f) for f in sorted(self.faults)]),
            "fault_count": self.fault_count,
            "nonspeculative_execution_count": self.nonspeculative_execution_count,
        }

    def load(self, data):
        self.faults = set([int(i, 16) for i in data["faults"]])
        self.fault_count = int(data["fault_count"])
        self.nonspeculative_execution_count = int(data["nonspeculative_execution_count"])

    def update(self, branch_update: 'Branch'):
        assert (self.address == branch_update.address)
        self.fault_count += 1
        self.faults |= branch_update.faults


class CollectedResults:
    total_guards: int
    branches: Dict[int, Branch]
    faults: Dict[int, Fault]
    crashed_runs: List[str]
    statistics: Dict

    def __init__(self):
        self.branches = {}
        self.faults = {}
        self.statistics = {}
        self.crashed_runs = []
        self.total_guards = 0

    def update(self, single_experiment_results: 'CollectedResults'):
        for edge_address, new_edge_data in single_experiment_results.branches.items():
            edge = self.branches.setdefault(edge_address, Branch(edge_address))
            edge.update(new_edge_data)

        for instruction_address, new_instruction_data in single_experiment_results.faults \
                .items():
            instruction = self.faults \
                .setdefault(instruction_address, Fault(instruction_address))
            instruction.update(new_instruction_data)

    def merge(self, full_data):
        for address, data in full_data["branches"].items():
            branch = self.branches.setdefault(int(address), Branch(int(address)))
            branch.nonspeculative_execution_count += data["nonspeculative_execution_count"]
            branch.fault_count += data["fault_count"]
            for f in data.get("faults", []):
                branch.faults.add(int(f, 16))

        for address, data in full_data["faults"].items():
            fault = self.faults.setdefault(int(address), Fault(int(address)))
            fault.fault_count += data["fault_count"]
            fault.order = data["order"] if fault.order == 0 or fault.order > data["order"] \
                else fault.order
            fault.controlled |= bool(data["controlled"])
            fault.controlled_offset |= bool(data["controlled_offset"])
            for a in data["accessed_addresses"]:
                fault.accessed_addresses.add(a)
            for a in data["offsets"]:
                fault.offsets.add(a)
            for a in data["types"]:
                fault.types.add(a)
            for branch_sequence in data["branch_sequences"]:
                fault.branch_sequences \
                    .add(tuple([int(b, 16) for b in branch_sequence]))

        for e in full_data["errors"]:
            self.crashed_runs.append(e)

    def get_dict(self):
        return {
            "errors": self.crashed_runs,
            "statistics": self.statistics,
            "branches": self.branches,
            "faults": self.faults,
        }

    def load(self, results_json: Dict):
        for key, data in results_json["branches"].items():
            branch = Branch(int(key))
            branch.load(data)
            self.branches[key] = branch

        for key, data in results_json["faults"].items():
            fault = Fault(int(key))
            fault.load(data)
            self.faults[key] = fault

        self.crashed_runs = results_json["errors"]
        self.statistics = results_json["statistics"]

    def collect_statistics(self):
        # coverage
        covered_edges = 0
        for v in self.branches.values():
            if v != 0 and v.nonspeculative_execution_count != 0:
                covered_edges += 1

        coverage_normalized = (covered_edges * 100 / self.total_guards) if self.total_guards else -1
        self.statistics = {
            "coverage": [coverage_normalized, covered_edges],
            "branches": len(self.branches),
            "faults": len(self.faults)
        }

    def set_order(self):
        for fault in self.faults.values():
            for branch_sequence in fault.branch_sequences:
                if fault.order == 0 or fault.order > len(branch_sequence):
                    fault.order = len(branch_sequence)

    def minimize_sequences(self):
        """Remove redundant branch sequences.
        E.g., if we have two sequences: (A, B, C) and (A, B, C, D),
        we consider the latter one redundant as the same vulnerability
        could be triggered by a misprediction of a subset of branches in it.
        """
        for fault in self.faults.values():
            # remove duplicates first and generate a nice list of sorted tuples
            sequences = set([tuple(set(s)) for s in fault.branch_sequences])

            # sort
            sequences = list(sequences)
            sequences.sort(key=lambda x: len(x), reverse=True)

            # search for supersets
            sequences_to_keep = []
            while len(sequences) > 0:
                top_sequence = sequences.pop()
                sequences_to_keep.append(top_sequence)

                not_supersets_of_top = []
                for other_sequence in sequences[:]:
                    # same length, different contents - definitely not a superset
                    # (duplicates are already removed)
                    if len(top_sequence) == len(other_sequence):
                        not_supersets_of_top.append(other_sequence)
                        continue

                    # check for supersets
                    # since the list is sorted, here len(other_sequence) > len(top_sequence)
                    for element in top_sequence:
                        if element not in other_sequence:
                            not_supersets_of_top.append(other_sequence)
                            break

                sequences = not_supersets_of_top

            fault.branch_sequences = set(sequences_to_keep)

        # after the minimization, some of the data in branches is not valid any more
        for branch in self.branches.values():
            branch.faults = set()

    def minimize_accessed_addresses(self):
        """Remove most of the data about accessed addresses
        and leave only the range limits
        """
        for fault in self.faults.values():
            accessed = list(fault.accessed_addresses)
            accessed.sort()
            redundant = []
            range_started = False
            for i in range(len(accessed) - 1):
                # end of a range
                if accessed[i + 1] - accessed[i] > 64:
                    range_started = False
                    continue

                # start of a range
                if not range_started:
                    range_started = True
                    continue

                # in a range
                redundant.append(accessed[i])
            fault.accessed_addresses -= set(redundant)


class Collector:
    results: CollectedResults
    current_experiment: CollectedResults
    main_branch: str

    def __init__(self):
        self.current_experiment = CollectedResults()
        self.results = CollectedResults()

    def collect_data(self, output, hongg_report, binary, main_branch):
        self.main_branch = main_branch

        # connect to the SUT's output and process it, line by line
        while True:
            try:
                line = sys.stdin.readline()
            except UnicodeDecodeError:
                print("Cannot process non-unicode data.\n"
                      "Set the required encoding in the PYTHONIOENCODING environment variable")
                exit(1)

            if not line:
                break  # EOF
            if not self.process_line(line):
                break
        self.process_experiment()  # process the last experiment

        # get additional data
        self.parse_hongg_report(hongg_report)
        self.results.total_guards = self.set_total_branch_count(binary)

        # process results
        self.results.collect_statistics()
        self.results.set_order()

        with open(output, 'w') as out_file:
            json.dump(self.results, out_file, indent=2, cls=SaneJSONEncoder)

    def process_line(self, line) -> bool:
        # check for errors
        if "Error" in line:
            self.results.crashed_runs.append(line)
            return False

        # if we start a new experiment, aggregate the previous one
        if line.startswith("[SF] Starting"):
            self.process_experiment()
            return True

        # filter out the lines not produced by SpecFuzz
        if not line.startswith(r'[SF],'):
            return True

        # parse the line
        try:
            values = line.split(",")
            fault_type = int(values[1])
            fault_address = int(values[2], 16)
            accessed_address = int(values[3], 16)
            offset = int(values[4])
            branches_sequence = [int(x, 16) for x in values[5:]]
        except:
            print("Error parsing string: " + str(line))
            return True

        if self.main_branch == "first":
            branch_address = branches_sequence[-1]
        else:
            branch_address = branches_sequence[0]

        # add the parsed data to the current experiment
        branch = self.current_experiment.branches. \
            setdefault(branch_address, Branch(branch_address))
        branch.faults.add(fault_address)

        fault = self.current_experiment.faults \
            .setdefault(fault_address, Fault(fault_address))
        if offset != 0:
            fault.offsets.add(offset)
        else:
            fault.accessed_addresses.add(accessed_address)
        fault.branch_sequences.add(tuple(sorted(branches_sequence)))
        fault.types.add(fault_type)
        return True

    def process_experiment(self):
        self.results.update(self.current_experiment)
        self.current_experiment.branches.clear()
        self.current_experiment.faults.clear()

    def parse_hongg_report(self, report: str):
        with open(report, "r") as f:
            for line in f:
                if not line.startswith("[SF]"):
                    continue

                try:
                    _, edge_address, count = line.split(" ")
                except ValueError:
                    print("Unexpected line: %s" % line)
                    continue
                if edge_address == "0x0:":
                    continue

                edge = self.results.branches \
                    .setdefault(int(edge_address[:-1], 16), Branch(int(edge_address[:-1], 16)))
                edge.nonspeculative_execution_count = int(count)

    @staticmethod
    def set_total_branch_count(binary: str):
        try:
            output = subprocess.check_output(["objdump", binary, "-D"])
        except subprocess.CalledProcessError:
            output = "".encode()

        total_cov_branches = len(re.findall(r"callq.*specfuzz_chkp", output.decode()))
        total_cov_branches_nosim = len(
            re.findall(r"callq.*specfuzz_cov_trace_pc_wrapper", output.decode()))
        if total_cov_branches < 2 and total_cov_branches_nosim != 0:
            return total_cov_branches_nosim
        return total_cov_branches


def merge_reports(inputs, output, binary):
    merged = CollectedResults()

    for i in inputs:
        print("Merging " + i)
        with open(i, 'r') as in_file:
            merged.merge(json.load(in_file))

    # re-process results
    merged.total_guards = Collector.set_total_branch_count(binary)
    merged.set_order()
    merged.collect_statistics()

    with open(output, 'w') as out_file:
        json.dump(merged, out_file, indent=2, cls=SaneJSONEncoder)


def minimize_report(input_, output):
    results = CollectedResults()

    print("Loading")
    with open(input_, 'r') as in_file:
        data = json.load(in_file)

    print("Processing data")
    results.load(data)
    results.set_order()

    results.minimize_sequences()
    results.minimize_accessed_addresses()

    print("Storing")
    with open(output, 'w') as out_file:
        json.dump(results, out_file, indent=2, cls=SaneJSONEncoder)


# ===============================
# Aggregation and Symbolization
# ===============================
class Symbolizer:
    def __init__(self, path, binary):
        self.path = path
        self.binary = binary
        self.process = None

    def start(self):
        self.process = subprocess.Popen([self.path,
                                         "-obj=" + self.binary, "-functions=none"],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=1)

    def stop(self):
        self.process.communicate(b"n\n")
        self.process.kill()

    def symbolize_one(self, address: str) -> List[str]:
        self.process.stdin.write((address + "\n").encode('utf-8'))
        self.process.stdin.flush()
        result = []
        while True:
            line_ = self.process.stdout.readline()
            if line_ == b"\n":
                break
            result.append(line_.decode()[:-1])
        return result


class SymbolizedFault:
    location: List[str]
    faults: List

    # aggregated data
    accessed_addresses: Set[int]
    offsets: Set[int]
    fault_counts: List[int]
    controlled: bool = False
    controlled_offset: bool = False
    branches: Dict[int, Tuple[int, str]]
    types: Set[int]
    order: int = 1000

    def __init__(self, locations):
        self.location = locations
        self.faults = []
        self.accessed_addresses = set()
        self.offsets = set()
        self.fault_counts = []
        self.branches = {}
        self.types = set()

    def __lt__(self, other: 'SymbolizedFault'):
        return self.location[0] < other.location[0]

    def get_dict(self) -> Dict:
        return {
            "location": self.get_location(),
            "faults": self.faults,
            "accessed_addresses": list(self.accessed_addresses),
            "offsets": list(self.offsets),
            "fault_counts": self.fault_counts,
            "controlled": self.controlled,
            "controlled_offset": self.controlled_offset,
            "types": list(self.types),
            "order": self.order,
        }

    def load(self, data: Dict):
        self.location = data["location"].split(" < ")
        self.faults = data["faults"]
        self.accessed_addresses = set([int(i) for i in data["accessed_addresses"]])
        self.offsets = set([int(i) for i in data["offsets"]])
        self.fault_counts = [int(i) for i in data["fault_counts"]]
        self.controlled = bool(data["controlled"])
        self.controlled_offset = bool(data["controlled_offset"])
        self.types = set([int(i) for i in data["types"]])
        self.order = int(data["order"])

    def get_location(self) -> str:
        return " < ".join(self.location)

    def aggregate(self):
        for f in self.faults:
            for i in f["accessed_addresses"]:
                self.accessed_addresses.add(i)
            for i in f["offsets"]:
                self.offsets.add(i)
            for i in f["types"]:
                self.types.add(i)
            self.fault_counts.append(f["fault_count"])
            self.controlled |= f["controlled"]
            self.controlled_offset |= f["controlled_offset"]
            self.order = f["order"] if f["order"] < self.order else self.order


class SymbolizedBranch:
    location: List[str]
    branches: List

    # aggregated data
    symbolized_faults: Set[str]
    fault_counts: List[int]
    nonspeculative_execution_counts: List[int]

    def __init__(self, locations):
        self.location = locations
        self.branches = []
        self.symbolized_faults = set()
        self.fault_counts = []
        self.nonspeculative_execution_counts = []

    def __lt__(self, other: 'SymbolizedBranch'):
        return self.location[0] < other.location[0]

    def get_dict(self):
        return {
            "location": self.get_location(),
            "branches": self.branches,
            "symbolized_faults": list(self.symbolized_faults),
            "fault_counts": self.fault_counts,
            "nonspeculative_execution_counts": self.nonspeculative_execution_counts
        }

    def load(self, data):
        self.location = data["location"].split(" < ")
        self.branches = data["branches"]
        self.symbolized_faults = data["symbolized_faults"]
        self.fault_counts = [int(c) for c in data["fault_counts"]]
        self.nonspeculative_execution_counts = \
            [int(c) for c in data["nonspeculative_execution_counts"]]

    def get_location(self) -> str:
        return " < ".join(self.location)

    def aggregate(self, symbolizer: Symbolizer):
        for b in self.branches:
            self.fault_counts.append(b["fault_count"])
            self.nonspeculative_execution_counts.append(b["nonspeculative_execution_count"])
            for fault_address in b["faults"]:
                self.symbolized_faults.add(symbolizer.symbolize_one(fault_address)[0])


class SymbolizedResults:
    branches: Dict[str, SymbolizedBranch]
    faults: Dict[str, SymbolizedFault]

    def __init__(self):
        self.branches = {}
        self.faults = {}
        self.statistics = {}

    def get_dict(self):
        return {
            "branches": self.branches,
            "faults": self.faults,
        }

    def add_branch(self, key: str, locations: List[str], serialized_branch_data: Dict):
        symbolized_branch = self.branches.setdefault(key, SymbolizedBranch(locations))
        symbolized_branch.branches.append(serialized_branch_data)

    def add_fault(self, key: str, locations: List[str], serialized_fault_data: Dict):
        symbolized_fault = self.faults.setdefault(key, SymbolizedFault(locations))
        symbolized_fault.faults.append(serialized_fault_data)

    def load(self, results_json: Dict):
        for key, data in results_json["branches"].items():
            branch = SymbolizedBranch([])
            branch.load(data)
            self.branches[key] = branch

        for key, data in results_json["faults"].items():
            fault = SymbolizedFault([])
            fault.load(data)
            self.faults[key] = fault


def build_aggregated_report(input_, output, symbolizer_path, binary, consider_callsite=False):
    def get_key(address):
        l = symbolizer.symbolize_one(address)
        if consider_callsite:
            k = "<".join(l)
        else:
            k = l[0]

        if "asan" in k or "sanitizer" in k:
            raise RuntimeError(
                "Detected an exception in ASan runtime library: " + k + " at " + address)

        return k, l

    results = SymbolizedResults()

    print("Loading data")
    with open(input_, 'r') as in_file:
        data = json.load(in_file)
        faults = data["faults"]
        branches = data["branches"]

    symbolizer = Symbolizer(symbolizer_path, binary)
    symbolizer.start()

    print("Symbolizing faults")
    for f in faults.values():
        key, locations = get_key(f["address"])
        if key:
            results.add_fault(key, locations, f)

    print("Symbolizing branches")
    for b in branches.values():
        key, locations = get_key(b["address"])
        if key:
            results.add_branch(key, locations, b)

    print("Aggregating")
    for f in results.faults.values():
        f.aggregate()

    for b in results.branches.values():
        b.aggregate(symbolizer)

    symbolizer.stop()

    print("Storing")
    with open(output, 'w') as out_file:
        json.dump(results, out_file, indent=2, cls=SaneJSONEncoder)


# ====================
# Querying
# ====================

class Query:
    faults: Dict
    branches: Dict
    fault_index: List[str]
    branch_index: List[str]
    results: SymbolizedResults

    def __init__(self, input_file, args):
        self.args = args

        print("Loading data...")
        with open(input_file, 'r') as in_file:
            data = json.load(in_file)
            self.faults = data["faults"]
            self.branches = data["branches"]

        self.fault_index = [i for i in self.faults]
        self.branch_index = [i for i in self.branches]

        # TODO: this is duplication. Merge with the first part of the function
        self.results = SymbolizedResults()
        self.results.load(data)

    def execute(self):
        if not self.args.output:
            print("Output file does not exist or not a file")
            exit(1)

        # Only simple whitelist so far
        # TODO: More in the future
        whitelist = self.build_whitelist()
        with open(self.args.output, 'w') as f:
            for branch in whitelist:
                f.write(branch + "\n")

    def start(self):
        msg = "\n*** Commands ***\n" \
              "  l: location  s: stats\n" \
              "  q: quit\n" \
              "\033[94mWhat now>\033[0m "
        while True:
            c = input(msg)
            if c == "l":
                while True:
                    location = input("\n\033[94mEnter location>>\033[0m ")
                    if location == "" or location == "q":
                        break
                    if len(location) < 3:
                        continue
                    else:
                        self.get_details(location)
            elif c == "s":
                print("Under construction.")
            elif c == "q":
                print("Bye.")
                break
            else:
                print("Huh (%s)?" % c)

    def get_details(self, location: str):
        matching_faults = [i for i in self.fault_index if location in i]
        matching_branches = [i for i in self.branch_index if location in i]
        if not matching_faults and not matching_branches:
            print("Location not found")
            return

        if len(matching_faults) == 1 and not matching_branches:
            self.print_fault(self.faults[matching_faults[0]])
            return

        if len(matching_branches) == 1 and not matching_faults:
            self.print_branch(self.branches[matching_branches[0]])
            return

        # several found
        print("Found several matches:")
        print(" Faults:")
        for i, l in enumerate(matching_faults):
            print("  f{}: {}".format(i, l))
        print(" Branches:")
        for i, l in enumerate(matching_branches):
            print("  b{}: {}".format(i, l))

        c = input("\033[94mEnter match id>>>\033[0m ")
        try:
            type_ = c[0]
            id_ = int(c[1:])
            if type_ == "f":
                self.print_fault(self.faults[matching_faults[id_]])
            elif type_ == "b":
                self.print_branch(self.branches[matching_branches[id_]])
            else:
                raise ValueError
        except (ValueError, IndexError):
            print("No such id")

    # Helper functions
    @staticmethod
    def print_fault(fault):
        fault["faults"] = []

        show_first = 5
        if len(fault["accessed_addresses"]) > show_first:
            length = len(fault["accessed_addresses"]) - show_first
            fault["accessed_addresses"] = "{} + {} more" \
                .format(", ".join([hex(i) for i in fault["accessed_addresses"][:show_first]]),
                        length)
        else:
            fault["accessed_addresses"] = ",".join([hex(i) for i in fault["accessed_addresses"]])
        print("Type: fault")
        pprint(fault)

        main_location = fault["location"].split("<")
        fname, line, column = main_location[0].split(":")
        if line == "0":
            return

        # TODO: are there any libraries for do this?
        print("\nCode:")
        try:
            with open(fname) as f:
                lines = f.readlines()
                line = int(line) - 1
                print("  {} {}".format(line - 2, lines[line - 3][:-1]))
                print("  {} {}".format(line - 1, lines[line - 2][:-1]))
                print("  {} {}".format(line, lines[line - 1][:-1]))
                print("\033[92m  {} {}\033[0m".format(line + 1, lines[line][:-1]))
                print("  {} {}".format(line + 2, lines[line + 1][:-1]))
                print("  {} {}".format(line + 3, lines[line + 2][:-1]))
                print("  {} {}".format(line + 4, lines[line + 3][:-1]))
                print("  {} {}".format(line + 5, lines[line + 4][:-1]))
                print("  {} {}".format(line + 6, lines[line + 5][:-1]))
        except EnvironmentError:
            print("Error opening the file")

    @staticmethod
    def print_branch(branch):
        branch["branches"] = []
        print("Type: branch")
        pprint(branch)

    def build_whitelist(self, exec_threshold: int = 100, fault_threshold: int = 100,
                        include_controlled_offset: bool = True,
                        include_uncontrolled: bool = False):
        blacklist: List[str] = []

        # build a list of all branches with too few executions (or no executions)
        not_covered_branches = []
        branch_locations = {}
        for location, branch in self.results.branches.items():
            for branch_in_binary in branch.branches:
                branch_locations[branch_in_binary["address"]] = location
                if branch_in_binary["nonspeculative_execution_count"] < exec_threshold:
                    not_covered_branches.append(branch_in_binary["address"])
        blacklist += not_covered_branches

        # build a list of faults to consider
        fault_list: List[str] = []
        for key, fault in self.results.faults.items():
            # we unconditionally include those faults that change the control flow
            if 2 in fault.types:
                fault_list.append(key)
                continue

            # controlled offset
            if include_controlled_offset and fault.controlled_offset:
                fault_list.append(key)
                continue

            # controlled
            if fault.controlled:
                fault_list.append(key)
                continue

            # not enough data to call it uncontrolled
            if min(fault.fault_counts) < fault_threshold:
                fault_list.append(key)
                continue

            # uncontrolled
            if include_uncontrolled and not fault.controlled and not fault.controlled_offset:
                fault_list.append(key)
                continue

        # build a list of all branch sequences that have to be patched
        all_sequences_set: Set[Tuple[str]] = set()
        for key in fault_list:
            raw_faults = self.results.faults[key].faults
            for f in raw_faults:
                for sequence in f["branch_sequences"]:
                    all_sequences_set.add(tuple(sequence))

        # removed the sequences that are already covered by non-tested branches
        # (those are always patched)
        all_sequences: List[Tuple[str]] = list(all_sequences_set)
        for sequence in all_sequences:
            for branch in not_covered_branches:
                if branch in sequence:
                    all_sequences_set.remove(sequence)
                    break

        # build a map of which branches cover which sequences
        # e.g., for [(A), (A, B), (B)], A covers 1 and 2, B covers 2 and 3
        all_sequences = list(all_sequences_set)
        branch_map: Dict[int] = {}
        for index, sequence in enumerate(all_sequences):
            for branch in sequence:
                map_entry = branch_map.setdefault(branch, [])
                map_entry.append(index)

        # convert the map into a list for later processing
        unprocessed_branches = []
        for branch, value in branch_map.items():
            unprocessed_branches.append((branch, value))

        # keep popping out the branches with the largest coverage until we reach full coverage
        while len(unprocessed_branches) > 0:
            unprocessed_branches.sort(key=lambda x: len(x[1]))
            top = unprocessed_branches.pop()
            blacklist.append(top[0])
            for branch in unprocessed_branches[:]:
                for index in top[1]:
                    if index in branch[1]:
                        branch[1].remove(index)
                        if len(branch[1]) == 0:
                            unprocessed_branches.remove(branch)

        blacklist_locations = set()
        for b in blacklist:
            if b not in branch_locations:
                print("Not found: " + b)
                continue
            blacklist_locations.add(branch_locations[b])

        whitelist = []
        for branch in self.results.branches:
            if branch not in blacklist_locations:
                whitelist.append(branch)

        return sorted(whitelist)


def main():
    parser = ArgumentParser(description='', add_help=False)
    subparsers = parser.add_subparsers(help='sub-command help', dest='subparser_name')

    # Data collection
    parser_collect = subparsers.add_parser('collect')
    parser_collect.add_argument(
        '-r', '--hongg-report',
        type=str,
        required=True,
    )
    parser_collect.add_argument(
        "-o", "--output",
        type=str,
        required=True
    )
    parser_collect.add_argument(
        "-b", "--binary",
        type=str,
        required=True
    )
    parser_collect.add_argument(
        "-m", "--main-branch",
        type=str,
        choices=["first", "last"],
        default="first"
    )

    parser_merge = subparsers.add_parser('merge')
    parser_merge.add_argument(
        "inputs",
        type=str,
        nargs="+"
    )
    parser_merge.add_argument(
        "-o", "--output",
        type=str,
        required=True
    )
    parser_merge.add_argument(
        "-b", "--binary",
        type=str,
        required=True
    )

    parser_minimize = subparsers.add_parser('minimize')
    parser_minimize.add_argument(
        "input",
        type=str,
    )
    parser_minimize.add_argument(
        "-o", "--output",
        type=str,
        required=True
    )

    # Aggregation
    parser_aggregate = subparsers.add_parser('aggregate')
    parser_aggregate.add_argument(
        "input",
        type=str,
    )
    parser_aggregate.add_argument(
        "-o", "--output",
        type=str,
        required=True
    )
    parser_aggregate.add_argument(
        "-s", "--symbolizer",
        type=str,
        required=True
    )
    parser_aggregate.add_argument(
        "-b", "--binary",
        type=str,
        required=True
    )
    parser_aggregate.add_argument(
        "-c", "--consider-callsite",
        action='store_true',
    )

    # Query
    # parser for comparing reports
    parser_query = subparsers.add_parser('query')
    parser_query.add_argument(
        "input",
        type=str,
    )
    parser_query.add_argument(
        "-i", "--interactive",
        action='store_true'
    )
    parser_query.add_argument(
        "-o", "--output",
        type=str,
    )

    args = parser.parse_args()

    # now, do the actual analysis
    if args.subparser_name == "collect":
        collector = Collector()
        collector.collect_data(args.output, args.hongg_report, args.binary, args.main_branch)
    elif args.subparser_name == "merge":
        merge_reports(args.inputs, args.output, args.binary)
    elif args.subparser_name == "minimize":
        minimize_report(args.input, args.output)

    elif args.subparser_name == "aggregate":
        build_aggregated_report(args.input, args.output, args.symbolizer, args.binary,
                                args.consider_callsite)

    elif args.subparser_name == "query":
        query = Query(args.input, args)
        if args.interactive:
            query.start()
        else:
            query.execute()


if __name__ == '__main__':
    main()
