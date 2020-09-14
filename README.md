# SpecFuzz
A tool to enable fuzzing for Spectre vulnerabilities. See our [Technical Report](https://arxiv.org/abs/1905.10311) for details.

# Have trouble using the tool? Open an issue!
The tool is relatively new and you might have trouble when installing or using it. If so, do not hesitate to open an issue.

# Getting started

## Dependencies
* Python 3.6+: [Install Python](https://www.python.org/downloads/)
* Cmake: [Install CMake](https://cmake.org/install/)
* LLVM 7.0.1., built from sources:
```bash
$ INSTALL_DIR=/llvm/installation/directory/ ./install/llvm.sh
$ /llvm/installation/directory/clang -v
clang version 7.0.1 (tags/RELEASE_701/final)
...
```
* HonggFuzz, built from sources:
```bash
$ apt-get install -y libbfd-dev libunwind8-dev binutils-dev libblocksruntime-dev
$ INSTALL_DIR=/honggfuzz/installation/directory/ ./install/honggfuzz.sh
$ honggfuzz
Usage: honggfuzz [options] -- path_to_command [args]
Options:
...
```
## Build it
```bash
$ make
$ export HONGG_SRC=/honggfuzz/installation/directory/src/
$ make install
$ make install_tools
```
## Try it
Build a sample vulnerable program:
```bash
$ cd example
$ make sf
clang-sf -fsanitize=address -O1 demo.c -c -o main.sf.o
clang-sf -fsanitize=address -O1 sizes.c -c -o sizes.sf.o
clang-sf -fsanitize=address -O1 main.sf.o sizes.sf.o -o demo-sf
```
Try running it:
```bash
$ ./demo-sf 11
[SF] Starting
[SF], 1, 0x123, 0x456, 0, 0x789
r = 0
```
Here, the line `[SF], 1, 0x123, 0x456, 0, 0x789` means that SpecFuzz detected that the instruction
at address `0x123` tried to access an invalid address `0x456`, and the speculation was triggered
by a misprediction of a branch at the address `0x789`.
## Fuzz it
Build a fuzzing driver:
```bash
$ cd example
$ export HONGG_SRC=/honggfuzz/installation/directory/src/
$ make fuzz
```
Fuzzing:
```bash
$ honggfuzz --run_time 10 -Q -n 1 -f ./ -l fuzzing.log -- ./fuzz ___FILE___ 2>&1 | analyzer collect -r fuzzing.log -o results.json -b ./fuzz
$ cat results.json   # raw results of fuzzing
{
  "errors": [],
  "statistics": {
    "coverage": [
      75.0,
      6
    ],
    "branches": 6,
    "faults": 1
  },
  "branches": {
    "5443896": {
      "address": "0x531138",
      "faults": [
        "0x530a48"
```

**Important**: fuzz only on a single thread (`-n 1`). In the current implementation, the detected errors are reported into `stderr` and the analyzer cannot correctly separate results from different threads.

Process the results:
```bash
$ analyzer aggregate results.json -s $(llvm-7.0.1-config --bindir)/llvm-symbolizer -b ./fuzz -o aggregated.json
```
The final, aggregated results are in `aggregated.json`.

# Development

## Testing
Tests depend on bats ([Install bats](https://github.com/sstephenson/bats/wiki/Install-Bats-Using-a-Package)).
```bash
$ cd tests
$ ./run.sh
```


# Cite us!

Paper:

```
@InProceedings{Oleksenko:2020,
  author={Oleksenko, Oleksii and Trach, Bohdan and Silberstein, Mark and Fetzer, Christof},
  title={{SpecFuzz: Bringing Spectre-type vulnerabilities to the surface}},
  booktitle={29th $\{$USENIX$\}$ Security Symposium ($\{$USENIX$\}$ Security)},
  year={2020}
}
```

Technical Report:

```
@Article{Oleksenko:2019,
  author={Oleksenko, Oleksii and Trach, Bohdan and Silberstein, Mark and Fetzer, Christof},
  title={{SpecFuzz: Bringing Spectre-type vulnerabilities to the surface}},
  journal = "",
  archivePrefix = "arXiv",
  eprint = {1905.10311},
  primaryClass = "",
  year = {2019},
}
```
