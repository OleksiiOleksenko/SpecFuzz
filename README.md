# SpecFuzz
A tool to enable fuzzing for Spectre vulnerabilities

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
$ INSTALL_DIR=/honggfuzz/installation/directory/ ./scripts/honggfuzz.sh
$ honggfuzz
Usage: honggfuzz [options] -- path_to_command [args]
Options:
...
```
## Build SpecFuzz and tools
```bash
$ make
$ make install
$ export HONGG_SRC=/honggfuzz/installation/directory/src/
$ make install_tools
```
## Try it
Build a sample vulnerable program:
```bash
$ cd example
$ make sf
clang-sf -fsanitize=address -O1 main.c -c -o main.sf.o
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
Here, the line `[SF], 1, 0x123, 0x456, 0, 0x52b519` means that SpecFuzz detected that the instruction
at address `0x123` tried to access an invalid address `0x456`, and the speculation was triggered
by a misprediction of a branch at the address `0x789`.
# Fuzz it
Build a fuzzing driver:
```bash
$ cd example
$ export HONGG_SRC=/honggfuzz/installation/directory/src/
$ make fuzz
```
Fuzz it:
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
Process the results:
```bash
$ analyzer aggregate results.json -s $(llvm-7.0.1-config --bindir)/llvm-symbolizer -b ./fuzz -o aggregated.json
```
The final, aggregated results are in `aggregated.json`.

# Testing
Tests depend on bats ([Install bats](https://github.com/sstephenson/bats/wiki/Install-Bats-Using-a-Package)).
```bash
$ cd tests
$ ./run.sh
```
