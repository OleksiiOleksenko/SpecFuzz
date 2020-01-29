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
make
make install
$ HONGG_SRC=/honggfuzz/installation/directory/src/ make install_tools
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
[SF], 1, 0x52b556, 0x0, -8, 0x52b519
r = 0
```
Here, the line `[SF], 1, 0x52b556, 0x0, -8, 0x52b519` means that SpecFuzz detected that instruction
at address `0x52b556` tried to access an invalid address `0x52b519` which was 8 bytes left from
a nearest valid object.

# Testing
Tests depend on bats ([Install bats](https://github.com/sstephenson/bats/wiki/Install-Bats-Using-a-Package)).
```bash
$ cd tests
$ ./run.sh
```
