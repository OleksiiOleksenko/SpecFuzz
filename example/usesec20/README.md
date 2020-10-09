
This directory contains experiment configurations that we used in our Usenix Security'20 paper.


To reproduce the result in the paper:
1. Pull the benchmarks' source code. Links and versions are below. It's important to checkout the correct version of the software: Otherwise the benchmark may not build with the given makefile or you will get different results.
2. Copy all the files from the corresponding subdirectory of `example/usesec20`. E.g., copy everything from `example/usesec20/brotli` into the directory with Brotli's source coe.
3. Follow the steps in the corresponding `experiment.md` file for each benchmark.


In the evaluation, we used the following versions of the software:

| Benchmark        | Version           | Fuzzing driver  | Perf. benchmark |
| ------------- |:-------------:|:-----:| ----:|
| Brotli | v1.0.7   | `fuzz/run_decode_fuzzer` | `tools/brotli` |
| JSMN | commit 18e9fe42cb | custom | custom |
| HTTP | v2.9.2     | custom | `bench.c` |
| libHTP | v0.5.30  | `test/fuzz/fuzz_htp` | `test/test_bench` |
| libYAML | v0.2.2  | custom | `tests/run-loader` |
| OpenSSL | v3.0.0  | `server` | `speed rsa ecdsa dsa` |

Sources:
* OpenSSL: https://github.com/openssl/openssl
* Brotli: https://github.com/google/brotli
* JSMN: https://github.com/zserge/jsmn
* HTTP: https://github.com/nodejs/http-parser
* libHTP: https://github.com/OISF/libhtp
* libYAML: https://github.com/yaml/libyaml

# On reproducing SLH results

For convenience, you could use a compiler wrapper `slh-wrapper.sh` that invokes SLH with all correct flags. To install it, execute the following commands from this directory:

```shell script
	cp slh-wrapper.sh /usr/bin/clang-slh
	cp slh-wrapper.sh /usr/bin/clang-slh++
	sed -i -e 's:/clang$$:/clang++:g' /usr/bin/clang-slh++
```
