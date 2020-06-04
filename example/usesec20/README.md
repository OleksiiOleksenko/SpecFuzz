This directory contains experiment configurations that we used in our Usenix Security'20 paper.

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


SLH: For convenience, you could use a compiler wrapper `slh-wrapper.sh` that invokes SLH with all correct flags.
To install it, do the following:

```shell script
	cp slh-wrapper.sh /usr/bin/clang-slh
	cp slh-wrapper.sh /usr/bin/clang-slh++
	sed -i -e 's:/clang$$:/clang++:g' /usr/bin/clang-slh++
```