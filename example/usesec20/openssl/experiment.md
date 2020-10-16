For this benchmark, it's better to put the Makefile somewhere outside the OpenSSL source code directory. You would need to change the `LIB_DIR` variable to point to this source code directory. 

Also, don't forget to replace the original OpenSSL fuzzing driver (`fuzz/driver.c`) with our version.

All the next steps are the same as for the other benchmarks.

---

When building for the first time, collect a function list:

```shell script
make sf SF_COLLECT=1
make clean
```

Build fuzzer:

```shell script
make sf
```

Fuzzing:

```shell script
honggfuzz  --run_time 3600 --exit_upon_crash -Q --no_fb_timeout 1 --timeout 120 -n 1 -f openssl-corpus/ -l hongg.log -- ./sf ___FILE___ 2>&1 | analyzer collect -r hongg.log -o analyzer.json -b sf >errors.log 2>&1
```

Build a whitelist:

```shell script
analyzer minimize analyzer.json -o minimal.json
analyzer aggregate minimal.json -s $(llvm-7.0.1-config --sfdir)/llvm-symbolizer -b ./sf -o aggregated.json
analyzer query aggregated.json -o whitelist.txt
```

Build a patched binary:

```shell script
make patched PERF=1
```

Performance:

```shell script
./patched speed -multi 4 rsa dsa ecdsa
```
