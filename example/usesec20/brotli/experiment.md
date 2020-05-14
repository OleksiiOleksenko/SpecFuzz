When building for the first time, collect a function list:

```shell script
make sf SF_COLLECT=1
make clean
```

Build fuzzer:

```shell script
make sf
```

Fuzz:

```shell script
honggfuzz  --run_time 3600 --exit_upon_crash -Q --no_fb_timeout 1 --timeout 120 -n 1 -f brotli-corpus/ -l hongg.log -- ./sf ___FILE___ 2>&1 | analyzer collect -r hongg.log -o analyzer.json -b sf >errors.log 2>&1
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
./patched --decompress enwik9.br -f
``` 

Input file: http://www.mattmahoney.net/dc/textdata.html