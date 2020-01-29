#!/usr/bin/bats

export CLANG_DIR=$(llvm-7.0.1-config --bindir)
export RTFLAGS="-lspecfuzz -L$CLANG_DIR/../lib"

msg () {
    echo "[BATS] " $*
}

setupOnce () {
    echo "start"
}

setup () {
    make clean
}

teardown() {
    make clean
}


@test "[$BATS_TEST_NUMBER] RTL: Checkpointing function does not introduce corruptions" {
    NAME=rtl_chkp
    make ${NAME}
    run bash -c "./${NAME}"
    [ "$status" -eq 0 ]
    rm ${NAME}
}

@test "[$BATS_TEST_NUMBER] RTL: Rollback functions correctly" {
    NAME=rtl_chkp_rlbk
    make ${NAME}
    run bash -c "./${NAME}"
    [ "$status" -eq 0 ]
    rm ${NAME}
}


# Below are our old tests. They probably won't work anymore

#@test "[$BATS_TEST_NUMBER] The pass is enabled and compiles correctly" {
#    make dummy.bc
#    run bash -c "$CLANG_DIR/llc dummy.bc -x86-specfuzz -debug-only=x86-specfuzz -o dummy.s"
#    [ "$status" -eq 0 ]
#    [[ "$output" == *"SpecFuzz"* ]]
#
#    $CLANG_DIR/clang dummy.s -o dummy -lspecfuzz
#    run ./dummy
#    [ "$status" -eq 0 ]
#    [ "$output" = "[SF] Starting
#Hello World!" ]
#    rm dummy
#}
#
#@test "[$BATS_TEST_NUMBER] Instruction counter is constantly incremented" {
#    NAME="instruction_counter"
#    make ${NAME}.s
#    run bash -c "$CLANG_DIR/FileCheck ${NAME}.ll --input-file=${NAME}.s"
#    [ "$status" -eq 0 ]
#
#    make ${NAME}
#    run bash -c "./${NAME}"
#    [ "$output" = "[SF] Starting
#Counter: -8" ]
#    rm ${NAME}
#}
#
#@test "[$BATS_TEST_NUMBER] Instrumentation of simple comparisons" {
#    NAME="comparison"
#    make ${NAME}.s
#    run bash -c "$CLANG_DIR/FileCheck ${NAME}.ll --input-file=${NAME}.s"
#    [ "$status" -eq 0 ]
#}
#
#@test "[$BATS_TEST_NUMBER] Instrumentation of function calls" {
#    NAME="call"
#    make ${NAME}.s
#    run bash -c "$CLANG_DIR/FileCheck ${NAME}.ll --input-file=${NAME}.s"
#    [ "$status" -eq 0 ]
#}
#
#@test "[$BATS_TEST_NUMBER] Instrumentation of writes" {
#    NAME="memory_write"
#    make ${NAME}.s
#    run bash -c "$CLANG_DIR/FileCheck ${NAME}.ll --input-file=${NAME}.s"
#    [ "$status" -eq 0 ]
#}
#
#@test "[$BATS_TEST_NUMBER] Instrumentation of inline assembly" {
#    NAME="inline-asm-write"
#    make ${NAME}.s
#    run bash -c "$CLANG_DIR/FileCheck ${NAME}.c --input-file=${NAME}.s"
#    [ "$status" -eq 0 ]
#}
#
#@test "[$BATS_TEST_NUMBER] Simulation traverses both branches and correctly rolls back the state" {
#    make -B comparison
#    run bash -c "gdb --batch --command=comparison.gdb ./comparison > gdb.log"
#    run bash -c "$CLANG_DIR/FileCheck comparison.gdb --input-file=gdb.log"
#    [ "$status" -eq 0 ]
#    rm gdb.log
#    rm comparison
#}
#
#@test "[$BATS_TEST_NUMBER] Rollback of EFLAGS" {
#    make -B comparison
#    run bash -c "gdb --batch --command=eflags.gdb ./comparison > gdb.log"
#    run bash -c "$CLANG_DIR/FileCheck eflags.gdb --input-file=gdb.log"
#    [ "$status" -eq 0 ]
#    rm gdb.log
#    rm comparison
#}
#
#@test "[$BATS_TEST_NUMBER] Detection of a speculative overflow with ASan" {
#    make acceptance_simple_speculative_overflow ENABLE_ASAN=1 -B
#    run bash -c "ASAN_OPTIONS=allow_user_segv_handler=1:detect_leaks=0 ./acceptance_simple_speculative_overflow 100"
#    [ "$status" -eq 0 ]
#    [[ "$output" == *"[SF], 1,"* ]]
#    rm acceptance_simple_speculative_overflow
#}
#
#@test "[$BATS_TEST_NUMBER] Detection of a speculative overflow with signal handler" {
#    make acceptance_simple_speculative_overflow ENABLE_ASAN=1 -B
#    run bash -c "ASAN_OPTIONS=allow_user_segv_handler=1:detect_leaks=0 ./acceptance_simple_speculative_overflow 1000000000"
#    [ "$status" -eq 0 ]
#    [[ "$output" == *"[SF], 11,"* ]]
#    rm acceptance_simple_speculative_overflow
#}
#
#@test "[$BATS_TEST_NUMBER] Collecting functions" {
#    touch list.txt
#    make dummy.bc
#    $CLANG_DIR/llc dummy.bc -x86-specfuzz -x86-specfuzz-collect-functions-into `pwd`/list.txt -o dummy.s
#    uniq list.txt | sort > t && mv t list.txt
#    run cat list.txt
#    [ "$output" == "main" ]
#    rm list.txt
#}
#
#@test "[$BATS_TEST_NUMBER] Wrapper: mmul compiled with a wrapper script" {
#    /usr/bin/clang-sf acceptance-mmul.c -o acceptance-mmul --disable-asan
#    run bash -c "./acceptance-mmul"
#    [ "$status" -eq 0 ]
#    [[ "$output" == *"70" ]]
#    rm acceptance-mmul
#}
#
#@test "[$BATS_TEST_NUMBER] Wrapper: mmul compiled with a wrapper script, in two stages" {
#    /usr/bin/clang-sf acceptance-mmul.c -c -o acceptance-mmul.o --disable-asan
#    /usr/bin/clang-sf acceptance-mmul.o -o acceptance-mmul
#    run bash -c "./acceptance-mmul"
#    [ "$status" -eq 0 ]
#    [[ "$output" == *"70" ]]
#    rm acceptance-mmul acceptance-mmul.o
#}
#
#@test "[$BATS_TEST_NUMBER] Wrapper: mmul compiled with a wrapper script, as assembler" {
#    /usr/bin/clang-sf acceptance-mmul.c -S -c -o acceptance-mmul.s --disable-asan
#    /usr/bin/clang-sf acceptance-mmul.s -o acceptance-mmul
#    run bash -c "./acceptance-mmul"
#    [ "$status" -eq 0 ]
#    [[ "$output" == *"70" ]]
#    rm acceptance-mmul acceptance-mmul.s
#}
#
#@test "[$BATS_TEST_NUMBER] Wrapper: mmul++ compiled with a c++ wrapper script, in two stages" {
#    /usr/bin/clang-sf++ acceptance-mmul.cpp -c -o acceptance-mmul.o --disable-asan
#    /usr/bin/clang-sf++ acceptance-mmul.o -o acceptance-mmul
#    run bash -c "./acceptance-mmul"
#    [ "$status" -eq 0 ]
#    [[ "$output" == *"70" ]]
#    rm acceptance-mmul acceptance-mmul.o
#}
#
#@test "[$BATS_TEST_NUMBER] Acceptance: msum" {
#    gcc acceptance-msum.c -o acceptance-msum
#    run bash -c "./acceptance-msum"
#    [ "$status" -eq 0 ]
#    [[ "$output" == *"45" ]]
#
#    /usr/bin/clang-sf acceptance-msum.c -o ./acceptance-msum
#    run bash -c "./acceptance-msum"
#    [ "$status" -eq 0 ]
#    [[ "$output" == *"45" ]]
#
#    /usr/bin/clang-sf acceptance-msum.c -o ./acceptance-msum -O1
#    run bash -c "./acceptance-msum"
#    [ "$status" -eq 0 ]
#    [[ "$output" == *"45" ]]
#
#    /usr/bin/clang-sf acceptance-msum.c -o ./acceptance-msum -O2
#    run bash -c "./acceptance-msum"
#    [ "$status" -eq 0 ]
#    [[ "$output" == *"45" ]]
#
#    /usr/bin/clang-sf acceptance-msum.c -o ./acceptance-msum -O3
#    run bash -c "./acceptance-msum"
#    [ "$status" -eq 0 ]
#    [[ "$output" == *"45" ]]
#
#    rm acceptance-msum
#}
#
#@test "[$BATS_TEST_NUMBER] Acceptance: mmul" {
#    gcc acceptance-mmul.c -o acceptance-mmul
#    run bash -c "./acceptance-mmul"
#    [ "$status" -eq 0 ]
#    [[ "$output" == *"70" ]]
#
#    /usr/bin/clang-sf acceptance-mmul.c -o ./acceptance-mmul
#    run bash -c "./acceptance-mmul"
#    [ "$status" -eq 0 ]
#    [[ "$output" == *"70" ]]
#
#    /usr/bin/clang-sf acceptance-mmul.c -o ./acceptance-mmul -O1
#    run bash -c "./acceptance-mmul"
#    [ "$status" -eq 0 ]
#    [[ "$output" == *"70" ]]
#
#    /usr/bin/clang-sf acceptance-mmul.c -o ./acceptance-mmul -O2
#    run bash -c "./acceptance-mmul"
#    [ "$status" -eq 0 ]
#    [[ "$output" == *"70" ]]
#
#    /usr/bin/clang-sf acceptance-mmul.c -o ./acceptance-mmul -O3
#    run bash -c "./acceptance-mmul"
#    [ "$status" -eq 0 ]
#    [[ "$output" == *"70" ]]
#
#    rm acceptance-mmul
#}
#
#@test "[$BATS_TEST_NUMBER] Acceptance: msqr" {
#    gcc acceptance-msqr.c -o acceptance-msqr
#    run bash -c "./acceptance-msqr"
#    [ "$status" -eq 0 ]
#    [[ "$output" == *"126" ]]
#
#    /usr/bin/clang-sf acceptance-msqr.c -o ./acceptance-msqr
#    run bash -c "./acceptance-msqr"
#    [ "$status" -eq 0 ]
#    [[ "$output" == *"126" ]]
#
#    /usr/bin/clang-sf acceptance-msqr.c -o ./acceptance-msqr -O1
#    run bash -c "./acceptance-msqr"
#    [ "$status" -eq 0 ]
#    [[ "$output" == *"126" ]]
#
#    /usr/bin/clang-sf acceptance-msqr.c -o ./acceptance-msqr -O2
#    run bash -c "./acceptance-msqr"
#    [ "$status" -eq 0 ]
#    [[ "$output" == *"126" ]]
#
#    /usr/bin/clang-sf acceptance-msqr.c -o ./acceptance-msqr -O3
#    run bash -c "./acceptance-msqr"
#    [ "$status" -eq 0 ]
#    [[ "$output" == *"126" ]]
#
#    rm acceptance-msqr
#}
#
#@test "[$BATS_TEST_NUMBER] Analyzer: Correctly aggregates values" {
#    skip
#    touch tmp
#    data="[SF], 0, 0x1, 0x1, 10\n[SF], 0, 0x1, 0x2, 20\n[SF], 0, 0x2, 0x2, 10\n"
#    run bash -c "printf \"$data\" | analyzer coverage -c tmp -o tmp"
#    [ "$status" -eq 0 ]
#    [ "$output" == "|1 |1 |False |1 |
#|2 |1,2 |False |1 |" ]
#    rm tmp
#}
#
#@test "[$BATS_TEST_NUMBER] Analyzer: Correctly combines experiments" {
#    skip
#    touch tmp
#    experiment1="[SF] Starting\n[SF], 0, 0x1, 0x1, 10\n"
#    experiment2="[SF] Starting\n[SF], 1, 0x1, 0x1, 10\n[SF], 0, 0x2, 0x1, 10\n"
#    data="$experiment1$experiment2"
#    run bash -c "printf \"$data\" | analyzer coverage -c tmp -o tmp"
#    [ "$status" -eq 0 ]
#    echo "$output"
#    [ "$output" == "|1 |1,2 |False |2 |" ]
#    rm tmp
#}
#
#@test "[$BATS_TEST_NUMBER] Analyzer: Correctly detects control" {
#    skip
#    touch tmp
#    experiment1="[SF] Starting\n[SF], 0, 0x1, 0x1, 10\n[SF] Starting\n[SF], 1, 0x1, 0x1, 20\n[SF], 0, 0x2, 0x1, 10\n"
#    data="$experiment1"
#    run bash -c "printf \"$data\" | analyzer coverage -c tmp -o tmp"
#    [ "$status" -eq 0 ]
#    echo "$output"
#    [ "$output" == "|1 |1,2 |True |2 |" ]
#    rm tmp
#}
#
#@test "[$BATS_TEST_NUMBER] Analyzer: Detects errors" {
#    skip
#    touch tmp
#    data='[SF] Error: foo bar\n[SF], 0, a, b, 20\n[SF], 0, b, b, 10\n'
#    printf "$data" | analyzer coverage -c tmp -o tmp
#    run grep "[SF] Error: foo bar" tmp
#    [ "$status" -ne 0 ]
#    rm tmp
#}
#
#@test "[$BATS_TEST_NUMBER] Coverage: mmul" {
#    skip
#    rm a.out*
#    /usr/bin/clang-sf coverage.c  --enable-coverage
#    ASAN_OPTIONS=coverage=1 ./a.out 1
#    run bash -c "sancov -print-coverage-stats `find . -name 'a.out.*' | head -1` a.out"
#    [ "$output" == "all-edges: 10
#cov-edges: 6
#all-functions: 2
#cov-functions: 2" ]
#    rm a.out*
#}
#
#@test "[$BATS_TEST_NUMBER] Nesting: graph traversal" {
#    skip
#    ./hadouken.py tmp.c 10
#    make tmp -B
#    run bash -c "objdump -d -j .text tmp | grep \"main+\" | grep -v \"jmp\" | wc -l"
#    [ "$output" == "2047" ]
#
#    run bash -c "gdb --batch --command=hadouken.gdb --args ./tmp 5 9 2>/dev/null | awk '/tmp.c/{ c = c + 1} END{print c}'"
#    [ "$output" == "22" ]
#    rm tmp.c tmp
#}