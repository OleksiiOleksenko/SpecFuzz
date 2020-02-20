#!/usr/bin/bats

export CLANG_DIR=$(llvm-7.0.1-config --bindir)
export RTFLAGS="-lspecfuzz -L$CLANG_DIR/../lib"

msg () {
    echo "[BATS] " $*
}

setup () {
    make clean
}

teardown() {
    make clean
}

function asm_test {
    CC=clang make ${NAME}
    run bash -c "./${NAME} 2>&1"
    if [ "$status" -ne 0 ]; then
        echo "status: $status"
        printf "output: $output\n"
        echo "  output end"
    fi
}

@test "[$BATS_TEST_NUMBER] Acceptance: The pass is enabled and compiles correctly" {
    NAME=dummy
    CC=clang-sf make ${NAME}
    run bash -c "./${NAME}"
    [ "$status" -eq 0 ]
    [ "$output" = "[SF] Starting
Hello World!" ]
}

@test "[$BATS_TEST_NUMBER] Acceptance: Detection of a speculative overflow with ASan" {
    NAME=acceptance-basic
    CC=clang-sf make ${NAME}
    run bash -c "ASAN_OPTIONS=allow_user_segv_handler=1:detect_leaks=0 ./${NAME} 100"
    [ "$status" -eq 0 ]
    [[ "$output" == *"[SF], 1,"* ]]
}

@test "[$BATS_TEST_NUMBER] Acceptance: Detection of a speculative overflow with signal handler" {
    NAME=acceptance-basic
    CC=clang-sf make ${NAME}
    run bash -c "ASAN_OPTIONS=allow_user_segv_handler=1:detect_leaks=0 ./${NAME} 1000000000"
    [ "$status" -eq 0 ]
    [[ "$output" == *"[SF], 11,"* ]]
}

@test "[$BATS_TEST_NUMBER] Acceptance: mmul" {
    NAME=acceptance-mmul

    CC=clang make ${NAME}
    run bash -c "./${NAME}"
    [ "$status" -eq 0 ]
    [[ "$output" == *"70" ]]

    CC=clang-sf make ${NAME}
    run bash -c "./${NAME}"
    [ "$status" -eq 0 ]
    [[ "$output" == *"70" ]]

    CC=clang-sf CFLAGS="-O1" make ${NAME}
    run bash -c "./${NAME}"
    [ "$status" -eq 0 ]
    [[ "$output" == *"70" ]]

    CC=clang-sf CFLAGS="-O2" make ${NAME}
    run bash -c "./${NAME}"
    [ "$status" -eq 0 ]
    [[ "$output" == *"70" ]]

    CC=clang-sf CFLAGS="-O3" make ${NAME}
    run bash -c "./${NAME}"
    [ "$status" -eq 0 ]
    [[ "$output" == *"70" ]]
}

@test "[$BATS_TEST_NUMBER] Runtime: Checkpointing function does not introduce corruptions" {
    NAME=rtl_chkp
    asm_test
    [ "$status" -eq 0 ]
}

@test "[$BATS_TEST_NUMBER] Runtime: Rollback function does not introduce corruptions" {
    NAME=rtl_rlbk
    asm_test
    [ "$status" -eq 0 ]
}

@test "[$BATS_TEST_NUMBER] Runtime: Rollback functions correctly" {
    NAME=rtl_chkp_rlbk
    asm_test
    [ "$status" -eq 0 ]
}

@test "[$BATS_TEST_NUMBER] Runtime: Reporting does not introduce corruptions" {
    NAME=rtl_report
    asm_test
    [ "$status" -eq 0 ]
}

@test "[$BATS_TEST_NUMBER] Runtime: Reporting functions correctly" {
    NAME=rtl_report
    asm_test
    [[ "${lines[1]}" == "[SF], 1, 0x29, 0x29, 0, "* ]] || [[ "${lines[1]}" == "[SF], 1, 0x29, 0x0, -8, "* ]]
}

@test "[$BATS_TEST_NUMBER] Wrapper: mmul compiled with a wrapper script" {
    NAME=acceptance-mmul
    CC=clang-sf CFLAGS=" --disable-asan -O3 -ggdb" make ${NAME}
    run bash -c "./${NAME}"
    [ "$status" -eq 0 ]
    [[ "$output" == *"70" ]]
}

@test "[$BATS_TEST_NUMBER] Wrapper: mmul compiled with a c++ wrapper script" {
    NAME=acceptance-mmul
    CC=clang-sf++ CFLAGS=" --disable-asan -O3 -ggdb" make ${NAME}
    run bash -c "./${NAME}"
    [ "$status" -eq 0 ]
    [[ "$output" == *"70" ]]
}

@test "[$BATS_TEST_NUMBER] Pass: Collecting functions" {
    NAME=dummy
    CC=clang-sf CFLAGS=" --collect list.txt --disable-asan -O3 -ggdb" make ${NAME}
    uniq list.txt | sort > t && mv t list.txt
    run cat list.txt
    [ "$output" == "main" ]
    rm list.txt
}

@test "[$BATS_TEST_NUMBER] Analyzer: Unit tests" {
    run bash -c "python3 -m unittest -v analyzer_unit"
    if [ "$status" -ne 0 ]; then
        printf "$output\n"
    fi
    [ "$status" -eq 0 ]
}


# Below are our old tests. They probably won't work anymore

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
