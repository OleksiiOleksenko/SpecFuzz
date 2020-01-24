#!/usr/bin/env bash
# TODO: this script is in a dire need of documentation

set -e

LLVM_CONFIG=${LLVM_CONFIG:-"llvm-7.0.1-config"}
CLANG_BINDIR=$(${LLVM_CONFIG} --bindir)

CC=${CLANG_BINDIR}/clang
LLC=${CLANG_BINDIR}/llc

# make sure that external varables do not corrupt our compilation
CFLAGS=""
LDFLAGS=""
LANGUAGE=""
GGDB=""
I=""
INPUT=""
OUTPUT=""
OPT=""

# configure the compiler
LLCFLAGS="-x86-specfuzz -disable-tail-calls"
ASAN_CFLAGS="-fsanitize=address -mllvm -asan-instrumentation-with-call-threshold=0 -mllvm -asan-use-after-scope=0 "
ASAN_LDFLAGS="-fsanitize=address"
COVERAGE_FLAGS=""

flag_coverage_only=0
flag_coverage=0
flag_collect=0
flag_function_list=0
flag_branch_list=0
flag_serialization_list=0

while [ "$#" -gt 0 ]; do
    case $1 in
        -o)
            if (($# > 1)); then
                OUTPUT=$2
                if [ "$2" == "/dev/null" ]; then
                    DEVNULL=1
                fi
                shift
            fi
        ;;
        *.c|*.cc|*.cpp|-)
            INPUT="$INPUT $1"
            SOURCE=1
        ;;
        *.o|*.s|*.S|*.a)
            INPUT="$INPUT $1"
        ;;
        -x)
            LANGUAGE="$1 $2"
            if [ "$2" == "assembler" ]; then
                ASM=1
            fi
            shift
        ;;
        -c)
            CFLAGS="$CFLAGS $1"
            CREATE_OBJECT=1
        ;;
        -I|-include|-isystem)
            I="$I $1 $2"
            shift
        ;;
        -I*)
            I="$I $1"
        ;;
        -ggdb*|-g)
            GGDB="-g -gcolumn-info"
        ;;
        -O?)
            CFLAGS="$CFLAGS $1"
            OPT="$1"
        ;;
        -S)
            CREATE_ASM=1
        ;;
        --collect)
            if [ $flag_collect == 0 ]; then
                if [ ! -f $2 ]; then
                    touch $2
                fi
                LLCFLAGS+=" -x86-specfuzz-collect-functions-into=$2"
                flag_collect=1
            fi
            shift
        ;;
        --function-list)
            if [ $flag_function_list == 0 ]; then
                LLCFLAGS+=" -x86-specfuzz-function-list=$2"
                flag_function_list=1
            fi
            shift
        ;;
        --branch-list)
            if [ $flag_branch_list == 0 ]; then
                LLCFLAGS+=" -x86-specfuzz-branch-list=$2"
                flag_branch_list=1
            fi
            shift
        ;;
        --serialization-list)
            if [ $flag_serialization_list == 0 ]; then
                LLCFLAGS+=" -x86-specfuzz-serialization-list=$2"
                flag_serialization_list=1
            fi
            shift
        ;;
        --echo)
            ECHO=1
        ;;
        --debug-pass)
            LLCFLAGS+=" -debug-only=x86-specfuzz"
        ;;
        --no-wrapper-cleanup)
            NO_CLEANUP=1
        ;;
        --disable-asan)
            ASAN_CFLAGS=
            ASAN_LDFLAGS=
        ;;
        --enable-coverage)
            if [ $flag_coverage == 0 ]; then
                ASAN_CFLAGS="$ASAN_CFLAGS $COVERAGE_FLAGS"
                ASAN_LDFLAGS="$ASAN_LDFLAGS $COVERAGE_FLAGS"
                flag_coverage=1
            fi
            shift
        ;;
        --coverage-only)
            if [ $flag_coverage_only == 0 ]; then
                ASAN_CFLAGS="$ASAN_CFLAGS $COVERAGE_FLAGS"
                ASAN_LDFLAGS="$ASAN_LDFLAGS $COVERAGE_FLAGS"
                LLCFLAGS+=" -x86-specfuzz-coverage-only"
                flag_coverage_only=1
            fi
            shift
        ;;
        -V|-v|-qversion)
            $CC -v
            exit $?
        ;;
        *)
            if [ -z "$OUTPUT" ]; then
                CFLAGS="$CFLAGS $1"
            else
                LDFLAGS="$LDFLAGS $1"
            fi
        ;;
    esac
    shift
done

if [ -z "$INPUT" ]; then
    echo "clang-sf: error: no input files"
    exit 1
fi

if [ -z "$OUTPUT" ]; then
    if [ $CREATE_OBJECT ]; then
        OUTPUT=$(basename ${INPUT%.c*}.o)
    else
        OUTPUT="a.out"
    fi
fi

CFLAGS="$CFLAGS -mno-red-zone"
CFLAGS="$CFLAGS -mno-avx -mno-avx2 "


if ! [ $CREATE_OBJECT ]; then
    LDFLAGS="$LDFLAGS -rdynamic -lspecfuzz"
fi

if [ -n "$SOURCE" ] && [ -z "$ASM" ] && [ -z "$DEVNULL" ]; then
    cmd=( $CC $ASAN_CFLAGS $CFLAGS $GGDB $I $LANGUAGE -c -emit-llvm $INPUT -o ${OUTPUT%.o}.bc )
    if [ -n "$ECHO" ]; then echo "${cmd[@]}"; fi
    "${cmd[@]}"

    cmd=( $LLC $LLCFLAGS $OPT ${OUTPUT%.o}.bc -o ${OUTPUT%.o}.s )
    if [ -n "$ECHO" ]; then echo "${cmd[@]}"; fi
    "${cmd[@]}"
    if [ -z "$NO_CLEANUP" ]; then rm ${OUTPUT%.o}.bc; fi

    if [ -z "$CREATE_ASM" ]; then
        cmd=( $CC -Wno-unused-command-line-argument $CFLAGS $ASAN_LDFLAGS ${OUTPUT%.o}.s -o $OUTPUT $LDFLAGS )
        if [ -n "$ECHO" ]; then echo "${cmd[@]}"; fi
        "${cmd[@]}"
    else
        cp ${OUTPUT%.o}.s ${OUTPUT%.o}
    fi

    if [ -z "$NO_CLEANUP" ]; then rm ${OUTPUT%.o}.s; fi
    if [ -n "$ECHO" ]; then echo "==========================================================="; fi
else
    if [ -z "$SOURCE" ]; then
        I=
    fi

    cmd=( $CC $ASAN_LDFLAGS $CFLAGS $GGDB $I $LANGUAGE $INPUT -o $OUTPUT $LDFLAGS )
    if [ -n "$ECHO" ]; then echo "${cmd[@]}"; fi
    "${cmd[@]}"
fi
