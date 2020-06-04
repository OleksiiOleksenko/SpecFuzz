#!/usr/bin/env bash
set -e

LLVM_CONFIG=${LLVM_CONFIG:-"llvm-7.0.1-config"}
CLANG_BINDIR=$(${LLVM_CONFIG} --bindir)

CC=${CLANG_BINDIR}/clang
LLC=${CLANG_BINDIR}/llc

# make sure that external variables do not corrupt our compilation
CFLAGS=""
LDFLAGS=""
LANGUAGE=""
GGDB=""
I=""
INPUT=""
OUTPUT=""
OPT=""

# configure the compiler
LLCFLAGS="-x86-speculative-load-hardening -x86-speculative-load-hardening-indirect=false"

flag_branch_list=0
flag_load_list=0
debug=0
flag_lfence=0
flag_file_list=0

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
        -pattern-detection|-stats|-debug)
            OPTFLAGS="$OPTFLAGS $1"
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
        --echo)
            ECHO=1
        ;;
        --debug-pass)
            if [ $debug == 0 ]; then
                LLCFLAGS+=" -debug-only=x86-speculative-load-hardening -stats"
                debug=1
            fi
        ;;
        --no-wrapper-cleanup)
            NO_CLEANUP=1
        ;;
        --whitelist)
            if [ $flag_branch_list == 0 ]; then
                LLCFLAGS+=" -x86-speculative-load-hardening-whitelist-branches=$2"
                flag_branch_list=1
            fi
            shift
        ;;
        --whitelist-loads)
            if [ $flag_load_list == 0 ]; then
                LLCFLAGS+=" -x86-speculative-load-hardening-whitelist-loads=$2"
                flag_load_list=1
            fi
            shift
        ;;
        --whitelist-files)
            if [ $flag_file_list == 0 ]; then
                LLCFLAGS+=" -x86-speculative-load-hardening-whitelist-modules=$2"
                flag_file_list=1
            fi
            shift
        ;;
        --lfence)
            if [ $flag_lfence == 0 ]; then
                LLCFLAGS+=" -x86-speculative-load-hardening-lfence"
                flag_lfence=1
            fi
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

if [ -z "$OUTPUT" ]; then
    if [ $CREATE_OBJECT ]; then
        OUTPUT=$(basename ${INPUT%.c*}.o)
    else
        OUTPUT="a.out"
    fi
fi

if [ -n "$SOURCE" ] && [ -z "$ASM" ] && [ -z "$DEVNULL" ]; then
    cmd=( $CC $CFLAGS $GGDB $I $LANGUAGE -c -emit-llvm $INPUT -o ${OUTPUT%.o}.bc )
    if [ -n "$ECHO" ]; then echo "${cmd[@]}"; fi
    "${cmd[@]}"

    cmd=( $LLC $LLCFLAGS $OPT ${OUTPUT%.o}.bc -o ${OUTPUT%.o}.s )
    if [ -n "$ECHO" ]; then echo "${cmd[@]}"; fi
    "${cmd[@]}"
    if [ -z "$NO_CLEANUP" ]; then rm ${OUTPUT%.o}.bc; fi

    if [ -z "$CREATE_ASM" ]; then
        cmd=( $CC -Wno-unused-command-line-argument $CFLAGS ${OUTPUT%.o}.s -o $OUTPUT $LDFLAGS )
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

    cmd=( $CC $CFLAGS $GGDB $I $LANGUAGE $INPUT -o $OUTPUT $LDFLAGS )
    if [ -n "$ECHO" ]; then echo "${cmd[@]}"; fi
    "${cmd[@]}"
fi
