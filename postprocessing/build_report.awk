#!/usr/bin/gawk -f
function filter(str) {
    gsub("killed", "", str)
    gsub("renamable", "", str)
    gsub("<regmask .*>", "", str)
    gsub("implicit .[a-z]+,", "", str)
    gsub("implicit-def .[a-z]+,", "", str)
    gsub("debug-location ![0-9]+", "", str)
    gsub(" +", " ", str)
    gsub(/^[ \t]+/, "", str)
    return str
}

BEGIN {
    bt_initialized = 0;
}

/\*+ SpecFuzz :/ {
    current_function = $4
}

/Blacklisted/ {
    blacklisted[current_function] = 1
}

/Instrumenting an indirect branch/ {
    gsub("Instrumenting an indirect branch:", "", $0)
    $0 = filter($0)
    indirect_branches[$0] = current_function
}

/Instrumenting an indirect call/ {
    gsub("Instrumenting an indirect call:", "", $0)
    $0 = filter($0)
    indirect_calls[$0] = current_function
}

/Instrumenting a call to an external function/ {
    gsub("Instrumenting a call to an external function:", "", $0)
    $0 = filter($0)
    if (match($2, "@") != 0) {
        external_calls[$1 " " $2] = current_function
    } else {
        external_calls[$0] = current_function
    }
}

/Instrumenting a call to an ASan function/ {
    gsub("Instrumenting a call to an ASan function:", "", $0)
    $0 = filter($0)
    if (match($2, "@") != 0) {
        asan_calls[$1 " " $2] = current_function
    } else {
        asan_calls[$0] = current_function
    }
}

/Instrumenting a serializing instruction/ {
    $1=""; $2=""; $3=""; $4="";
    $0 = filter($0)
    serializing[$0] = current_function
}


END {
    print "Blacklisted functions:"
    for (f in blacklisted) {
        print f;
    }

    printf "\nBranch Table is initialized: "
    if (bt_initialized == 0) {
        print "Yes"
    } else {
        print "No"
    }

    printf "\nIndirect branches:\n"
    n = asorti(indirect_branches, sorted)
    for (i in sorted) {
        printf("%s in %s\n", sorted[i], indirect_branches[sorted[i]])
    }

    printf "\nIndirect calls:\n"
    n = asorti(indirect_calls, sorted)
    for (i in sorted) {
        printf("%s in %s\n", sorted[i], indirect_calls[sorted[i]])
    }

    printf "\nExternal calls:\n"
    n = asorti(external_calls, sorted)
    for (i in sorted) {
        printf("%s in %s\n", sorted[i], external_calls[sorted[i]])
    }

    printf "\nASan calls:\n"
    n = asorti(asan_calls, sorted)
    for (i in sorted) {
        printf("%s in %s\n", sorted[i], asan_calls[sorted[i]])
    }

    printf "\nSerializing instructions:\n"
    n = asorti(serializing, sorted)
    for (i in sorted) {
        printf("%s in %s\n", sorted[i], serializing[sorted[i]])
    }
}
