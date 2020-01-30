#!/usr/bin/gawk -f

function sorted_print(map, threshold, total, sims, total_simulations) {
    for (key in map) {
        inverted_map[map[key]/sims[key]] = key
    }

    n = asorti(inverted_map, sorted, "@ind_num_desc")
    sum = 0.0
    for (i = 1; i <= n; i++) {
        #rate = (sorted[i] / total) * 100
        printf("%s\t%.4f\n", inverted_map[sorted[i]], sorted[i])
        #sum += rate
        sum += 1
        if (sum > threshold) {
            break
        }
    }
    return str
}


BEGIN {
    simulation_id = -1
}

/\[SF\] rlbk:/ {
    if ($6 != simulation_id) {
        simulation_id = $6
        simulations[$3] += 1
        total_simulations++
    }
    rollbacks[$3] += 1
    weighted_simulations[$3] += $4
    depth[$4 - $4 % 50] += 1;
    nesting[$5] += 1;
    
    total_rollbacks++
    total_depth += $4
}

END {
    print "* Depths:"
    for (d in depth) {
         #printf("%s: \t%.4f ", (250 - d), (depth[d] / total_rollbacks) * 100)
         printf("%s:\t", (250 - d))
         rate = (depth[d] / total_rollbacks) * 100
         for (i=0; i < rate ; i++) {
            printf("*")
         }
         printf("\n")
    }

    printf("\n* Nestings:\n")
    for (n in nesting) {
        printf("%s: %.2f%\n", n, (nesting[n] / total_rollbacks) * 100)
    }

    printf("\n* rollbacks\n")
    sorted_print(rollbacks, threshold, total_rollbacks, simulations, total_simulations)
}



