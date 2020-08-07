#include "instrument.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "honggfuzz.h"
#include "libhfcommon/common.h"
#include "libhfcommon/log.h"
#include "libhfcommon/util.h"

extern uint64_t branch_execution_count;

__attribute__((visibility("default"))) __attribute__((used))
const char *const LIBHFUZZ_module_instrument = "LIBHFUZZ_module_instrument";

typedef struct {
    unsigned long pointer : 48U;
    uint16_t count : 16U;
} packed_pointer;

uint16_t cmpMapPcLocal[COVERAGE_MAP_SIZE] = {0};
packed_pointer cmpMapPcCache[COVERAGE_MAP_HASHMAP_SIZE] = {{0, 0}};
__attribute__((preserve_most)) static map_entry_t *get_hash_map_entry(uintptr_t pc);

/*
 * If there's no _HF_BITMAP_FD available (running without the honggfuzz
 * supervisor), use a dummy bitmap and control structure located in the BSS
 */
static feedback_t bbMapFb;
feedback_t *feedback = &bbMapFb;
uint32_t my_thread_no = 0;

__attribute__((constructor)) static void initializeInstrument(void) {
    if (fcntl(_HF_LOG_FD, F_GETFD) != -1) {
        enum llevel_t ll = INFO;
        const char *llstr = getenv(_HF_LOG_LEVEL_ENV);
        if (llstr) {
            ll = atoi(llstr);
        }
        logInitLogFile(NULL, _HF_LOG_FD, ll);
    }

    char *my_thread_no_str = getenv(_HF_THREAD_NO_ENV);
    if (my_thread_no_str == NULL) {
        LOG_D("The '%s' envvar is not set", _HF_THREAD_NO_ENV);
        return;
    }
    my_thread_no = atoi(my_thread_no_str);

    if (my_thread_no >= _HF_THREAD_MAX) {
        LOG_F("Received (via envvar) my_thread_no > _HF_THREAD_MAX (%" PRIu32 " > %d)\n",
              my_thread_no, _HF_THREAD_MAX);
    }

    struct stat st;
    if (fstat(_HF_BITMAP_FD, &st) == -1) {
        return;
    }
    if (st.st_size != sizeof(feedback_t)) {
        LOG_F(
            "size of the feedback structure mismatch: st.size != sizeof(feedback_t) (%zu != %zu). "
            "Link your fuzzed binaries with the newest honggfuzz sources via hfuzz-clang(++)",
            (size_t) st.st_size, sizeof(feedback_t));
    }
    if ((feedback = mmap(NULL, sizeof(feedback_t), PROT_READ | PROT_WRITE, MAP_SHARED,
                         _HF_BITMAP_FD, 0)) == MAP_FAILED) {
        PLOG_F("mmap(fd=%d, size=%zu) of the feedback structure failed", _HF_BITMAP_FD,
               sizeof(feedback_t));
    }

    /* Reset coverage counters to their initial state */
    instrumentClearNewCov();
}

/* Reset the counters of newly discovered edges/pcs/features */
void instrumentClearNewCov() {
    feedback->pidFeedbackPc[my_thread_no] = 0U;
    feedback->pidFeedbackEdge[my_thread_no] = 0U;
    feedback->pidFeedbackCmp[my_thread_no] = 0U;
}

void specfuzz_cov_vuln(uintptr_t pc) {
    uint64_t index = (pc & VULN_MAP_INDEX_MASK) >> VULN_MAP_INDEX_OFFSET;
    uint8_t prev = feedback->vulnMap[index];
    if (prev == 0U) {
        ATOMIC_PRE_INC_RELAXED(feedback->pidFeedbackPc[my_thread_no]);
        feedback->vulnMap[index] = 1U;
    }
}

__attribute__((preserve_most))
void specfuzz_cov_trace_pc(uintptr_t pc) {
    // quick path - check the cache
    uint64_t index = pc & COVERAGE_INDEX_MASK;
    if (cmpMapPcCache[index].pointer == pc) {
        branch_execution_count = cmpMapPcCache[index].count;
        return;
    }

    // Update the cache and proceed with slow path
    cmpMapPcCache[index].pointer = pc;

    // slow path: get an entry from the global coverage map
    map_entry_t *entry = get_hash_map_entry(pc);
    int localMapIndex = entry - (map_entry_t *) &feedback->cmpMapPc[0];
    uint16_t *localEntry = &cmpMapPcLocal[localMapIndex];
    uint16_t count = *localEntry;

    if (count != 0) {
        // already covered; nothing to do here
        cmpMapPcCache[index].count = count;
        branch_execution_count = count;
        return;
    }

    // sloth path: we see this CMP the first time in this run
    uint64_t prev = entry->count;
    entry->count++;
    if (prev == 0) {
        ATOMIC_PRE_INC_RELAXED(feedback->pidFeedbackCmp[my_thread_no]);
    }
    count = ((uint16_t) prev) + 1;
    *localEntry = count;
    cmpMapPcCache[index].count = count;
    branch_execution_count = count;
    return;
}

/// A helper function for accessing the coverage map
///
/// Warning: This function is not safe for parallel fuzzing.
/// To support it, the function needs to be re-written with atomics
__attribute__((always_inline)) __attribute__((preserve_most))
static map_entry_t *get_hash_map_entry(uintptr_t pc) {
    map_entry_t *coverage_map = (map_entry_t *) feedback->cmpMapPc;
    uint64_t index = pc & COVERAGE_INDEX_MASK;
    uint64_t tag = (pc & COVERAGE_TAG_MASK) >> COVERAGE_INDEX_WIDTH;
    map_entry_t *entry = &(coverage_map[index]);
    map_entry_t *next;

    if (entry->tag == 0) {
        entry->tag = tag;
        return entry;
    } else if (entry->tag == tag) {
        return entry;
    }

    // hash conflict
    map_entry_t *coverage_map_conflicts = &coverage_map[COVERAGE_MAP_HASHMAP_SIZE];
    do {
        if (entry->next == 0) { // create a new entry
            uint32_t top = feedback->cmpMapPcTop;
            next = &(coverage_map_conflicts[top]);
            entry->next = (uint16_t) top;
            next->tag = tag;

            if (top + 1 > COVERAGE_MAP_CONFLICTS_SIZE) {
                LOG_F("Error: coverage map overflow");
                exit(1);
            }
            feedback->cmpMapPcTop = top + 1;
            return next;
        }
        entry = &coverage_map_conflicts[entry->next];
    } while (entry->tag != tag);
    return entry;
}