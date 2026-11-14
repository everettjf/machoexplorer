// Exhaustive validity scan of one AArch64 encoding class (bits 28:25) with Capstone.
// Output: <out>.keys (u16 pattern index per key = word >> 10 with class bits removed), <out>.pats (128 bytes each)
#include <capstone/capstone.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
int main(int argc, char **argv) {
    unsigned cls = strtoul(argv[1], 0, 2);
    csh h; cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &h);
    cs_insn *ci = cs_malloc(h);
    static uint8_t pats[65536][128]; int npat = 0;
    uint16_t *keys = malloc(sizeof(uint16_t) << 18);
    for (uint32_t k = 0; k < (1u << 18); k++) {
        // k: bits 17:15 -> word bits 31:29 ; bits 14:0 -> word bits 24:10
        uint32_t hi = ((k >> 15) << 29) | (cls << 25) | ((k & 0x7fff) << 10);
        uint8_t pat[128]; memset(pat, 0, sizeof pat);
        for (uint32_t lo = 0; lo < 1024; lo++) {
            uint32_t w = hi | lo; const uint8_t *p = (const uint8_t *)&w; size_t left = 4; uint64_t addr = 0x100000000ull;
            if (cs_disasm_iter(h, &p, &left, &addr, ci)) pat[lo >> 3] |= 1 << (lo & 7);
        }
        int id = -1;
        for (int i = npat - 1; i >= 0; i--) if (!memcmp(pats[i], pat, 128)) { id = i; break; }
        if (id < 0) { if (npat == 65536) { fprintf(stderr, "too many patterns\n"); return 1; } memcpy(pats[npat], pat, 128); id = npat++; }
        keys[k] = id;
    }
    char name[256];
    snprintf(name, sizeof name, "%s.keys", argv[2]); FILE *f = fopen(name, "wb"); fwrite(keys, 2, 1 << 18, f); fclose(f);
    snprintf(name, sizeof name, "%s.pats", argv[2]); f = fopen(name, "wb"); fwrite(pats, 128, npat, f); fclose(f);
    // stats
    long runs = 1; for (uint32_t k = 1; k < (1u << 18); k++) if (keys[k] != keys[k - 1]) runs++;
    printf("class %s: %d patterns, %ld runs\n", argv[1], npat, runs);
    return 0;
}
