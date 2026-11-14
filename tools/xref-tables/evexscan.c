#include <capstone/capstone.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
static csh h; static cs_insn *ci;
static const uint8_t TAIL[] = {0x24,0x08,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
static int valid(const uint8_t *pre, int npre, int modrm) {
    uint8_t buf[32]; memcpy(buf, pre, npre); buf[npre] = modrm; memcpy(buf + npre + 1, TAIL, sizeof TAIL);
    const uint8_t *p = buf; size_t left = 16; uint64_t addr = 0x100000000ull;
    return cs_disasm_iter(h, &p, &left, &addr, ci) ? 1 : 0;
}
int main(int argc, char **argv) {
    cs_open(CS_ARCH_X86, CS_MODE_64, &h); ci = cs_malloc(h);
    uint8_t pre[16];
    // prints: map ctx op variant mem8 reg64   variant = z<<1 | (aaa != 0) ; with extra arg: aaa value / V' / R' probes
    for (int mp = 1; mp <= 3; mp++) for (int ctx = 0; ctx < 128; ctx++) for (int op = 0; op < 256; op++) for (int var = 0; var < 4; var++) {
        int pp = ctx & 3, LL = (ctx >> 2) & 3, W = (ctx >> 4) & 1, vv = ((ctx >> 5) & 1) ? 6 : 15, bb = (ctx >> 6) & 1;
        int z = var >> 1, k = var & 1;
        int n = 0; pre[n++] = 0x62; pre[n++] = 0xf0 | mp; pre[n++] = W << 7 | vv << 3 | 4 | pp; pre[n++] = z << 7 | LL << 5 | bb << 4 | 0x08 | k; pre[n++] = op;
        unsigned mem8 = 0; uint64_t reg64 = 0;
        for (int reg = 0; reg < 8; reg++) {
            if (valid(pre, n, reg << 3)) mem8 |= 1u << reg;
            for (int rm = 0; rm < 8; rm++) if (valid(pre, n, 0xc0 | reg << 3 | rm)) reg64 |= 1ull << (reg * 8 + rm);
        }
        printf("%d %d %d %d %u %llu\n", mp, ctx, op, var, mem8, (unsigned long long)reg64);
    }
    return 0;
}
