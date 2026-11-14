// Validity scan of x86 opcode maps with Capstone: for each (kind, ctx, opcode) prints
// "kind ctx opcode mem8 reg64 mixed" where mem8 = valid mask by modrm.reg for memory forms (rm=0),
// reg64 = valid mask by reg*8+rm for register forms, mixed = 1 if memory validity depends on rm.
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
static void scan(const char *kind, int ctx, int op, const uint8_t *pre, int npre) {
    unsigned mem8 = 0; uint64_t reg64 = 0; int mixed = 0;
    for (int reg = 0; reg < 8; reg++) {
        int v0 = valid(pre, npre, reg << 3);            // mod=0 rm=0
        for (int mod = 0; mod < 3; mod++) for (int rm = 0; rm < 8; rm++) if (valid(pre, npre, mod << 6 | reg << 3 | rm) != v0) mixed = 1;
        if (v0) mem8 |= 1u << reg;
        for (int rm = 0; rm < 8; rm++) if (valid(pre, npre, 0xc0 | reg << 3 | rm)) reg64 |= 1ull << (reg * 8 + rm);
    }
    printf("%s %d %d %u %llu %d\n", kind, ctx, op, mem8, (unsigned long long)reg64, mixed);
}
int main(int argc, char **argv) {
    int mode = !strcmp(argv[1], "64") ? CS_MODE_64 : CS_MODE_32;
    cs_open(CS_ARCH_X86, mode, &h); ci = cs_malloc(h);
    uint8_t pre[16];
    // legacy maps: ctx = p66 | rep<<1 (0 none, 1 F3, 2 F2) | W<<3
    const char *kinds[] = {"two", "38", "3a", "x87"};
    for (int k = 0; k < 4; k++) for (int ctx = 0; ctx < (mode == CS_MODE_64 ? 16 : 8); ctx++) {
        int p66 = ctx & 1, rep = (ctx >> 1) & 3, W = ctx >> 3;
        if (rep == 3 || (W && mode != CS_MODE_64)) continue;
        for (int op = 0; op < 256; op++) {
            if (k == 3 && (op < 0xd8 || op > 0xdf)) continue;
            int n = 0;
            if (p66) pre[n++] = 0x66;
            if (rep == 1) pre[n++] = 0xf3; else if (rep == 2) pre[n++] = 0xf2;
            if (W) pre[n++] = 0x48;
            if (k < 3) pre[n++] = 0x0f;
            if (k == 1) pre[n++] = 0x38; else if (k == 2) pre[n++] = 0x3a;
            pre[n++] = op;
            scan(kinds[k], ctx, op, pre, n);
        }
    }
    // 3DNow!: 0F 0F modrm suffix
    for (int sfx = 0; sfx < 256; sfx++) {
        uint8_t buf[16] = {0x0f, 0x0f, 0xc0, sfx, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
        const uint8_t *p = buf; size_t left = 16; uint64_t addr = 0x100000000ull;
        printf("3dnow 0 %d %d 0 0\n", sfx, cs_disasm_iter(h, &p, &left, &addr, ci) ? 1 : 0);
    }
    // VEX: ctx = pp | L<<2 | W<<3 | (vvvv != 15)<<4 ; map 1..3
    for (int mp = 1; mp <= 3; mp++) for (int ctx = 0; ctx < 32; ctx++) for (int op = 0; op < 256; op++) {
        int pp = ctx & 3, L = (ctx >> 2) & 1, W = (ctx >> 3) & 1, vv = (ctx >> 4) ? 14 : 15;
        int n = 0; pre[n++] = 0xc4; pre[n++] = 0xe0 | mp; pre[n++] = W << 7 | vv << 3 | L << 2 | pp; pre[n++] = op;
        char kind[8]; snprintf(kind, sizeof kind, "vex%d", mp);
        scan(kind, ctx, op, pre, n);
    }
    // XOP: map 8..10, same ctx
    for (int mp = 8; mp <= 10; mp++) for (int ctx = 0; ctx < 32; ctx++) for (int op = 0; op < 256; op++) {
        int pp = ctx & 3, L = (ctx >> 2) & 1, W = (ctx >> 3) & 1, vv = (ctx >> 4) ? 14 : 15;
        int n = 0; pre[n++] = 0x8f; pre[n++] = 0xe0 | mp; pre[n++] = W << 7 | vv << 3 | L << 2 | pp; pre[n++] = op;
        char kind[8]; snprintf(kind, sizeof kind, "xop%d", mp);
        scan(kind, ctx, op, pre, n);
    }
    // EVEX: ctx = pp | LL<<2 | W<<4 | (vvvv != 15)<<5 ; map 1..3 ; b=0 z=0 aaa=0
    for (int mp = 1; mp <= 3; mp++) for (int ctx = 0; ctx < 128; ctx++) for (int op = 0; op < 256; op++) {
        int pp = ctx & 3, LL = (ctx >> 2) & 3, W = (ctx >> 4) & 1, vv = ((ctx >> 5) & 1) ? 6 : 15, bb = (ctx >> 6) & 1;
        int n = 0; pre[n++] = 0x62; pre[n++] = 0xf0 | mp; pre[n++] = W << 7 | vv << 3 | 4 | pp; pre[n++] = LL << 5 | bb << 4 | 0x08; pre[n++] = op;
        char kind[8]; snprintf(kind, sizeof kind, "evex%d", mp);
        scan(kind, ctx, op, pre, n);
    }
    return 0;
}
