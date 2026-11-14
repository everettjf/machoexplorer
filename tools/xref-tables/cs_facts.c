// Differential oracle: prints, per instruction, the facts the Xref view derives from Capstone.
#include <capstone/capstone.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <ctype.h>

static int is_a64_gpr(const char *n) {
    if (!n) return 0;
    if (!strcmp(n, "sp") || !strcmp(n, "wsp") || !strcmp(n, "xzr") || !strcmp(n, "wzr")) return 1;
    if ((n[0] == 'x' || n[0] == 'w') && isdigit((unsigned char)n[1])) return 1;
    return 0;
}
static const char *a64name(csh h, unsigned r) {
    const char *n = cs_reg_name(h, r);
    if (!n) return "?";
    if (!strcmp(n, "fp")) return "x29";
    if (!strcmp(n, "lr")) return "x30";
    return n;
}
static const char *x86_tracked[] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15",
 "eax","ecx","edx","ebx","esp","ebp","esi","edi","r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d",
 "ax","cx","dx","bx","sp","bp","si","di","r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w",
 "al","cl","dl","bl","spl","bpl","sil","dil","r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b","ah","ch","dh","bh",
 "rip","eip","ip","es","cs","ss","ds","fs","gs", NULL};
static int is_x86_tracked(const char *n) {
    if (!n) return 0;
    for (int i = 0; x86_tracked[i]; i++) if (!strcmp(n, x86_tracked[i])) return 1;
    if ((n[0]=='c'||n[0]=='d') && n[1]=='r' && isdigit((unsigned char)n[2])) return 1;
    return 0;
}
static int cmpstr(const void *a, const void *b) { return strcmp(*(const char **)a, *(const char **)b); }
static const char *xn(csh h, unsigned r) { const char *n = r ? cs_reg_name(h, r) : "-"; if (!n) return "?"; return is_x86_tracked(n) || !strcmp(n,"-") ? n : "~"; }

int verbose = 0;
static void facts(csh h, int arch, const cs_insn *ci, FILE *out) {
    int J = 0, C = 0;
    for (int g = 0; g < ci->detail->groups_count; g++) {
        if (ci->detail->groups[g] == CS_GRP_JUMP) J = 1;
        if (ci->detail->groups[g] == CS_GRP_CALL) C = 1;
    }
    fprintf(out, "%" PRIx64 " %d %c%c W=", ci->address, ci->size, J ? 'J' : '-', C ? 'C' : '-');
    cs_regs rr, rw; uint8_t nr = 0, nw = 0;
    const char *names[64]; int nn = 0;
    if (cs_regs_access(h, ci, rr, &nr, rw, &nw) == 0) {
        for (int i = 0; i < nw; i++) {
            const char *n = arch == CS_ARCH_ARM64 ? a64name(h, rw[i]) : cs_reg_name(h, rw[i]);
            if (arch == CS_ARCH_ARM64 ? is_a64_gpr(n) : is_x86_tracked(n)) {
                int dup = 0; for (int k = 0; k < nn; k++) if (!strcmp(names[k], n)) dup = 1;
                if (!dup) names[nn++] = n;
            }
        }
    } else fprintf(out, "!");
    qsort(names, nn, sizeof(names[0]), cmpstr);
    for (int i = 0; i < nn; i++) fprintf(out, "%s%s", i ? "," : "", names[i]);
    fprintf(out, " A=");
    if (arch == CS_ARCH_ARM64) {
        const cs_arm64 *a = &ci->detail->arm64;
        #define RN(i) a64name(h, a->operands[i].reg)
        #define GP(i) is_a64_gpr(RN(i))
        if ((ci->id == ARM64_INS_ADR || ci->id == ARM64_INS_ADRP) && a->op_count >= 2 && a->operands[0].type == ARM64_OP_REG && a->operands[1].type == ARM64_OP_IMM) {
            fprintf(out, "set %s %" PRIx64, RN(0), (uint64_t)a->operands[1].imm);
        } else if ((ci->id == ARM64_INS_ADD || ci->id == ARM64_INS_SUB) && a->op_count >= 3 && a->operands[0].type == ARM64_OP_REG && a->operands[1].type == ARM64_OP_REG && a->operands[2].type == ARM64_OP_IMM) {
            if (GP(0) && GP(1)) fprintf(out, "%s %s %s %" PRIx64, ci->id == ARM64_INS_ADD ? "add" : "sub", RN(0), RN(1), (uint64_t)a->operands[2].imm); else fprintf(out, "-");
        } else if (ci->id == ARM64_INS_MOV && a->op_count >= 2 && a->operands[0].type == ARM64_OP_REG && a->operands[1].type == ARM64_OP_REG) {
            if (GP(0) && GP(1)) fprintf(out, "mov %s %s", RN(0), RN(1)); else fprintf(out, "-");
        } else if (ci->id == ARM64_INS_MOVZ && a->op_count >= 2 && a->operands[0].type == ARM64_OP_REG && a->operands[1].type == ARM64_OP_IMM) {
            uint64_t v = (uint64_t)a->operands[1].imm;
            if (a->op_count >= 3 && a->operands[2].type == ARM64_OP_IMM) { uint64_t s = (uint64_t)a->operands[2].imm; if (s < 64) v <<= s; }
            fprintf(out, "set %s %" PRIx64, RN(0), v);
        } else if (ci->id == ARM64_INS_MOVK && a->op_count >= 2 && a->operands[0].type == ARM64_OP_REG && a->operands[1].type == ARM64_OP_IMM) {
            uint64_t s = 0;
            if (a->op_count >= 3 && a->operands[2].type == ARM64_OP_IMM) { s = (uint64_t)a->operands[2].imm; if (s >= 64) s = 0; }
            fprintf(out, "movk %s %" PRIx64 " %" PRIu64, RN(0), (uint64_t)a->operands[1].imm & 0xffff, s);
        } else if ((ci->id == ARM64_INS_LDR || ci->id == ARM64_INS_LDUR || ci->id == ARM64_INS_LDRSW) && a->op_count >= 2 && a->operands[0].type == ARM64_OP_REG && a->operands[1].type == ARM64_OP_MEM) {
            if (GP(0)) fprintf(out, "ldrm %s %s %" PRIx64, RN(0), a64name(h, a->operands[1].mem.base), (uint64_t)(int64_t)a->operands[1].mem.disp); else fprintf(out, "-");
        } else if ((ci->id == ARM64_INS_LDR || ci->id == ARM64_INS_LDRSW) && a->op_count >= 2 && a->operands[0].type == ARM64_OP_REG && a->operands[1].type == ARM64_OP_IMM) {
            if (GP(0)) fprintf(out, "ldri %s %" PRIx64, RN(0), (uint64_t)a->operands[1].imm); else fprintf(out, "-");
        } else fprintf(out, "-");
        if (J || C) {
            fprintf(out, " B=");
            for (int o = 0; o < a->op_count; o++) {
                const cs_arm64_op *op = &a->operands[o];
                if (op->type == ARM64_OP_IMM) fprintf(out, "[i %" PRIx64 "]", (uint64_t)op->imm);
                else if (op->type == ARM64_OP_REG) fprintf(out, "[r %s]", is_a64_gpr(a64name(h, op->reg)) ? a64name(h, op->reg) : "~");
            }
        }
    } else {
        const cs_x86 *x = &ci->detail->x86;
        #define XR(i) xn(h, x->operands[i].reg)
        int wr0 = 0; /* op0 reg reported as written */
        if (x->op_count >= 1 && x->operands[0].type == X86_OP_REG) { for (int k = 0; k < nw; k++) if (rw[k] == x->operands[0].reg) wr0 = 1; }
        #define TR(i) (strcmp(XR(i), "~") != 0)
        if (ci->id == X86_INS_LEA && x->op_count >= 2 && x->operands[0].type == X86_OP_REG && x->operands[1].type == X86_OP_MEM) {
            unsigned b = x->operands[1].mem.base;
            if (!TR(0)) fprintf(out, "-");
            else if (b == X86_REG_RIP || b == X86_REG_EIP) fprintf(out, "set %s %" PRIx64, XR(0), (uint64_t)((int64_t)ci->address + ci->size + x->operands[1].mem.disp));
            else if (x->operands[1].mem.index == X86_REG_INVALID && b != X86_REG_INVALID && strcmp(xn(h, b), "~")) fprintf(out, "add %s %s %" PRIx64, XR(0), xn(h, b), (uint64_t)x->operands[1].mem.disp);
            else fprintf(out, "-");
        } else if (ci->id == X86_INS_MOV && x->op_count >= 2 && x->operands[0].type == X86_OP_REG) {
            if (!TR(0)) fprintf(out, "-");
            else if (x->operands[1].type == X86_OP_IMM) fprintf(out, "set %s %" PRIx64, XR(0), (uint64_t)x->operands[1].imm);
            else if (x->operands[1].type == X86_OP_REG) { if (TR(1)) fprintf(out, "mov %s %s", XR(0), XR(1)); else fprintf(out, "-"); }
            else if (x->operands[1].type == X86_OP_MEM && (x->operands[1].mem.base == X86_REG_RIP || x->operands[1].mem.base == X86_REG_EIP))
                fprintf(out, "ldri %s %" PRIx64, XR(0), (uint64_t)((int64_t)ci->address + ci->size + x->operands[1].mem.disp));
            else fprintf(out, "-");
        } else if ((ci->id == X86_INS_ADD || ci->id == X86_INS_SUB) && x->op_count >= 2 && x->operands[0].type == X86_OP_REG && x->operands[1].type == X86_OP_IMM) {
            if (wr0 || !TR(0)) fprintf(out, "-"); else fprintf(out, "%s %s %" PRIx64, ci->id == X86_INS_ADD ? "addi!" : "subi!", XR(0), (uint64_t)x->operands[1].imm);
        } else if (ci->id == X86_INS_XOR && x->op_count >= 2 && x->operands[0].type == X86_OP_REG && x->operands[1].type == X86_OP_REG && x->operands[0].reg == x->operands[1].reg) {
            if (TR(0)) fprintf(out, "set %s 0", XR(0)); else fprintf(out, "-");
        } else fprintf(out, "-");
        if (J || C) {
            fprintf(out, " B=");
            for (int o = 0; o < x->op_count; o++) {
                const cs_x86_op *op = &x->operands[o];
                if (op->type == X86_OP_IMM) fprintf(out, "[i %" PRIx64 "]", (uint64_t)op->imm);
                else if (op->type == X86_OP_MEM) fprintf(out, "[m %s %s %" PRIx64 "]", xn(h, op->mem.base), xn(h, op->mem.index), (uint64_t)op->mem.disp);
                else if (op->type == X86_OP_REG) fprintf(out, "[r %s]", xn(h, op->reg));
            }
        }
    }
    if (verbose) fprintf(out, "   ; %s %s", ci->mnemonic, ci->op_str);
    fprintf(out, "\n");
}

int main(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: cs_facts arm64|x64|x86 file base [-v]\n"); return 2; }
    int arch = !strcmp(argv[1], "arm64") ? CS_ARCH_ARM64 : CS_ARCH_X86;
    int mode = !strcmp(argv[1], "arm64") ? CS_MODE_ARM : !strcmp(argv[1], "x64") ? CS_MODE_64 : CS_MODE_32;
    for (int k = 4; k < argc; k++) if (!strcmp(argv[k], "-v")) verbose = 1;
    FILE *f = fopen(argv[2], "rb"); if (!f) { perror("open"); return 1; }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc(n ? n : 1); if (fread(buf, 1, n, f) != (size_t)n) return 1; fclose(f);
    uint64_t base = strtoull(argv[3], NULL, 16);
    csh h; if (cs_open(arch, mode, &h) != CS_ERR_OK) return 1;
    cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
    cs_insn *ci = cs_malloc(h);
    const uint8_t *p = buf; size_t left = n; uint64_t addr = base;
    static char obuf[1 << 20]; setvbuf(stdout, obuf, _IOFBF, sizeof obuf);
    int chunk = 0;
    for (int k = 4; k < argc; k++) if (!strncmp(argv[k], "-c", 2)) chunk = atoi(argv[k] + 2);
    if (chunk == 1) { /* sliding window: one instruction at every byte offset */
        for (long off = 0; off < n; off++) {
            p = buf + off; left = n - off < 16 ? n - off : 16; addr = base + off;
            if (cs_disasm_iter(h, &p, &left, &addr, ci)) facts(h, arch, ci, stdout);
            else printf("%" PRIx64 " INVALID\n", base + off);
        }
        return 0;
    }
    if (chunk) {
        for (long off = 0; off + chunk <= n; off += chunk) {
            p = buf + off; left = chunk; addr = base + off;
            if (cs_disasm_iter(h, &p, &left, &addr, ci)) facts(h, arch, ci, stdout);
            else printf("%" PRIx64 " INVALID\n", base + off);
        }
        return 0;
    }
    while (cs_disasm_iter(h, &p, &left, &addr, ci)) facts(h, arch, ci, stdout);
    printf("STOP %" PRIx64 "\n", addr - base);
    return 0;
}
