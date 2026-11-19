/* Dense `switch` statements that the compiler turns into jump tables.
 *
 *   clang -arch arm64  -O2 -c switch.c -o switch_arm64.o
 *   clang -arch x86_64 -O2 -c switch.c -o switch_x86_64.o
 *   clang -arch arm64  -O2 switch.c -o switch_arm64
 *   clang -arch arm64e -O2 switch.c -o switch_arm64e
 *   clang -arch x86_64 -O2 switch.c -o switch_x86_64
 *
 * arm64: tables of bytes (`tiny`, `based`, `holes`, `flow`, `unchecked`) and
 * of halfwords (`wide`) in `__TEXT,__const`, counted in instructions from a
 * block of the function (clang builds a table from 13 cases up there). arm64e and x86-64: tables of 32-bit offsets in
 * `__text`, marked as data in code. `unchecked` has no range check, so the
 * table's length does not show in the code; `flow` uses, in its cases, an
 * address computed before the switch.
 */
extern int ext(int);
int ext_data = 5;
int counters[8] = {1, 2, 3};
struct big {
  int head[4096];
  int tail[16];
} big;

__attribute__((noinline)) int ext(int x) { return x ^ 0x55; }

__attribute__((noinline)) int tiny(int x) {
  switch (x) {
  case 0: counters[0] += x; return ext(10) + 1;
  case 1: counters[1] += x; return ext(11) * 3;
  case 2: counters[2] += x; return ext(12) - 9;
  case 3: counters[3] += x; return ext(13) / 3;
  case 4: counters[4] += x; return ext(14) << 2;
  case 5: counters[5] += x; return ext(15) | 64;
  case 6: counters[6] += x; return ext(16) % 7;
  case 7: counters[7] += x; return ext(17) ^ 5;
  case 8: counters[0] += x; return ext(18) + 77;
  case 9: counters[1] += x; return ext(19) * 5;
  case 10: counters[2] += x; return ext(20) - 3;
  case 11: counters[3] += x; return ext(21) / 7;
  case 12: counters[4] += x; return ext(22) << 1;
  case 13: counters[5] += x; return ext(23) | 9;
  default: return ext(-1);
  }
}

#define BODY(n)                                                               \
  p[(n) % 7] += ext((n) * 31);                                                \
  p[((n) + 1) % 7] -= ext((n) * 31 + 1);                                      \
  p[((n) + 2) % 7] ^= ext((n) * 31 + 2);                                      \
  p[((n) + 3) % 7] |= ext((n) * 31 + 3);                                      \
  p[((n) + 4) % 7] += ext((n) * 31 + 4) * 3;                                  \
  counters[(n) % 8] = (n);                                                    \
  return ext(n) + ext_data;

/* More than a kilobyte of code: the offsets do not fit in bytes. */
__attribute__((noinline)) int wide(int x, int *p) {
  switch (x) {
  case 0: BODY(0)
  case 1: BODY(1)
  case 2: BODY(2)
  case 3: BODY(3)
  case 4: BODY(4)
  case 5: BODY(5)
  case 6: BODY(6)
  case 7: BODY(7)
  case 8: BODY(8)
  case 9: BODY(9)
  case 10: BODY(10)
  case 11: BODY(11)
  case 12: BODY(12)
  case 13: BODY(13)
  case 14: BODY(14)
  case 15: BODY(15)
  case 16: BODY(16)
  case 17: BODY(17)
  case 18: BODY(18)
  case 19: BODY(19)
  default: return ext(-1);
  }
}

/* The lowest case is not 0: the index is `x - 100`. */
__attribute__((noinline)) int based(int x) {
  switch (x) {
  case 100: counters[0] += x; return ext(200) + 1;
  case 101: counters[1] += x; return ext(201) * 3;
  case 102: counters[2] += x; return ext(202) - 9;
  case 103: counters[3] += x; return ext(203) / 3;
  case 104: counters[4] += x; return ext(204) << 2;
  case 105: counters[5] += x; return ext(205) | 64;
  case 106: counters[6] += x; return ext(206) % 7;
  case 107: counters[7] += x; return ext(207) ^ 5;
  case 108: counters[0] += x; return ext(208) + 77;
  case 109: counters[1] += x; return ext(209) * 5;
  case 110: counters[2] += x; return ext(210) - 3;
  case 111: counters[3] += x; return ext(211) / 7;
  case 112: counters[4] += x; return ext(212) << 1;
  case 113: counters[5] += x; return ext(213) | 9;
  default: return ext(-2);
  }
}

/* Every other value: the entries between lead to the default. */
__attribute__((noinline)) int holes(int x) {
  switch (x) {
  case 0: counters[0] += x; return ext(300) + 1;
  case 2: counters[1] += x; return ext(301) * 3;
  case 4: counters[2] += x; return ext(302) - 9;
  case 6: counters[3] += x; return ext(303) / 3;
  case 8: counters[4] += x; return ext(304) << 2;
  case 10: counters[5] += x; return ext(305) | 64;
  case 12: counters[6] += x; return ext(306) % 7;
  case 14: counters[7] += x; return ext(307) ^ 5;
  case 16: counters[0] += x; return ext(308) + 77;
  case 18: counters[1] += x; return ext(309) * 5;
  case 20: counters[2] += x; return ext(310) - 3;
  case 22: counters[3] += x; return ext(311) / 7;
  case 24: counters[4] += x; return ext(312) << 1;
  case 26: counters[5] += x; return ext(313) | 9;
  default: return ext(-3);
  }
}

/* No range check. */
__attribute__((noinline)) int unchecked(int x) {
  switch (x) {
  case 0: counters[0] += x; return ext(400) + 1;
  case 1: counters[1] += x; return ext(401) * 3;
  case 2: counters[2] += x; return ext(402) - 9;
  case 3: counters[3] += x; return ext(403) / 3;
  case 4: counters[4] += x; return ext(404) << 2;
  case 5: counters[5] += x; return ext(405) | 64;
  case 6: counters[6] += x; return ext(406) % 7;
  case 7: counters[7] += x; return ext(407) ^ 5;
  case 8: counters[0] += x; return ext(408) + 77;
  case 9: counters[1] += x; return ext(409) * 5;
  case 10: counters[2] += x; return ext(410) - 3;
  case 11: counters[3] += x; return ext(411) / 7;
  case 12: counters[4] += x; return ext(412) << 1;
  case 13: counters[5] += x; return ext(413) | 9;
  case 14: counters[6] += x; return ext(414) % 11;
  case 15: counters[7] += x; return ext(415) ^ 12;
  default: __builtin_unreachable();
  }
}

/* `t` is computed once, before the loop, and used in every case. */
__attribute__((noinline)) int flow(int x, int y) {
  int *t = big.tail;
  int r = 0;
  for (int i = 0; i < y; i++) {
    switch (x + i) {
    case 0: r += ext(t[1]); break;
    case 1: r ^= ext(t[2]) + 1; break;
    case 2: r -= ext(t[3]) * 3; break;
    case 3: r += ext(t[4]) << 2; break;
    case 4: r |= ext(t[5]) - 7; break;
    case 5: r += ext(t[6]) / 3; break;
    case 6: r *= ext(t[7]); break;
    case 7: r += ext(t[8]) % 5; break;
    case 8: r -= ext(t[9]) ^ 9; break;
    case 9: r ^= ext(t[10]) * 11; break;
    case 10: r += ext(t[11]) | 3; break;
    case 11: r -= ext(t[12]) << 3; break;
    case 12: r |= ext(t[13]) / 5; break;
    case 13: r += ext(t[14]) - 13; break;
    default: r++; break;
    }
  }
  return r;
}

int main(int argc, char **argv) {
  int p[8] = {0};
  (void)argv;
  return tiny(argc) + wide(argc, p) + based(argc) + holes(argc) +
         unchecked(argc & 15) + flow(argc, 3);
}
