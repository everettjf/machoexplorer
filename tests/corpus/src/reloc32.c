/* Calls and data references as 32-bit object files relocate them.
 *
 *   clang -arch i386  -O1 -c reloc32.c -o reloc_i386.o
 *   clang -arch i386  -O1 -mdynamic-no-pic -c reloc32.c -o reloc_i386_nopic.o
 *   clang -arch armv7 -O1 -c reloc32.c -o reloc_armv7.o
 *   clang -arch armv7 -O1 -marm -c reloc32.c -o reloc_armv7_arm.o
 *   clang -arch armv7 -O1 -mdynamic-no-pic -c reloc32.c -o reloc_armv7_nopic.o
 *
 * i386: position-independent code refers to data by its distance from the
 * address `call` / `pop` reads (`SECTDIFF`, `LOCAL_SECTDIFF` + `PAIR`);
 * without it the operands are absolute (`VANILLA`). A call to a symbol that
 * is not surely this file's (`weak_fn`, `ext_fn`) names the symbol.
 * armv7: `movw` / `movt` pairs (`HALF`, `HALF_SECTDIFF` + `PAIR`) in Thumb
 * and ARM code, `bl` / `b` (`BR22`, `BR24`).
 */
extern int ext_fn(int);
extern int ext_var;
int g_var = 5;
int g_arr[16] = {1};
static int s_var = 7;
__attribute__((weak)) int weak_fn(int x) { return x + 1; }
__attribute__((noinline)) int def_fn(int x) { return x * 3; }
__attribute__((noinline)) static int local_fn(int x) { return x ^ s_var; }
const char *str(void) { return "hello reloc"; }
int use(int x) {
  s_var += x;
  g_var += ext_var;
  g_arr[3] = x;
  return def_fn(x) + local_fn(x) + ext_fn(x) + weak_fn(x) + g_arr[5];
}
int (*fp(void))(int) { return def_fn; }
int tail(int x) { return def_fn(x + 1); }
