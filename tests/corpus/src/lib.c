#include <stdlib.h>
int moex_add(int a, int b) { return a + b; }
__attribute__((weak)) int moex_weak(void) { return 7; }
void *moex_alloc(size_t n) { return malloc(n); }
__attribute__((constructor)) static void moex_init(void) { }
