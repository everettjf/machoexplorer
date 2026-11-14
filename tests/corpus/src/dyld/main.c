#include <stdio.h>
extern int lib_entry(int);
extern int base_func(int);
extern int base_value;
int *pv = &base_value;
int main(int argc, char **argv) { printf("%d\n", lib_entry(argc) + base_func(*pv)); return 0; }
