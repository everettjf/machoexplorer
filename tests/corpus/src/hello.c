#include <stdio.h>
#include <string.h>
static const char *kNames[] = {"alpha", "beta", "gamma"};
__thread int tls_counter = 3;
double scale(double v) { return v * 2.5; }
int main(int argc, char **argv) {
    for (int i = 0; i < 3; i++) printf("%s %zu\n", kNames[i], strlen(kNames[i]));
    tls_counter += argc;
    printf("%f %d\n", scale(1.0), tls_counter);
    return 0;
}
