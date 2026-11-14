#include <cstdio>
#include <new>
#include <string>
extern "C" int base_func(int);
__thread int tls_var = 5;
__attribute__((weak)) int weak_def(int x) { return x * 2; }
extern "C" int weak_import_fn(void) __attribute__((weak_import));
inline int inline_fn(int x) { static int counter; return counter += x; }
void *operator new(std::size_t n) { return malloc(n); }
void operator delete(void *p) noexcept { free(p); }
struct Base { virtual ~Base() {} virtual int f() { return 1; } };
struct Derived : Base { int f() override { return inline_fn(2); } };
int (*fptr)(int) = base_func;
const char *strs[] = {"a", "b", "c"};
Base *make() { return new Derived(); }
extern "C" int lib_entry(int x) {
    std::string s = std::to_string(x);
    printf("%s %d\n", s.c_str(), tls_var);
    if (weak_import_fn) x += weak_import_fn();
    return base_func(x) + weak_def(x) + make()->f();
}
