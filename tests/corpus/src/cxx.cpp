#include <map>
#include <string>
#include <vector>
#include <functional>
namespace moex { namespace demo {
template <typename T> struct Box { T v; T get() const { return v; } };
class Shape { public: virtual ~Shape() {} virtual double area() const = 0; };
class Rect : public Shape { double w, h; public: Rect(double a, double b) : w(a), h(b) {} double area() const override { return w * h; } };
std::string join(const std::vector<std::string> &v, const char *sep) { std::string o; for (auto &s : v) { o += s; o += sep; } return o; }
int apply(const std::function<int(int, unsigned long)> &f, int x) { return f(x, 2); }
bool operator<(const Rect &a, const Rect &b) { return a.area() < b.area(); }
}}
int main(int argc, char **) {
    moex::demo::Rect r(2, 3);
    moex::demo::Box<long long> b{argc};
    std::map<std::string, int> m; m["a"] = 1;
    auto lam = [&](int a, unsigned long c) { return a + (int)c + m["a"]; };
    return moex::demo::apply(lam, (int)b.get()) + (int)r.area() + (int)moex::demo::join({"x"}, ",").size() + (r < r);
}
