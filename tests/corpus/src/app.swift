protocol Shape { var area: Double { get } }
struct Circle: Shape { var r: Double; var area: Double { 3.14159 * r * r } }
final class Box<T>: Shape { var w: Double; var h: Double; var tag: T
    init(w: Double, h: Double, tag: T) { self.w = w; self.h = h; self.tag = tag }
    var area: Double { w * h } }
enum Kind: String { case small, large }
func describe(_ s: Shape) -> String { "\(type(of: s)) \(s.area) \(s.area > 10 ? Kind.large.rawValue : Kind.small.rawValue)" }
print(describe(Circle(r: 2)))
print(describe(Box(w: 2, h: 3, tag: "t")))
