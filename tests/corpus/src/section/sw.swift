import Foundation
protocol Shape { associatedtype Unit; var area: Double { get }; func scaled(by k: Double) -> Self }
protocol Named { var name: String { get } }
struct Circle: Shape, Named { typealias Unit = Int; var r: Double; var name: String { "circle" }
  var area: Double { 3.14159 * r * r }; func scaled(by k: Double) -> Circle { Circle(r: r * k) } }
final class Box<T>: Named { var w: Double; var h: Double; var tag: T; var name: String { "box '\(tag)'" }
  init(w: Double, h: Double, tag: T) { self.w = w; self.h = h; self.tag = tag } }
enum Payload { case none; case text(String); case pair(Int, Double); case boxed(Box<Int>) }
enum Kind: String, CaseIterable { case small, large }
struct Wrapper<A: Named, B> { var a: A; var b: [B]; var f: (Int) -> String }
extension Circle: CustomStringConvertible { var description: String { "Circle(\(r))" } }
func makeCounter(start: Int, label: String) -> () -> String { var n = start; let c = Circle(r: 1); return { n += 1; return "\(label) \(n) \(c.area)" } }
func opaque() -> some Named { Circle(r: 2) }
@objc class Bridged: NSObject { @objc var title: String = "it's"; @objc func ping(_ x: Int) -> Int { x + 1 } }
let counter = makeCounter(start: 3, label: "n")
let w = Wrapper(a: Circle(r: 1), b: [Payload.text("x"), .pair(1, 2)], f: { "\($0)" })
print(counter(), w.a.name, opaque().name, Kind.allCases, Box(w: 1, h: 2, tag: 3).name, Bridged().ping(1), Payload.none)
