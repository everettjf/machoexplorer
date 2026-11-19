// Field types whose mangled names hold symbolic references of every kind
// the reflection metadata uses.
//
//   swiftc -Onone -target arm64-apple-macos12 -module-name Refs \
//       refs.swift -o ../bin/swiftrefs_arm64
import Foundation

protocol Shape {
    associatedtype Unit
    func area() -> Double
}

struct Square: Shape {
    typealias Unit = Int
    var side: Double
    func area() -> Double { side * side }
}

func makeShape() -> some Shape { Square(side: 2) }

struct Wrap<T> {
    var value: T
    struct Inner {
        var inner: T
        var pair: (Wrap<T>, Wrap<T>)
    }
}

extension Array {
    struct Tag {
        var element: Element
    }
}

protocol Named { var name: String { get } }

enum Choice<T> {
    case one(Wrap<T>)
    case two(Wrap<T>.Inner)
    case none
}

final class Holder {
    var wrapped: Wrap<Int>
    var nested: Wrap<Int>.Inner
    var repeated: (Wrap<Int>, Wrap<Int>, Wrap<Wrap<Int>>)
    var table: [String: Wrap<Square>]?
    var existential: any Named
    var optionalExistential: (any Named)?
    var objc: NSCopying
    var composed: any Named & NSCopying
    var tagged: Array<Int>.Tag
    var choice: Choice<Square>
    var callback: (Wrap<Int>) -> Wrap<Int>.Inner

    init(named: any Named, objc: NSCopying & Named) {
        wrapped = Wrap(value: 1)
        nested = Wrap.Inner(inner: 2, pair: (Wrap(value: 3), Wrap(value: 4)))
        repeated = (wrapped, wrapped, Wrap(value: wrapped))
        table = nil
        existential = named
        optionalExistential = nil
        self.objc = objc
        composed = objc
        tagged = Array.Tag(element: 5)
        choice = .none
        callback = { Wrap.Inner(inner: $0.value, pair: ($0, $0)) }
    }
}

final class Label: NSObject, NSCopying, Named {
    var name: String { "label" }
    func copy(with zone: NSZone? = nil) -> Any { self }
}

func capture<T>(_ value: Wrap<T>) -> () -> Wrap<T> {
    return { value }
}

// The closure's capture is of the opaque result type of `makeShape`.
func captureOpaque() -> () -> Double {
    let wrapped = Wrap(value: makeShape())
    return { wrapped.value.area() }
}

let label = Label()
let holder = Holder(named: label, objc: label)
print(captureOpaque()(), capture(holder.wrapped)().value, holder.callback(holder.wrapped).inner)
