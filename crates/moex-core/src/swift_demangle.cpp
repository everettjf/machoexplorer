// C interface to the bundled Swift demangler (vendor/swift), used by
// src/macho/swift.rs.
//
// Besides whole symbols it demangles the type names stored in a binary's
// reflection metadata. Those hold "symbolic references": a control byte and
// a 32-bit relative offset to a context descriptor (or another record) in
// place of a mangled declaration. The demangler asks a resolver what each
// one stands for; here the caller has looked that up already and passes,
// per reference, either a mangling without references that says the same
// thing or the address referred to.

#include "swift/Demangling/Demangle.h"
#include "swift/Demangling/Demangler.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

using namespace swift::Demangle;

extern "C" {

// What one symbolic reference of a name stands for.
struct moex_swift_ref {
  // Offset in the name of the reference's 4-byte operand.
  uint32_t position;
  // 1: `text` is a mangling that demangles to the node the reference
  //    stands for (a type, a protocol, `<declaration>QO` for an opaque
  //    result type).
  // 2: only `address` is known; the name is printed with a note of it.
  uint32_t kind;
  const char *text;
  size_t text_len;
  uint64_t address;
};

void moex_swift_free(char *text) { free(text); }

}  // extern "C"

static char *copy_out(const std::string &text, size_t *out_len) {
  if (text.empty())
    return nullptr;
  char *out = static_cast<char *>(malloc(text.size()));
  if (!out)
    return nullptr;
  memcpy(out, text.data(), text.size());
  *out_len = text.size();
  return out;
}

extern "C" {

// The demangled form of a symbol, or null when the demangler does not
// understand it. Release with moex_swift_free.
char *moex_swift_demangle_symbol(const char *name, size_t len,
                                 size_t *out_len) {
  llvm::StringRef mangled(name, len);
  if (!isSwiftSymbol(mangled))
    return nullptr;
  std::string text = demangleSymbolAsString(mangled, DemangleOptions());
  if (text.size() == len && memcmp(text.data(), name, len) == 0)
    return nullptr;
  return copy_out(text, out_len);
}

// The demangled form of a type name (no `$s` prefix) whose symbolic
// references stand for `refs`, or null when the demangler does not
// understand it or a reference has no entry. Release with moex_swift_free.
char *moex_swift_demangle_type(const char *name, size_t len,
                               const moex_swift_ref *refs, size_t nrefs,
                               size_t *out_len) {
  Demangler dem;
  // The nodes made from `text` live in demanglers of their own, which have
  // to outlive the printing below.
  std::vector<std::unique_ptr<Demangler>> parts;
  auto resolve = [&](SymbolicReferenceKind kind, Directness, int32_t,
                     const void *at) -> NodePointer {
    size_t position = static_cast<const char *>(at) - name;
    const moex_swift_ref *ref = nullptr;
    for (size_t i = 0; i < nrefs; ++i) {
      if (refs[i].position == position) {
        ref = &refs[i];
        break;
      }
    }
    if (!ref)
      return nullptr;
    if (ref->kind == 1) {
      auto part = std::make_unique<Demangler>();
      NodePointer node =
          part->demangleType(llvm::StringRef(ref->text, ref->text_len));
      parts.push_back(std::move(part));
      return node;
    }
    if (ref->kind != 2)
      return nullptr;
    Node::Kind node;
    switch (kind) {
    case SymbolicReferenceKind::Context:
      node = Node::Kind::OpaqueTypeDescriptorSymbolicReference;
      break;
    case SymbolicReferenceKind::AccessorFunctionReference:
      node = Node::Kind::AccessorFunctionReference;
      break;
    case SymbolicReferenceKind::UniqueExtendedExistentialTypeShape:
      node = Node::Kind::UniqueExtendedExistentialTypeShapeSymbolicReference;
      break;
    case SymbolicReferenceKind::NonUniqueExtendedExistentialTypeShape:
      node =
          Node::Kind::NonUniqueExtendedExistentialTypeShapeSymbolicReference;
      break;
    case SymbolicReferenceKind::ObjectiveCProtocol:
      node = Node::Kind::ObjectiveCProtocolSymbolicReference;
      break;
    default:
      return nullptr;
    }
    return dem.createNode(node, static_cast<Node::IndexType>(ref->address));
  };
  NodePointer node = dem.demangleType(llvm::StringRef(name, len), resolve);
  if (!node)
    return nullptr;
  return copy_out(nodeToString(node, DemangleOptions()), out_len);
}

}  // extern "C"
