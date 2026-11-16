//! "Xref Report" node: who refers to which address, from pointer sections
//! and from the code sections (calls, jumps, address computations
//! and memory accesses), followed by a call graph summary per instruction
//! and per function.

use crate::hex::{as_address, as_short_hex_string, as_string};
use crate::macho::xref::{self, Xrefs};
use crate::macho::MachHeader;
use crate::view::{leaf, Content, Table, ViewNode};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

pub fn node(mh: Arc<MachHeader>) -> Option<ViewNode> {
    Some(leaf("Xref Report", move || content(&mh)))
}

/// Symbol names by address: exact lookup and "nearest symbol below".
#[derive(Default)]
struct Symbols {
    exact: HashMap<u64, String>,
    /// Sorted by address; addresses are unique.
    sorted: Vec<(u64, String)>,
}

impl Symbols {
    fn load(mh: &MachHeader) -> Self {
        let mut s = Symbols::default();
        let Some(symtab) = mh.symtab() else { return s };
        // Whether the name at an address so far is that of a local symbol.
        let mut local: HashMap<u64, bool> = HashMap::new();
        for sym in symtab.symbols() {
            // Defined in a section: only such a symbol can be at address 0
            // (the first function of an object file).
            let in_section = sym.n_type & 0xe0 == 0 && sym.n_type & 0x0e == 0x0e;
            let external = sym.n_type & 0x01 != 0;
            if sym.n_strx == 0 || (sym.n_value == 0 && !in_section) {
                continue;
            }
            // The first named symbol at an address wins, except that an
            // external symbol replaces a local one (`_main` rather than
            // the assembler's `ltmp0`).
            match local.get(&sym.n_value) {
                Some(true) if external => {}
                Some(_) => continue,
                None => {}
            }
            let name = symtab.string(sym.n_strx);
            if !name.is_empty() {
                local.insert(sym.n_value, !external);
                s.exact.insert(sym.n_value, name);
            }
        }
        s.sorted = s.exact.iter().map(|(a, n)| (*a, n.clone())).collect();
        s.sorted.sort_by_key(|(addr, _)| *addr);
        s
    }

    fn exact(&self, addr: u64) -> Option<&str> {
        self.exact.get(&addr).map(String::as_str)
    }

    /// The last symbol at or below `addr`.
    fn at_or_below(&self, addr: u64) -> Option<&(u64, String)> {
        let n = self.sorted.partition_point(|(a, _)| *a <= addr);
        self.sorted.get(n.checked_sub(1)?)
    }

    /// `symbol+0xoff` for an address strictly inside a symbol.
    fn offset_name(&self, addr: u64) -> Option<String> {
        let (base, name) = self.at_or_below(addr)?;
        (addr > *base).then(|| format!("{}+0x{}", name, as_short_hex_string(addr - base)))
    }

    /// Exact name, else `symbol+0xoff`, else empty.
    fn describe(&self, addr: u64) -> String {
        match self.exact(addr) {
            Some(name) => name.to_string(),
            None => self.offset_name(addr).unwrap_or_default(),
        }
    }

    /// Start address and name of the function holding `addr`: the nearest
    /// symbol at or below it, or the address itself when there is none.
    fn function_base(&self, addr: u64) -> (u64, String) {
        if let Some(name) = self.exact(addr) {
            return (addr, name.to_string());
        }
        match self.at_or_below(addr) {
            Some((base, name)) => (*base, name.clone()),
            None => (addr, as_address(addr)),
        }
    }
}

fn or_address(name: String, addr: u64) -> String {
    if name.is_empty() {
        as_address(addr)
    } else {
        name
    }
}

fn content(mh: &MachHeader) -> Content {
    let mut t = Table::new();
    t.set_headers(&["Target", "Symbol", "Ref Count", "Referrer"]);
    t.set_widths(&[180, 360, 120, 460]);

    let symbols = Symbols::load(mh);
    let refs = xref::collect(mh);
    fill(&mut t, &symbols, &refs);
    Content::table(t)
}

fn fill(t: &mut Table, symbols: &Symbols, refs: &Xrefs) {
    for (target, items) in &refs.targets {
        let target_text = as_address(*target);
        let symbol = symbols.describe(*target);
        t.add([
            target_text.as_str(),
            symbol.as_str(),
            as_string(items.len()).as_str(),
            "",
        ]);
        for item in items {
            let mut referrer = format!(
                "{} [{}] @ raw 0x{}",
                refs.source_name(item),
                item.kind.name(),
                as_short_hex_string(item.ref_raw)
            );
            if item.ref_vm != 0 {
                referrer.push_str(&format!(" vm 0x{}", as_short_hex_string(item.ref_vm)));
            }
            t.add([target_text.as_str(), symbol.as_str(), "", referrer.as_str()]);
        }
        t.separator();
    }

    // Call graph by referring instruction.
    let mut caller_to_targets: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    for (target, items) in &refs.targets {
        for item in items {
            if item.ref_vm != 0 && item.kind.is_branch() {
                caller_to_targets
                    .entry(item.ref_vm)
                    .or_default()
                    .insert(*target);
            }
        }
    }
    if !caller_to_targets.is_empty() {
        t.add(["-", "-", "-", "Call Graph Summary"]);
        for (caller, callees) in &caller_to_targets {
            let caller_name = or_address(symbols.describe(*caller), *caller);
            t.add([
                as_address(*caller),
                caller_name,
                as_string(callees.len()),
                "caller".to_string(),
            ]);
            for callee in callees {
                let name = or_address(symbols.exact(*callee).unwrap_or("").to_string(), *callee);
                t.add([
                    as_address(*callee),
                    name,
                    String::new(),
                    "callee".to_string(),
                ]);
            }
            t.separator();
        }

        // The same, with callers merged into the function that holds them.
        let mut function_to_targets: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
        for (caller, callees) in &caller_to_targets {
            let (function, _) = symbols.function_base(*caller);
            function_to_targets
                .entry(function)
                .or_default()
                .extend(callees.iter().copied());
        }
        t.add(["-", "-", "-", "Function Call Graph (approx)"]);
        for (function, callees) in &function_to_targets {
            let (_, label) = symbols.function_base(*function);
            t.add([
                as_address(*function),
                label,
                as_string(callees.len()),
                "caller-func".to_string(),
            ]);
            for callee in callees {
                let name = match symbols.exact(*callee) {
                    Some(name) if !name.is_empty() => name.to_string(),
                    _ => match symbols.at_or_below(*callee) {
                        Some((base, name)) if *callee > *base => {
                            format!("{}+0x{}", name, as_short_hex_string(callee - base))
                        }
                        Some((_, name)) => name.clone(),
                        None => String::new(),
                    },
                };
                t.add([
                    as_address(*callee),
                    or_address(name, *callee),
                    String::new(),
                    "callee-func".to_string(),
                ]);
            }
            t.separator();
        }
    }

    if refs.targets.is_empty() {
        t.add(["-", "-", "0", "No xrefs found (pointer + disassembly scan)"]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn symbols(list: &[(u64, &str)]) -> Symbols {
        let mut s = Symbols::default();
        for (addr, name) in list {
            s.exact.insert(*addr, name.to_string());
            s.sorted.push((*addr, name.to_string()));
        }
        s.sorted.sort_by_key(|(a, _)| *a);
        s
    }

    #[test]
    fn symbol_lookup() {
        let s = symbols(&[(0x1000, "_a"), (0x2000, "_b")]);
        assert_eq!(s.describe(0x1000), "_a");
        assert_eq!(s.describe(0x1004), "_a+0x4");
        assert_eq!(s.describe(0x2abc), "_b+0xABC");
        // Below the first symbol: nothing.
        assert_eq!(s.describe(0xfff), "");
        assert_eq!(s.function_base(0x1ffc), (0x1000, "_a".to_string()));
        assert_eq!(s.function_base(0x2000), (0x2000, "_b".to_string()));
        assert_eq!(s.function_base(0x10), (0x10, "00000010".to_string()));
        assert_eq!(Symbols::default().describe(5), "");
        assert_eq!(or_address(String::new(), 0x1_0000_0000), "100000000");
    }

    #[test]
    fn empty_report() {
        let mut t = Table::new();
        fill(&mut t, &Symbols::default(), &Xrefs::default());
        assert_eq!(t.rows.len(), 1);
        assert_eq!(
            t.rows[0].cells,
            ["-", "-", "0", "No xrefs found (pointer + disassembly scan)"]
        );
    }
}
