use std::{
    collections::{HashMap, HashSet},
    sync::OnceLock,
};

use anyhow::{Context, Result, bail};
use cargo_metadata::camino::Utf8Path;
use goblin::Object;
use regex_lite::Regex;

#[derive(Debug, Default)]
pub struct Report {
    pub file_size: u64,
    pub text_size: u64,
    pub rodata_size: u64,
    pub data_size: u64,
    pub bss_size: u64,

    pub funcs: Vec<Func>,
}

#[derive(Debug)]
pub struct Func {
    pub symbols: Vec<Symbol>,
    pub size: u64,
}

#[derive(Debug)]
pub struct Symbol {
    pub raw_name: String,
    pub demangled_name: Option<String>,
    pub crate_names: Option<Vec<String>>,
}

impl Symbol {
    pub fn display_name(&self) -> &str {
        self.demangled_name.as_deref().unwrap_or(&self.raw_name)
    }

    pub fn display_crates(&self) -> String {
        let Some(names) = &self.crate_names else {
            return "?".into();
        };
        let mut s = names.iter().flat_map(|s| [s, ","]).collect::<String>();
        s.pop();
        s
    }

    pub fn primary_crate(&self) -> Option<&str> {
        Some(self.crate_names.as_ref()?.first()?)
    }
}

pub fn analyze(exe_path: &Utf8Path, crate_topo_order: &HashMap<&str, usize>) -> Result<Report> {
    let mut ret = Report::default();

    let bytes = std::fs::read(exe_path).context("failed to read file")?;
    ret.file_size = bytes.len() as u64;

    let obj = Object::parse(&bytes).context("failed to parse object")?;
    let elf = match obj {
        Object::Elf(elf) => elf,
        _ => bail!("TODO: unsupported object type"),
    };

    let mut text_sec_idx = Vec::with_capacity(4);
    for (idx, sh) in elf.section_headers.iter().enumerate() {
        let name = &elf.shdr_strtab[sh.sh_name];
        let size = sh.sh_size;
        if name.starts_with(".text") {
            ret.text_size += size;
            text_sec_idx.push(idx);
        } else if name.starts_with(".rodata") || name.starts_with(".lrodata") {
            ret.rodata_size += size;
        } else if name.starts_with(".bss") || name.starts_with(".lbss") {
            ret.bss_size += size;
        } else if name.starts_with(".data") || name.starts_with(".ldata") {
            ret.data_size += size;
        }
    }

    let mut addr_to_func_idx = HashMap::new();

    for sym in &elf.syms {
        if !sym.is_function() || sym.st_value == 0 || sym.st_size == 0 {
            continue;
        }
        if !text_sec_idx.contains(&sym.st_shndx) {
            continue;
        }

        let raw_name = elf.strtab[sym.st_name].to_owned();
        let demangled_name = demangle_rust(&raw_name);
        let crate_names = if raw_name.starts_with("_R") {
            demangled_name.as_ref().and_then(|s| {
                let mut crates = find_func_crates(s)?.into_iter().collect::<Vec<_>>();
                if let Some((idx, _)) = crates
                    .iter()
                    .enumerate()
                    // Choose the latest crates in topo order, which must be the
                    // latest instantiation location. Use crate name to break the tie.
                    .max_by_key(|(_, s)| (crate_topo_order.get(s.as_str()), *s))
                {
                    crates.swap(0, idx);
                    crates[1..].sort_unstable();
                }
                Some(crates)
            })
        } else {
            // Not a Rust symbol.
            Some(["-".into()].into())
        };

        let idx = *addr_to_func_idx.entry(sym.st_value).or_insert_with(|| {
            let idx = ret.funcs.len();
            ret.funcs.push(Func {
                symbols: Vec::new(),
                size: sym.st_size,
            });
            idx
        });
        ret.funcs[idx].symbols.push(Symbol {
            raw_name,
            demangled_name,
            crate_names,
        });
    }

    for f in &mut ret.funcs {
        // Try to select a good representative symbol name, with its
        // max-topo-order (primary crate) being the minimum (earliest) among all
        // other aliases.
        //
        // Eg.
        // - `core::mem::drop_in_place::<std::string::String>` primary = std
        // - `core::mem::drop_in_place::<my_crate::StringLike>` primary = my_crate
        // Here the second function is "zero-cost" because it's already
        // instantiated by its dependency.
        let sort_range = if let Some((idx, _)) = f
            .symbols
            .iter()
            .enumerate()
            .map(|(idx, sym)| {
                let order = (|| {
                    let crates = sym.crate_names.as_ref()?;
                    let order = *crate_topo_order.get(crates[0].as_str())?;
                    Some(order)
                })()
                .unwrap_or(!0usize);
                (idx, order)
            })
            .min_by_key(|(_, order)| *order)
            // If all candidates are "bad", do not promote anyone.
            // Just sort alphabetically.
            .filter(|(_, order)| *order != !0usize)
        {
            f.symbols.swap(0, idx);
            &mut f.symbols[1..]
        } else {
            &mut f.symbols
        };

        sort_range.sort_unstable_by(|lhs, rhs| Ord::cmp(&lhs.raw_name, &rhs.raw_name));
    }

    ret.funcs.sort_unstable_by(|lhs, rhs| {
        Ord::cmp(&rhs.size, &lhs.size)
            .then_with(|| Ord::cmp(&lhs.symbols[0].raw_name, &rhs.symbols[0].raw_name))
    });

    Ok(ret)
}

fn demangle_rust(raw_name: &str) -> Option<String> {
    static RE_REMOVE_DISAMBIGUATOR: OnceLock<Regex> = OnceLock::new();
    let re = RE_REMOVE_DISAMBIGUATOR.get_or_init(|| Regex::new(r"\[[[:xdigit:]]+\]").unwrap());
    let s = rustc_demangle::try_demangle(raw_name).ok()?.to_string();
    let s = re.replace_all(&s, "").into_owned();
    Some(s)
}

#[derive(Default)]
struct CrateCollector {
    crate_names: HashSet<String>,
}

/// <https://rust-lang.github.io/rfcs/2603-rust-symbol-name-mangling-v0.html#syntax-of-mangled-names>
#[rustfmt::skip]
const BASIC_TYPES: &[&str] = &[
    "bool", "char", "str",
    "i8", "i16", "i32", "i64", "i128", "isize",
    "u8", "u16", "u32", "u64", "u128", "usize",
    "f32", "f64",
];

impl CrateCollector {
    fn visit_root_name(&mut self, name: &syn::Ident) {
        let name = name.to_string();
        if !BASIC_TYPES.contains(&&*name) {
            self.crate_names.insert(name);
        }
    }
}

impl syn::visit::Visit<'_> for CrateCollector {
    fn visit_expr_path(&mut self, i: &'_ syn::ExprPath) {
        if i.qself.is_none() {
            if let Some(s) = i.path.segments.first() {
                self.visit_root_name(&s.ident);
            }
        }
        syn::visit::visit_expr_path(self, i);
    }

    fn visit_type_path(&mut self, i: &'_ syn::TypePath) {
        if i.qself.is_none() {
            if let Some(s) = i.path.segments.first() {
                self.visit_root_name(&s.ident);
            }
        }
        syn::visit::visit_type_path(self, i);
    }
}

fn find_func_crates(demangled_name: &str) -> Option<HashSet<String>> {
    static RE_REMOVE_CLOSURE_SHIM: OnceLock<Regex> = OnceLock::new();
    let re = RE_REMOVE_CLOSURE_SHIM.get_or_init(|| Regex::new(r"\{[^}]*\}").unwrap());
    let s = re.replace_all(demangled_name, "__");

    let path = syn::parse_str::<syn::ExprPath>(&s).ok()?;
    let mut v = CrateCollector::default();
    syn::visit::Visit::visit_expr_path(&mut v, &path);

    // If no crate name is found, assume it to be from `std`.
    // This happens for method functions on primitive types, eg. `<[u8]>::repeat`.
    if v.crate_names.is_empty() {
        v.crate_names.insert("std".into());
    }
    Some(v.crate_names)
}
