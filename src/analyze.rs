use std::{
    borrow::Cow,
    cmp::Reverse,
    collections::{HashMap, HashSet},
    io::Read,
    process::{Command, Stdio},
    sync::LazyLock,
};

use anyhow::{Context, Result, bail, ensure};
use cargo_metadata::camino::Utf8Path;
use color_print::cwriteln;
use goblin::{Object, elf::Elf};
use regex_lite::Regex;
use tempfile::NamedTempFile;

use crate::StatusWriter;

/// Special cases crates that does not appear in dependency graph.
/// They are not disambiguated.
///
/// Defined in topological order.
pub const SYSROOT_CRATES: &[&str] = &["core", "alloc", "std", "proc_macro", "test"];

#[derive(Debug, Default)]
pub struct Report {
    pub unstripped: SectionReport,
    pub stripped: SectionReport,
    pub text_size: u64,
    pub funcs: Vec<Func>,
}

#[derive(Debug, Default, Clone)]
pub struct SectionReport {
    pub file_size: u64,
    pub sections: Vec<(String, u64)>,
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
    pub crate_names: Option<Vec<CrateName>>,
}

impl Symbol {
    pub fn display_name(&self, mangled: bool, with_disambig: bool) -> Cow<'_, str> {
        let Some(demangled) = self.demangled_name.as_ref().filter(|_| !mangled) else {
            return Cow::Borrowed(&self.raw_name);
        };
        if with_disambig {
            return Cow::Borrowed(demangled);
        }
        RE_DISAMBIGUATOR.replace_all(demangled, "")
    }

    pub fn display_crates(&self, with_disambig: bool) -> String {
        let Some(names) = &self.crate_names else {
            return "?".into();
        };
        let mut s = names
            .iter()
            .flat_map(|s| [s.display(with_disambig), ","])
            .collect::<String>();
        s.pop();
        s
    }

    pub fn primary_crate(&self) -> Option<&CrateName> {
        self.crate_names.as_ref()?.first()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CrateName(pub String);

impl CrateName {
    pub fn display(&self, with_disambig: bool) -> &str {
        if with_disambig {
            return &self.0;
        }
        match self.0.split_once('[') {
            Some((name, _)) => name,
            None => &self.0,
        }
    }
}

fn analyze_sections(elf: &Elf<'_>) -> Vec<(String, u64)> {
    let mut sections = Vec::with_capacity(elf.section_headers.len());
    for sh in elf.section_headers.iter() {
        let name = &elf.shdr_strtab[sh.sh_name];
        let size = sh.sh_size;
        sections.push((name.to_owned(), size));
    }
    sections.sort_by_key(|(_, size)| Reverse(*size));
    sections
}

pub fn analyze(
    bin_path: &Utf8Path,
    crate_topo_order: &HashMap<CrateName, usize>,
    werr: &mut StatusWriter<'_>,
) -> Result<Report> {
    let mut ret = Report::default();

    let bytes = std::fs::read(bin_path).context("failed to read file")?;

    let obj = Object::parse(&bytes).context("failed to parse object")?;
    let elf = match obj {
        Object::Elf(elf) => elf,
        _ => bail!("TODO: unsupported object type"),
    };

    ret.unstripped.file_size = bytes.len() as u64;
    ret.unstripped.sections = analyze_sections(&elf);

    ret.stripped = match analyze_stripped(bin_path, werr) {
        Ok(stripped) => stripped,
        Err(err) => {
            werr.error(format_args!(
                "failed to strip, fallback to use unstripped file for calculation. {}",
                err,
            ));
            ret.unstripped.clone()
        }
    };

    let text_sec_idx = elf
        .section_headers
        .iter()
        .enumerate()
        .filter(|(_, sh)| elf.shdr_strtab[sh.sh_name].starts_with(".text"))
        .map(|(idx, _)| idx)
        .collect::<Vec<_>>();
    ensure!(!text_sec_idx.is_empty(), "missing '.text' section");
    ret.text_size = text_sec_idx
        .iter()
        .map(|&i| elf.section_headers[i].sh_size)
        .sum();

    let mut addr_to_func_idx = HashMap::new();
    let mut unknown_crates = HashSet::new();

    for sym in &elf.syms {
        if !sym.is_function() || sym.st_value == 0 || sym.st_size == 0 {
            continue;
        }
        if !text_sec_idx.contains(&sym.st_shndx) {
            continue;
        }

        let raw_name = elf.strtab[sym.st_name].to_owned();
        let demangled_name = rustc_demangle::try_demangle(&raw_name)
            .ok()
            .map(|s| s.to_string());
        let crate_names = raw_name.starts_with("_R").then_some(()).and_then(|()| {
            let demangled_name = demangled_name.as_ref()?;
            let mut crates = find_func_crates(demangled_name)?
                .into_iter()
                .collect::<Vec<_>>();
            if let Some((idx, _)) = crates
                .iter()
                .enumerate()
                // Choose the latest crates in topo order, which must be the
                // latest instantiation location. Use crate name to break the tie.
                .max_by_key(|&(_, s)| {
                    let order = crate_topo_order.get(s).copied().or_else(|| {
                        let bare_name = s.display(false).to_string();
                        crate_topo_order.get(&CrateName(bare_name)).copied()
                    });
                    if order.is_none() {
                        unknown_crates.insert(s.clone());
                    }
                    // Default to max order for unknown crates, assuming they are user crates.
                    (order.unwrap_or(!0usize), s)
                })
            {
                crates.swap(0, idx);
                crates[1..].sort_unstable();
            }
            Some(crates)
        });

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

    if !unknown_crates.is_empty() {
        let mut unknown_crates = unknown_crates.into_iter().collect::<Vec<_>>();
        unknown_crates.sort_unstable();
        werr.warn(format_args!(
            "cannot locate dependencies of some crates, results may be incorrect: {:?}",
            unknown_crates,
        ));
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
                    let order = *crate_topo_order.get(&crates[0])?;
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

fn analyze_stripped(bin_path: &Utf8Path, werr: &mut StatusWriter<'_>) -> Result<SectionReport> {
    let out_file = NamedTempFile::new().context("failed to create a temp file")?;
    let strip_exe = std::env::var("STRIP").unwrap_or_else(|_| "strip".into());
    let mut cmd = Command::new(strip_exe);
    cmd.args(["-s", "-o"])
        .arg(out_file.path())
        .arg(bin_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());

    werr.with(1, |werr| {
        cwriteln!(werr, "<green,bold>     Running</> {:?}", &cmd)
    });
    let st = cmd.status().context("failed to run strip")?;
    if !st.success() {
        bail!("strip exited with {:?}", st.code());
    }

    let mut bytes = Vec::new();
    out_file
        .as_file()
        .read_to_end(&mut bytes)
        .context("failed to read stripped file")?;

    let file_size = bytes.len() as u64;
    let elf = Elf::parse(&bytes).context("failed to parse stripped binary")?;
    let sections = analyze_sections(&elf);
    Ok(SectionReport {
        file_size,
        sections,
    })
}

#[derive(Default)]
struct CrateCollector {
    crate_names: HashSet<CrateName>,
}

/// <https://rust-lang.github.io/rfcs/2603-rust-symbol-name-mangling-v0.html#syntax-of-mangled-names>
#[rustfmt::skip]
const BASIC_TYPES: &[&str] = &[
    "bool", "char", "str",
    "i8", "i16", "i32", "i64", "i128", "isize",
    "u8", "u16", "u32", "u64", "u128", "usize",
    "f32", "f64",
    // Sanitized from `_` types or names.
    "__",
];

impl CrateCollector {
    fn visit_root_name(&mut self, ident: &syn::Ident) {
        let ident = ident.to_string();
        if BASIC_TYPES.contains(&&*ident) {
            return;
        }
        let name = match ident.split_once(DISAMBIG_SEP) {
            Some((name, disambig)) => {
                if SYSROOT_CRATES.contains(&name) {
                    name.into()
                } else {
                    format!("{name}[{disambig}]")
                }
            }
            _ => ident,
        };
        self.crate_names.insert(CrateName(name));
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

static RE_DISAMBIGUATOR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\[([[:xdigit:]]+)\]").unwrap());
static RE_SANITIZE_IDENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\{[^}]*\}|\b_\b").unwrap());

const DISAMBIG_SEP: &str = "__disambig_";
const DISAMBIG_REPLACER: &str = "__disambig_$1";

fn find_func_crates(demangled_name: &str) -> Option<HashSet<CrateName>> {
    // `{closure#0}`, `{shim:vtable#0}`, `foo::_::bar`, `<foo::Foo<_>>::bar` (item inside generic item).
    let s = RE_SANITIZE_IDENT.replace_all(demangled_name, "__");
    let s = RE_DISAMBIGUATOR.replace_all(&s, DISAMBIG_REPLACER);

    let path = syn::parse_str::<syn::ExprPath>(&s).ok()?;
    let mut v = CrateCollector::default();
    syn::visit::Visit::visit_expr_path(&mut v, &path);

    // If no crate name is found, assume it to be from `std`.
    // This happens for method functions on primitive types, eg. `<[u8]>::repeat`.
    if v.crate_names.is_empty() {
        v.crate_names.insert(CrateName("std".into()));
    }
    Some(v.crate_names)
}
