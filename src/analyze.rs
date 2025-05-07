use std::collections::HashMap;

use anyhow::{Context, Result, bail};
use cargo_metadata::camino::Utf8Path;
use goblin::Object;

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
    pub display_name: String,
}

pub fn analyze(exe_path: &Utf8Path) -> Result<Report> {
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

        let idx = *addr_to_func_idx.entry(sym.st_value).or_insert_with(|| {
            let idx = ret.funcs.len();
            ret.funcs.push(Func {
                symbols: Vec::new(),
                size: sym.st_size,
            });
            idx
        });
        ret.funcs[idx].symbols.push(Symbol {
            display_name: demangled_name.unwrap_or_else(|| raw_name.clone()),
            raw_name,
        });
    }

    for f in &mut ret.funcs {
        f.symbols
            .sort_unstable_by(|lhs, rhs| Ord::cmp(&lhs.raw_name, &rhs.raw_name));
    }

    ret.funcs.sort_unstable_by(|lhs, rhs| {
        Ord::cmp(&rhs.size, &lhs.size)
            .then_with(|| Ord::cmp(&lhs.symbols[0].raw_name, &rhs.symbols[0].raw_name))
    });

    Ok(ret)
}

fn demangle_rust(raw_name: &str) -> Option<String> {
    let mut s = &*rustc_demangle::try_demangle(raw_name).ok()?.to_string();

    // Strip disambiguators in `[..]`.
    let mut out = String::with_capacity(s.len());
    while let Some(lpos) = s.find('[') {
        out.push_str(&s[..lpos]);
        s = &s[lpos..];
        match s.find(']') {
            Some(rpos) => s = &s[rpos + 1..],
            None => break,
        }
    }
    out.push_str(s);
    Some(out)
}
