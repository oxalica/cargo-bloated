use crate::{LINKER_SENTINEL_VAR, Result};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    ffi::OsStr,
    process::Stdio,
};

use anyhow::{Context, bail};
use cargo_metadata::camino::Utf8Path;
use miniserde::{Deserialize, Serialize};
use object::{Object, ObjectSection, ObjectSymbol, RelocationTarget, read::archive::ArchiveFile};
use tempfile::NamedTempFile;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct LinkerMapResult {
    pub warnings: Vec<String>,
    pub func_data_map: HashMap<String, DataUsage>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DataUsage {
    pub rodata_owned: u64,
    pub rodata_shared: u64,
    pub relro_owned: u64,
    pub relro_shared: u64,
}

#[derive(Debug, Default)]
struct SectionInfo {
    size: u64,
    ref_count: usize,
    visited: usize,
}

#[expect(clippy::print_stderr)]
pub fn main_as_linker(output_path: &OsStr) -> Result<()> {
    let args = std::env::args()
        .skip(1)
        .filter(|arg| !arg.starts_with(LINKER_SENTINEL_VAR))
        .collect::<Vec<_>>();

    let map_file = NamedTempFile::new().context("failed to create temp file")?;
    let map_file_path =
        Utf8Path::from_path(map_file.path()).context("temp file path is not UTF-8")?;

    match std::process::Command::new("gcc")
        .args(&args)
        .arg(format!("-Wl,--Map={map_file_path}"))
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
    {
        Ok(status) if status.success() => {}
        Ok(status) => {
            bail!("linker exited with {status}")
        }
        Err(err) => {
            bail!("failed to run linker: {err}")
        }
    }

    let linker_map = std::fs::read_to_string(map_file_path)
        .context("cargo-bloated: failed to read linker map file")?;

    let mut warnings = Vec::new();

    let mut kept_sections = <HashMap<String, SectionInfo>>::new();
    for line in linker_map.lines() {
        let v = line.split_ascii_whitespace().collect::<Vec<_>>();
        (|| -> Option<()> {
            let size = u64::from_str_radix(v.get(2)?, 16).ok()?;
            let orig_section = v.last()?.strip_suffix(")")?.rsplit_once(":(")?.1;
            kept_sections
                .entry(orig_section.to_owned())
                .or_default()
                .size += size;
            Some(())
        })();
    }

    let mut graph = <HashMap<String, HashSet<String>>>::new();
    for arg in &args {
        if !arg.starts_with("-")
            && (arg.ends_with(".o") || arg.ends_with(".rlib"))
            && let Err(err) = parse_file(Utf8Path::new(&arg), &mut |from, to| {
                let from = from.to_string();
                let to = to.to_string();
                if kept_sections.contains_key(&from) && kept_sections.contains_key(&to) {
                    graph.entry(from).or_default().insert(to);
                }
            })
        {
            let msg = format!("failed to parse {arg}: {err}");
            eprintln!("cargo-bloated: {msg}");
            warnings.push(msg);
        }
    }

    fn bfs(
        sections: &mut HashMap<String, SectionInfo>,
        raw_graph: &HashMap<String, HashSet<String>>,
        start: &String,
        tag: usize,
        cb: &mut dyn FnMut(&str, &mut SectionInfo),
    ) {
        let mut q = VecDeque::new();
        {
            let info = sections.get_mut(start).unwrap();
            info.visited = tag;
            // The size of starting section (.text.*) is not counted.
            q.push_back(start);
        }
        while let Some(cur) = q.pop_front() {
            for to in raw_graph.get(cur).iter().copied().flatten() {
                let info = sections.get_mut(to).unwrap();
                if info.visited == tag {
                    continue;
                }
                info.visited = tag;
                cb(to, info);
                q.push_back(to);
            }
        }
    }

    for ((from, _), tag) in graph.iter().zip(1usize..) {
        if from.starts_with(".text.") {
            bfs(&mut kept_sections, &graph, from, tag, &mut |_, info| {
                info.ref_count += 1
            });
        }
    }

    let func_data_map = graph
        .iter()
        .zip(graph.len() + 1..)
        .filter_map(|((from, _), tag)| {
            let func_name = from.strip_prefix(".text.")?;
            let func_name = func_name.strip_prefix("unlikely.").unwrap_or(func_name);

            let mut usage = <DataUsage as Default>::default();
            bfs(&mut kept_sections, &graph, from, tag, &mut |to, info| {
                let size = info.size;
                if to.starts_with(".data.rel.ro") {
                    if info.ref_count == 1 {
                        usage.relro_owned += size;
                    } else {
                        usage.relro_shared += size;
                    }
                } else if to.starts_with(".rodata") {
                    if info.ref_count == 1 {
                        usage.rodata_owned += size;
                    } else {
                        usage.rodata_shared += size;
                    }
                }
            });

            Some((func_name.to_owned(), usage))
        })
        .collect::<HashMap<String, DataUsage>>();

    let result = miniserde::json::to_string(&LinkerMapResult {
        warnings,
        func_data_map,
    });
    std::fs::write(output_path, &result)
        .expect("cargo-bloated: failed to write back parsed result");

    Ok(())
}

fn parse_file(path: &Utf8Path, cb: &mut dyn FnMut(&str, &str)) -> Result<()> {
    let blob = std::fs::read(path).unwrap();
    if path.extension() == Some("rlib") {
        let ar = ArchiveFile::parse(&blob[..]).unwrap();
        for member in ar.members() {
            let member = member.unwrap();
            if member.name().ends_with(b".o") {
                let file_blob = member.data(&blob[..]).unwrap();
                let file = object::File::parse(file_blob).unwrap();
                parse_object(&file, cb).unwrap();
            }
        }
    } else {
        let file = object::File::parse(&blob[..]).unwrap();
        parse_object(&file, cb).unwrap();
    }
    Ok(())
}

fn parse_object(file: &object::File<'_>, cb: &mut dyn FnMut(&str, &str)) -> Result<()> {
    for sec in file.sections() {
        let Some(src_name) = sec
            .name()
            .ok()
            .filter(|s| s.starts_with(".text.") || s.starts_with(".data"))
        else {
            continue;
        };

        sec.relocations()
            .filter_map(|(_, reloc)| {
                let RelocationTarget::Symbol(sym_idx) = reloc.target() else {
                    return None;
                };
                let tgt_sym = file.symbol_by_index(sym_idx).ok()?;
                let tgt_name = match tgt_sym.section().index() {
                    Some(sec_idx) => file.section_by_index(sec_idx).ok()?.name().ok()?,
                    None => tgt_sym.name().unwrap_or(""),
                };
                if !tgt_name.starts_with(".rodata") && !tgt_name.starts_with(".data") {
                    return None;
                }
                Some(tgt_name)
            })
            .for_each(|tgt_name| cb(src_name, tgt_name));
    }

    Ok(())
}
