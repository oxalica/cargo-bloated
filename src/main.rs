use std::cmp::Reverse;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::{BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::LazyLock;

use anstream::stream::IsTerminal;
use anyhow::{Context, Result, bail};
use cargo_metadata::camino::Utf8PathBuf;
use cargo_metadata::{Artifact, Message, MetadataCommand, TargetKind};
use color_print::cwriteln;
use regex_lite::Regex;

use crate::analyze::{CrateName, SYSROOT_CRATES};

mod analyze;

#[derive(Debug, clap::Parser)]
#[command(name = "cargo")]
#[command(bin_name = "cargo")]
enum CargoCli {
    Bloated(Cli),
}

/// Find out what takes most of the space in your executable, more accurately.
#[derive(Debug, clap::Args)]
struct Cli {
    /// Print mangled names without demangling.
    #[arg(long)]
    mangled: bool,
    /// Include disambiguators for demangled crate names.
    #[arg(long)]
    disambiguator: bool,
    /// Use verbose output.
    #[arg(long, short)]
    verbose: bool,
    /// Output format for analysis report.
    ///
    /// Output fields for `--output=functions`:
    /// - `File`  : The function size percentage of the stripped binary.
    /// - `.text` : The function size percentage of the ".text" sections.
    /// - `Size`  : The absolute function size.
    /// - `Crates`: Crates referenced by this symbol. The first one is the earliest instantiator to blame.
    /// - `Name`  : The demangled (or mangled if `--mangled` is set) symbol name.
    ///
    /// Output fields for `--output=crates`:
    /// - `File`  : The crate size percentage of the stripped binary.
    /// - `.text` : The crate size percentage of the ".text" sections.
    /// - `Size`  : The accumulated size of all functions introduced (earliest instantiation) by this crate.
    /// - `Crate` : The crate name.
    #[arg(long, value_enum, default_value_t, verbatim_doc_comment)]
    output: OutputMode,
    /// Do not automatically use `PAGER` to long outputs.
    /// This option is implied if stdout is not TTY, `PAGER` environment is an
    /// empty string, or `--output=summary` (the default value).
    #[arg(long)]
    no_pager: bool,
    /// Coloring.
    #[arg(long, default_value_t = clap::ColorChoice::Auto)]
    color: clap::ColorChoice,

    /// (unstable) Change how to decide which crate to blame for a given symbol.
    #[arg(long, default_value = "primary", hide = true)]
    crate_grouping: CrateGrouping,

    #[command(flatten)]
    target: Target,
    /// No effect. We already use `release` profile by default.
    #[arg(long)]
    release: bool,
    /// Select a profile other than `release` to analyze.
    #[arg(long, default_value = "release")]
    profile: String,
    /// Package to build
    #[arg(long, short)]
    package: Option<String>,

    #[command(flatten)]
    passthru: PassthruOpts,

    /// Arbitrary additional options to be passed to `cargo build`.
    #[arg(last = true)]
    build_args: Vec<OsString>,
}

#[derive(Debug, clap::Args)]
struct PassthruOpts {
    /// Passthru option of `cargo`.
    #[arg(long)]
    manifest_path: Option<Utf8PathBuf>,
    /// Passthru option of `cargo`.
    #[arg(long)]
    lockfile_path: Option<Utf8PathBuf>,
    /// Passthru option of `cargo`.
    #[arg(long)]
    locked: bool,
    /// Passthru option of `cargo`.
    #[arg(long)]
    offline: bool,
    /// Passthru option of `cargo`.
    #[arg(long)]
    frozen: bool,
    /// Passthru option of `cargo`.
    #[arg(long)]
    no_default_features: bool,
    /// Passthru option of `cargo`.
    #[arg(long)]
    all_features: bool,
    /// Passthru option of `cargo`.
    #[arg(long, short = 'F', value_delimiter = ',')]
    features: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
enum OutputMode {
    /// Print a short summary for human, including file size, some top largest
    /// ELF sections and functions.
    #[default]
    Summary,
    /// Print file size and ELF sections sorted by reversed size.
    Sections,
    /// Print functions sorted by reversed size.
    Functions,
    /// Print crates size estimation sorted by reversed size.
    Crates,
}

#[derive(Debug, Default, Clone, clap::ValueEnum)]
enum CrateGrouping {
    #[default]
    Primary,
    Mention,
}

#[derive(Debug, clap::Args)]
#[group(multiple = false)]
struct Target {
    /// Build and analyze this package's library.
    #[arg(long)]
    lib: bool,

    /// Build and analyze the specified binary.
    #[arg(long)]
    bin: Option<String>,

    /// Build and analyze the specified test target.
    #[arg(long)]
    test: Option<String>,

    /// Build and analyze the specified bench target.
    #[arg(long)]
    bench: Option<String>,

    /// Build and analyze the specified example target.
    #[arg(long)]
    example: Option<String>,
}

impl Target {
    fn is_set(&self) -> bool {
        self.lib
            || self.bin.is_some()
            || self.test.is_some()
            || self.bench.is_some()
            || self.example.is_some()
    }
}

impl Cli {
    fn color(&self) -> anstream::ColorChoice {
        match self.color {
            clap::ColorChoice::Auto => anstream::ColorChoice::Auto,
            clap::ColorChoice::Always => anstream::ColorChoice::Always,
            clap::ColorChoice::Never => anstream::ColorChoice::Never,
        }
    }

    fn extend_cargo_build_args(&self, cmd: &mut Command) {
        if self.target.lib {
            // FIXME: This should also recognize dylib and staticlib.
            cmd.arg("--lib");
        } else if let Some(name) = &self.target.bin {
            cmd.arg("--bin").arg(name);
        } else if let Some(name) = &self.target.test {
            cmd.arg("--test").arg(name);
        } else if let Some(name) = &self.target.bench {
            cmd.arg("--bench").arg(name);
        } else if let Some(name) = &self.target.example {
            cmd.arg("--example").arg(name);
        } else {
            panic!("target not set");
        }

        cmd.arg("--profile").arg(&self.profile);

        if let Some(pkg) = &self.package {
            cmd.arg("--package").arg(pkg);
        }

        self.extend_cargo_metadata_args(cmd);
        cmd.args(&self.build_args);
    }

    fn extend_cargo_metadata_args(&self, cmd: &mut Command) {
        cmd.arg("--color")
            .arg(self.color.to_string())
            .args(
                self.passthru
                    .no_default_features
                    .then_some("--no-default-features"),
            )
            .args(self.passthru.all_features.then_some("--all-features"))
            .args(self.passthru.locked.then_some("--locked"))
            .args(self.passthru.offline.then_some("--offline"))
            .args(self.passthru.frozen.then_some("--frozen"));
        if !self.passthru.features.is_empty() {
            cmd.arg("--features").arg(self.passthru.features.join(","));
        }
        if let Some(path) = &self.passthru.manifest_path {
            cmd.arg("--manifest-path").arg(path);
        }
    }
}

fn main() -> Result<()> {
    let CargoCli::Bloated(cli) = <CargoCli as clap::Parser>::parse();
    match main_inner(cli) {
        Ok(()) => Ok(()),
        Err(err) => {
            // Exit without additional message on broken pipe. This is a common
            // case when piping our output to a `PAGER`.
            if err
                .downcast_ref::<std::io::Error>()
                .is_some_and(|err| err.kind() == std::io::ErrorKind::BrokenPipe)
            {
                std::process::exit(1);
            }
            Err(err)
        }
    }
}

fn main_inner(mut cli: Cli) -> Result<()> {
    let cargo_path = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    // Stderr is not performance critical. Do not lock to ease debugging experience.
    let mut werr = anstream::AutoStream::new(std::io::stderr(), cli.color());

    let cargo_meta = {
        let mut cmd = MetadataCommand::new()
            .cargo_path(&cargo_path)
            .cargo_command();
        cli.extend_cargo_metadata_args(&mut cmd);
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        if cli.verbose {
            let _ = cwriteln!(werr, "<green,bold>     Running</> {:?}", &cmd);
        }
        let output = cmd.output().context("failed to run `cargo metadata`")?;
        if !output.status.success() {
            std::process::exit(output.status.code().unwrap_or(1));
        }

        let output_str =
            String::from_utf8(output.stdout).context("output of `cargo metadata` is not UTF-8")?;
        MetadataCommand::parse(output_str).context("failed to parse output of `cargo metadata`")?
    };

    // Find the specific package, or auto-select the only or the default package from workspace.
    let pkg = if let Some(pkg_name) = &cli.package {
        cargo_meta
            .workspace_packages()
            .into_iter()
            .find(|pkg| pkg.name == *pkg_name)
            .with_context(|| format!("cannot find workspace package {pkg_name}"))?
    } else {
        let mut default_pkg = None;
        if cargo_meta.workspace_members.len() == 1 {
            default_pkg = Some(&cargo_meta.workspace_members[0])
        } else if cargo_meta.workspace_default_members.is_available() {
            let default_members = &*cargo_meta.workspace_default_members;
            if default_members.len() == 1 {
                default_pkg = Some(&default_members[0]);
            }
        }
        let default_pkg = default_pkg
            .context("multiple packages are available, use `--package` to select one")?;
        let pkg = &cargo_meta[default_pkg];
        cli.package = Some(pkg.name.clone());
        pkg
    };

    let target = if cli.target.is_set() {
        let (tgt_kind, name) = if cli.target.lib {
            (TargetKind::Lib, None)
        } else if let Some(name) = &cli.target.bin {
            (TargetKind::Bin, Some(name))
        } else if let Some(name) = &cli.target.test {
            (TargetKind::Test, Some(name))
        } else if let Some(name) = &cli.target.bench {
            (TargetKind::Bench, Some(name))
        } else if let Some(name) = &cli.target.example {
            (TargetKind::Example, Some(name))
        } else {
            unreachable!()
        };
        pkg.targets
            .iter()
            .find(|tgt| tgt.is_kind(tgt_kind.clone()) && name.is_none_or(|name| *name == tgt.name))
            .context("cannot found specified target")?
    } else {
        // Only auto-select lib or bin targets.
        let targets = pkg
            .targets
            .iter()
            .filter(|tgt| tgt.is_lib() || tgt.is_bin())
            .collect::<Vec<_>>();

        if targets.len() != 1 {
            bail!(
                "multiple targets are available for package '{}', \
                use --lib, --bin=BIN, --test=TEST or --example=EXAMPLE to select one",
                pkg.name,
            );
        }
        let tgt = targets[0];
        if tgt.is_lib() {
            cli.target.lib = true;
        } else {
            cli.target.bin = Some(tgt.name.clone());
        }
        tgt
    };

    let mut crate_topo_order = SYSROOT_CRATES
        .iter()
        .enumerate()
        .map(|(idx, &name)| (CrateName(name.to_owned()), idx))
        .collect::<HashMap<CrateName, usize>>();

    let artifact = {
        let mut cmd = Command::new(&cargo_path);
        let profile_env = cli.profile.to_uppercase();
        cmd.args(["build", "--message-format=json-render-diagnostics"])
            // FIXME: Encode, inherit.
            .env("RUSTFLAGS", "-Cprefer-dynamic -Csymbol-mangling-version=v0")
            .env(format!("CARGO_PROFILE_{profile_env}_STRIP",), "false")
            .env(format!("CARGO_PROFILE_{profile_env}_LTO"), "false")
            .stdin(Stdio::inherit())
            .stderr(Stdio::inherit())
            .stdout(Stdio::piped());
        cli.extend_cargo_build_args(&mut cmd);
        if cli.verbose {
            let _ = cwriteln!(werr, "<green,bold>     Running</> {:?}", &cmd);
        }
        let mut child = cmd.spawn().context("failed to run `cargo build`")?;

        let reader = BufReader::new(child.stdout.take().unwrap());
        let mut final_artifact = None;
        for msg in Message::parse_stream(reader) {
            let Message::CompilerArtifact(artifact) = msg? else {
                continue;
            };
            let is_target_crate = artifact.package_id == pkg.id && artifact.target == *target;
            if is_target_crate {
                final_artifact = Some(artifact.clone());
            }
            if artifact.target.is_proc_macro() || artifact.target.is_custom_build() {
                continue;
            }

            let crate_name = match get_crate_name_from_artifact(&artifact) {
                Ok(crate_name) => crate_name,
                Err(err) => {
                    if !is_target_crate {
                        let _ = cwriteln!(
                            werr,
                            "<yellow,bold>warning</>: cannot resolve disambiguator from artifact {:?}, results may be incorrect: {}",
                            artifact.filenames,
                            err,
                        );
                    }
                    CrateName(artifact.target.name.replace("-", "_"))
                }
            };

            let next_idx = crate_topo_order.len();
            match crate_topo_order.entry(crate_name) {
                Entry::Occupied(ent) => {
                    let _ = cwriteln!(
                        werr,
                        "<yellow,bold>warning</>: duplicated crate names in dependency graph, results may be incorrect: {}",
                        ent.key().0,
                    );
                }
                Entry::Vacant(ent) => {
                    ent.insert(next_idx);
                }
            }
        }
        let st = child.wait().context("failed to wait `cargo build`")?;
        if !st.success() {
            std::process::exit(st.code().unwrap_or(1));
        }
        final_artifact.context("artifact is not produced")?
    };

    if cli.verbose {
        let mut ordered_crates = crate_topo_order.iter().collect::<Vec<_>>();
        ordered_crates.sort_unstable_by_key(|(_, ord)| **ord);
        let mut out = ordered_crates
            .iter()
            .flat_map(|(name, _)| [name.display(true), ", "])
            .collect::<String>();
        out.pop();
        out.pop();
        let _ = cwriteln!(werr, "crates in dependency graph: {out}");
    }

    let exe_path = artifact
        .executable
        .as_ref()
        .or_else(|| {
            artifact
                .filenames
                .iter()
                .find(|p| p.extension() == Some("rlib"))
        })
        .with_context(|| {
            format!(
                "cannot determine artifact path from outputs {:?}",
                artifact.filenames
            )
        })?;

    let _ = cwriteln!(werr, "<cyan,bold>   Analyzing</> {exe_path}");
    let report = analyze::analyze(exe_path, &crate_topo_order, &mut werr, cli.verbose)
        .with_context(|| format!("failed to analyze file: {exe_path}"))?;

    // Setup pager for output, if possible.
    let mut stdout = std::io::stdout().lock();
    // Emit colors early based on the stdout, not the pipe of the pager.
    let stdout_color = anstream::AutoStream::choice(&stdout);
    let mut pager_child = None;
    let w: &mut dyn std::io::Write =
        if cli.no_pager || cli.output == OutputMode::Summary || !stdout.is_terminal() {
            &mut stdout
        } else if let Some(child) = detect_spawn_pager() {
            pager_child.insert(child).stdin.as_mut().unwrap()
        } else {
            &mut stdout
        };
    let mut w = anstream::AutoStream::new(w, stdout_color);

    let (show_sections, show_crates, show_functions) = match cli.output {
        OutputMode::Summary => (Some(4), Some(8), Some(8)),
        OutputMode::Sections => (Some(usize::MAX), None, None),
        OutputMode::Crates => (None, Some(usize::MAX), None),
        OutputMode::Functions => (None, None, Some(usize::MAX)),
    };
    let stripped_size = report.stripped.file_size;
    let unstripped_size = report.unstripped.file_size;

    // Sections.
    if let Some(max_len) = show_sections {
        cwriteln!(w, "<underline,bold>   File   Size Section</>",)?;
        cwriteln!(w, "<dim>100.0% {} (file)</>", ByteSize(stripped_size))?;
        if stripped_size != unstripped_size {
            cwriteln!(
                w,
                "<dim>{:>5.1}% {} (unstripped)</>",
                perc(unstripped_size, stripped_size),
                ByteSize(unstripped_size),
            )?;
        }
        for (name, size) in report.stripped.sections.iter().take(max_len) {
            writeln!(
                w,
                "{:>5.1}% {} {}",
                perc(*size, stripped_size),
                ByteSize(*size),
                name,
            )?;
        }
        writeln!(w)?;
    }

    // Crates.
    if let Some(max_len) = show_crates {
        let unknown_crate = CrateName("?".into());
        let mut crate_tally = <HashMap<&CrateName, u64>>::new();
        for func in &report.funcs {
            let sym = &func.symbols[0];
            match cli.crate_grouping {
                CrateGrouping::Primary => {
                    let name = sym.primary_crate().unwrap_or(&unknown_crate);
                    *crate_tally.entry(name).or_default() += func.size;
                }
                CrateGrouping::Mention => {
                    for name in sym.crate_names.iter().flatten() {
                        *crate_tally.entry(name).or_default() += func.size;
                    }
                }
            }
        }
        let mut crate_tally = crate_tally.into_iter().collect::<Vec<_>>();
        crate_tally.sort_unstable_by_key(|&(name, size)| (Reverse(size), name));
        let sum = crate_tally.iter().map(|(_, size)| size).sum::<u64>();

        cwriteln!(w, "<underline,bold>  File  .text    Size  Crate</>")?;
        cwriteln!(
            w,
            "<dim>{:>5.1}% {:>5.1}% {}  *</>",
            perc(sum, stripped_size),
            perc(sum, report.text_size),
            ByteSize(sum),
        )?;
        for &(name, size) in crate_tally.iter().take(max_len) {
            writeln!(
                w,
                "{:>5.1}% {:>5.1}% {}  {}",
                perc(size, stripped_size),
                perc(size, report.text_size),
                ByteSize(size),
                name.display(cli.disambiguator),
            )?;
        }
        writeln!(w)?;
    }

    // Functions.
    if let Some(max_len) = show_functions {
        cwriteln!(
            w,
            "<underline,bold>  File  .text    Size  Crates                           Name</>"
        )?;
        for func in report.funcs.iter().take(max_len) {
            writeln!(
                w,
                "{:>5.1}% {:>5.1}% {}  {:32} {}",
                perc(func.size, stripped_size),
                perc(func.size, report.text_size),
                ByteSize(func.size),
                func.symbols[0].display_crates(cli.disambiguator),
                func.symbols[0].display_name(cli.mangled, cli.disambiguator),
            )?;
            for sym in &func.symbols[1..] {
                cwriteln!(
                    w,
                    "<dim>                       {:32} {}</>",
                    sym.display_crates(cli.disambiguator),
                    sym.display_name(cli.mangled, cli.disambiguator),
                )?;
            }
        }
    }

    if let Some(mut child) = pager_child {
        // Flush and drop the pipe, indicating EOF.
        child.stdin.take();
        child.wait().context("failed to wait pager")?;
    }

    Ok(())
}

fn perc(x: u64, y: u64) -> f32 {
    x as f32 / y as f32 * 100.0
}

fn get_crate_name_from_artifact(artifact: &Artifact) -> Result<CrateName> {
    static RE_DISAMBIG_HASH: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\.[[:xdigit:]]+-cgu").unwrap());

    let bare_name = artifact.target.name.replace("-", "_");

    let rlib_path = artifact
        .filenames
        .iter()
        .find(|path| path.extension() == Some("rlib"))
        .context("missing rlib output")?;
    let bytes = std::fs::read(rlib_path).with_context(|| format!("failed to read {rlib_path}"))?;
    let archive = goblin::archive::Archive::parse(&bytes)
        .with_context(|| format!("failed to parse {rlib_path}"))?;
    for member in archive.members() {
        if let Some(m) = RE_DISAMBIG_HASH.find(member) {
            let m = m.as_str();
            let meta = &m[1..m.len() - 4];
            return Ok(CrateName(format!("{bare_name}[{meta}]")));
        }
    }

    bail!("cannot find disambiguator from rlib");
}

fn detect_spawn_pager() -> Option<Child> {
    fn try_spawn(s: &[&OsStr]) -> Option<Child> {
        Command::new(s[0])
            .stdin(Stdio::piped())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .args(&s[1..])
            .spawn()
            .ok()
    }

    let pager = std::env::var_os("PAGER");
    if pager == Some(Default::default()) {
        // Explicitly disabled.
        return None;
    }

    // Prefer `less` for custom options.
    if let Ok(less_path) = which::which_global("less") {
        if let Some(child) = try_spawn(&[
            less_path.as_ref(),
            "--chop-long-lines".as_ref(),
            "--RAW-CONTROL-CHARS".as_ref(),
        ]) {
            return Some(child);
        }
    }

    if let Some(pager) = pager {
        if let Some(child) = try_spawn(&["/bin/sh".as_ref(), "-c".as_ref(), pager.as_ref()]) {
            return Some(child);
        }
    }
    try_spawn(&["more".as_ref()])
}

// Byte size display, but with number and unit aligned.
struct ByteSize(u64);

impl fmt::Display for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let x = self.0;
        if x < (2 << 10) {
            return write!(f, "{x:>4}  B");
        }
        let (y, unit) = if x < (2 << 20) {
            (x as f32 / (1 << 10) as f32, "KiB")
        } else if x < (2 << 30) {
            (x as f32 / (1 << 20) as f32, "MiB")
        } else {
            (x as f32 / (1 << 30) as f32, "GiB")
        };
        // 1.23KiB
        // 12.3KiB
        //  123KiB
        // 1234KiB
        let prec = if y < 10.0 {
            2
        } else if y < 100.0 {
            1
        } else {
            0
        };
        write!(f, "{y:>4.prec$}{unit}")
    }
}
