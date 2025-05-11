use std::cmp::Reverse;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::{BufReader, Write};
use std::process::{Child, Command, ExitCode, ExitStatus, Stdio};

use anstream::stream::IsTerminal;
use anyhow::{Context, Result, bail};
use cargo_metadata::camino::Utf8PathBuf;
use cargo_metadata::{Message, MetadataCommand, TargetKind};
use clap::ArgAction;
use color_print::cwriteln;
use itertools::Itertools;

use crate::analyze::{CrateName, get_crate_name_from_artifact, sysroot_crate_names};

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
    /// Use verbose output for cargo-bloated.
    ///
    /// Note: this option is not automatically passed to `cargo` to allow
    /// individual control. Use `-- --verbose` if you want to pass it to `cargo`.
    #[arg(long, short, action = ArgAction::Count)]
    verbose: u8,
    /// Do not print log messages from cargo-bloated.
    ///
    /// Note: this option is not automatically passed to `cargo` to allow
    /// individual control. Use `-- --quiet` if you want to pass it to `cargo`.
    #[arg(long, short, conflicts_with = "verbose")]
    quiet: bool,
    /// Do not automatically use `PAGER` to long outputs.
    /// This option is implied if stdout is not TTY, `PAGER` environment is an
    /// empty string, or `--output=summary` (the default value).
    #[arg(long)]
    no_pager: bool,
    /// Coloring.
    #[arg(long, default_value_t = clap::ColorChoice::Auto)]
    color: clap::ColorChoice,

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

struct StatusWriter<'a> {
    werr: &'a mut dyn std::io::Write,
    verbosity: i8,
}

impl StatusWriter<'_> {
    fn with(
        &mut self,
        verbosity: i8,
        f: impl FnOnce(&mut dyn std::io::Write) -> std::io::Result<()>,
    ) {
        if verbosity <= self.verbosity {
            let _ = f(self.werr);
        }
    }

    fn note(&mut self, f: impl fmt::Display) {
        self.with(1, |w| cwriteln!(w, "<cyan,bold>note</>: {}", f));
    }

    fn warn(&mut self, f: impl fmt::Display) {
        self.with(-1, |w| cwriteln!(w, "<yellow,bold>warning</>: {}", f));
    }

    fn error(&mut self, f: impl fmt::Display) {
        self.with(-2, |w| cwriteln!(w, "<red,bold>error</>: {}", f));
    }
}

fn main() -> ExitCode {
    let CargoCli::Bloated(cli) = <CargoCli as clap::Parser>::parse();
    let mut werr = StatusWriter {
        // Stderr is not performance critical. Do not lock to ease debugging experience.
        werr: &mut anstream::AutoStream::new(std::io::stderr(), cli.color()),
        verbosity: if cli.quiet {
            -1
        } else {
            i8::try_from(cli.verbose).unwrap_or(i8::MAX)
        },
    };

    match main_inner(cli, &mut werr) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // Exit without additional message on broken pipe. This is a common
            // case when piping our output to a `PAGER`.
            if err
                .downcast_ref::<std::io::Error>()
                .is_some_and(|err| err.kind() == std::io::ErrorKind::BrokenPipe)
            {
                // Print nothing.
            } else {
                werr.error(format_args!("{err:#}"));
            }
            ExitCode::FAILURE
        }
    }
}

fn main_inner(mut cli: Cli, werr: &mut StatusWriter<'_>) -> Result<()> {
    let cargo_path = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());

    let cargo_meta = {
        let mut cmd = MetadataCommand::new()
            .cargo_path(&cargo_path)
            .cargo_command();
        cli.extend_cargo_metadata_args(&mut cmd);
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        werr.with(1, |werr| {
            cwriteln!(werr, "<green,bold>     Running</> {:?}", &cmd)
        });
        (|| {
            let output = cmd.output()?;
            output.status.exit_ok()?;
            let stdout = String::from_utf8(output.stdout)?;
            anyhow::Ok(MetadataCommand::parse(&stdout)?)
        })()
        .with_context(|| format!("failed to run {cmd:?}"))?
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
            .context("multiple packages are available, use `--package=NAME` to select one")?;
        let pkg = &cargo_meta[default_pkg];
        cli.package = Some(pkg.name.clone());
        pkg
    };

    let (target, target_display) = select_pkg_target(&mut cli, pkg)?;

    let mut crate_topo_order = sysroot_crate_names(werr)
        .context("failed to search std's dependencies")?
        .into_iter()
        .enumerate()
        // Also include the name without disambiguator, for legacy symbols.
        .flat_map(|(idx, name)| [(name.without_disambig(), idx), (name, idx)])
        .collect::<HashMap<CrateName, usize>>();

    let artifact = {
        let mut enc_rustflags = if let Some(s) = std::env::var_os("CARGO_ENCODED_RUSTFLAGS") {
            s.into_string()
                .ok()
                .context("CARGO_ENCODED_RUSTFLAGS is not UTF-8")?
        } else if let Some(s) = std::env::var_os("RUSTFLAGS") {
            s.to_str()
                .context("RUSTFLAGS is not UTF-8")?
                .split_ascii_whitespace()
                .join("\x1F")
        } else {
            String::new()
        };
        if !enc_rustflags.is_empty() {
            enc_rustflags.push('\x1F');
        }
        enc_rustflags.push_str("-Cprefer-dynamic\x1F-Csymbol-mangling-version=v0");

        let mut cmd = Command::new(&cargo_path);
        let profile_env = cli.profile.to_uppercase();
        cmd.args(["build", "--message-format=json-render-diagnostics"])
            .env("CARGO_ENCODED_RUSTFLAGS", enc_rustflags)
            .env(format!("CARGO_PROFILE_{profile_env}_STRIP",), "false")
            .env(format!("CARGO_PROFILE_{profile_env}_LTO"), "false")
            .stdin(Stdio::inherit())
            .stderr(Stdio::inherit())
            .stdout(Stdio::piped());
        cli.extend_cargo_build_args(&mut cmd);
        werr.with(1, |werr| {
            cwriteln!(werr, "<green,bold>     Running</> {:?}", &cmd)
        });
        let mut child = cmd
            .spawn()
            .with_context(|| format!("failed to run {cmd:?}"))?;

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
                        werr.note(format_args!(
                            "cannot resolve disambiguator from artifact {:?}: {}",
                            artifact.filenames, err,
                        ));
                    }
                    CrateName(artifact.target.name.replace("-", "_"))
                }
            };

            let next_idx = crate_topo_order.len();
            match crate_topo_order.entry(crate_name) {
                Entry::Occupied(ent) => {
                    werr.warn(format_args!(
                        "duplicated crate names without disambiguator in dependency graph, \
                        results may be incorrect: {}",
                        ent.key().0,
                    ));
                }
                Entry::Vacant(ent) => {
                    ent.insert(next_idx);
                }
            }
        }
        let st = child.wait().context("failed to wait `cargo build`")?;
        if !st.success() {
            // Build failed. Cargo already printed the message, we simply exit.
            std::process::exit(st.code().unwrap_or(1));
        }
        final_artifact.context("artifact is not produced")?
    };

    if werr.verbosity >= 1 {
        let mut ordered_crates = crate_topo_order.iter().collect::<Vec<_>>();
        ordered_crates.sort_unstable_by_key(|(_, ord)| **ord);
        let graph = ordered_crates
            .iter()
            .map(|(name, _)| name.display(true))
            .join(", ");
        werr.note(format_args!("crates in dependency graph: {graph}"));
    }

    let exe_path = artifact
        .executable
        .as_ref()
        .or_else(|| {
            artifact
                .filenames
                .iter()
                .find(|p| p.extension() == Some("so"))
        })
        .with_context(|| {
            format!(
                "cannot determine artifact path from outputs {:?}",
                artifact.filenames
            )
        })?;

    werr.with(0, |werr| {
        cwriteln!(
            werr,
            "<cyan,bold>   Analyzing</> {target_display}: {exe_path}"
        )
    });
    let report = analyze::analyze(exe_path, &crate_topo_order, werr)
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

fn select_pkg_target<'m>(
    cli: &mut Cli,
    pkg: &'m cargo_metadata::Package,
) -> Result<(&'m cargo_metadata::Target, String)> {
    let tgt_name_display = |tgt: &cargo_metadata::Target| {
        if tgt.is_cdylib() {
            "dynamic system library"
        } else {
            "dynamic Rust library"
        }
        .to_owned()
    };

    if cli.target.is_set() {
        if cli.target.lib {
            // Note: dylib and cdylib cannot be used together.
            let tgt = pkg
                .targets
                .iter()
                .find(|tgt| tgt.is_cdylib() || tgt.is_dylib())
                .context(
                    "cannot find 'cdylib' or 'dylib' target. \
                    Note that 'lib', 'rlib' and 'staticlib' are not supported yet.",
                )?;
            return Ok((tgt, tgt_name_display(tgt)));
        }

        let (expect_kind, name, display) = if let Some(name) = &cli.target.bin {
            (TargetKind::Bin, name, format!("binary {name:?}"))
        } else if let Some(name) = &cli.target.test {
            (TargetKind::Test, name, format!("test {name:?}"))
        } else if let Some(name) = &cli.target.bench {
            (TargetKind::Bench, name, format!("bench {name:?}"))
        } else if let Some(name) = &cli.target.example {
            (TargetKind::Example, name, format!("example {name:?}"))
        } else {
            unreachable!()
        };
        let tgt = pkg
            .targets
            .iter()
            .find(|tgt| tgt.is_kind(expect_kind.clone()) && *name == tgt.name)
            .context("cannot find specified target")?;
        return Ok((tgt, display));
    }

    // Prefer the only binary target. If there is no binary target, use library target.
    let bin_targets = pkg
        .targets
        .iter()
        .filter(|tgt| tgt.is_bin())
        .collect::<Vec<_>>();
    let lib_target = pkg
        .targets
        .iter()
        .find(|tgt| tgt.is_cdylib() || tgt.is_dylib());
    if let &[tgt] = &*bin_targets {
        cli.target.bin = Some(tgt.name.clone());
        Ok((tgt, format!("binary {:?}", tgt.name)))
    } else if let Some(tgt) = lib_target.filter(|_| bin_targets.is_empty()) {
        cli.target.lib = true;
        Ok((tgt, tgt_name_display(tgt)))
    } else {
        bail!(
            "cannot decide which target of package {:?} to analyze, \
            use --lib, --bin=BIN, --test=TEST or --example=EXAMPLE to select one.",
            pkg.name,
        );
    }
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

// From feature "exit_status_error": <https://github.com/rust-lang/rust/issues/84908>
trait ExitStatusExt: Sized {
    fn exit_ok(self) -> Result<()>;
}
impl ExitStatusExt for ExitStatus {
    fn exit_ok(self) -> Result<()> {
        self.success()
            .then_some(())
            .ok_or_else(|| anyhow::anyhow!("process exited unsuccessfully: {self}"))
    }
}
