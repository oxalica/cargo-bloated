use std::io::BufReader;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use bytesize::ByteSize;
use cargo_metadata::camino::Utf8PathBuf;
use cargo_metadata::{Message, MetadataCommand, TargetKind};

mod analyze;

/// Find out what takes most of the space in your binary.
#[derive(Debug, clap::Parser)]
#[command(name = "cargo")]
#[command(bin_name = "cargo")]
enum CargoCli {
    Bloated(Cli),
}

#[derive(Debug, clap::Args)]
struct Cli {
    #[command(flatten)]
    target: Target,
    #[arg(long, default_value = "release")]
    profile: String,
    #[arg(long)]
    ignore_rust_version: bool,
    #[arg(long, short)]
    package: Option<String>,

    #[arg(long)]
    no_default_features: bool,
    #[arg(long, conflicts_with = "no_default_features")]
    all_features: bool,
    #[arg(long, short = 'F', value_delimiter = ',')]
    features: Vec<String>,
    #[arg(long)]
    locked: bool,
    #[arg(long)]
    offline: bool,
    #[arg(long)]
    frozen: bool,
    #[arg(long)]
    manifest_path: Option<Utf8PathBuf>,
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

        cmd.arg("--profile")
            .arg(&self.profile)
            .args(self.ignore_rust_version.then_some("--ignore-rust-version"));

        if let Some(pkg) = &self.package {
            cmd.arg("--package").arg(pkg);
        }

        self.extend_cargo_metadata_args(cmd);
    }

    fn extend_cargo_metadata_args(&self, cmd: &mut Command) {
        cmd.args(self.no_default_features.then_some("--no-default-features"))
            .args(self.all_features.then_some("--all-features"))
            .args(self.locked.then_some("--locked"))
            .args(self.offline.then_some("--offline"))
            .args(self.frozen.then_some("--frozen"));
        if !self.features.is_empty() {
            cmd.arg("--features").arg(self.features.join(","));
        }
        if let Some(path) = &self.manifest_path {
            cmd.arg("--manifest-path").arg(path);
        }
    }
}

fn main() -> Result<()> {
    let CargoCli::Bloated(mut cli) = <CargoCli as clap::Parser>::parse();

    let cargo_path = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());

    let cargo_meta = {
        let mut cmd = MetadataCommand::new()
            .cargo_path(&cargo_path)
            .cargo_command();
        cli.extend_cargo_metadata_args(&mut cmd);
        let output = cmd
            .stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .output()
            .context("failed to run `cargo metadata`")?;
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

    let artifact = {
        let mut cmd = Command::new("cargo");
        cmd.args(["build", "--message-format=json-render-diagnostics"])
            // FIXME: Encode, inherit.
            .env("RUSTFLAGS", "-Cprefer-dynamic -Csymbol-mangling-version=v0")
            .env(format!("CARGO_PROFILE_{}_STRIP", cli.profile), "none")
            .stdin(Stdio::inherit())
            .stderr(Stdio::inherit())
            .stdout(Stdio::piped());
        cli.extend_cargo_build_args(&mut cmd);
        let mut child = cmd.spawn().context("failed to run `cargo build`")?;

        let reader = BufReader::new(child.stdout.take().unwrap());
        let mut final_artifact = None;
        for msg in Message::parse_stream(reader) {
            match msg? {
                Message::CompilerArtifact(artifact)
                    if artifact.package_id == pkg.id && artifact.target == *target =>
                {
                    final_artifact = Some(artifact);
                }
                _ => {}
            }
        }
        let st = child.wait().context("failed to wait `cargo build`")?;
        if !st.success() {
            std::process::exit(st.code().unwrap_or(1));
        }
        final_artifact.context("artifact is not produced")?
    };

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

    eprintln!("   Analyzing {exe_path}");
    let report = analyze::analyze(exe_path)
        .with_context(|| format!("failed to analyze file: {exe_path}"))?;

    let perc = |x: u64, y: u64| x as f32 / y as f32 * 100.0;

    #[rustfmt::skip]
    {
        println!("File size: {:>10}", ByteSize(report.file_size));
        println!("    .text: {:>10} {:>5.1}%", ByteSize(report.text_size), perc(report.text_size, report.file_size));
        println!("  .rodata: {:>10} {:>5.1}%", ByteSize(report.rodata_size), perc(report.rodata_size, report.file_size));
        println!("    .data: {:>10} {:>5.1}%", ByteSize(report.data_size), perc(report.data_size, report.file_size));
        println!("     .bss: {:>10} {:>5.1}%", ByteSize(report.bss_size), perc(report.bss_size, report.file_size));
        println!();
    };

    println!("  File  .text       Size Name");
    for func in &report.funcs {
        println!(
            "{:>5.1}% {:>5.1}% {:>10} {}",
            func.size as f32 / report.file_size as f32 * 100.0,
            func.size as f32 / report.text_size as f32 * 100.0,
            ByteSize(func.size),
            func.demangled_name.as_deref().unwrap_or(&func.raw_name),
        );
    }

    Ok(())
}
