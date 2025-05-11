# cargo-bloated

[![github](https://img.shields.io/crates/v/cargo-bloated)](https://crates.io/crates/cargo-bloated)
[![crates.io](https://img.shields.io/crates/v/cargo-bloated)](https://crates.io/crates/cargo-bloated)

Find out what takes most of the space in your executable, more accurately.

A more bloated but feature-rich reimplementation of
[cargo-bloat](https://github.com/RazrFalcon/cargo-bloat)
optimized for my personal use.
Use more dependencies rather than reinventing wheels.

## Install

```bash
cargo install cargo-bloated
```

## Usage

```console
$ cargo bloated # Analyze the default target of default package, and print a summary.
$ cargo bloated --output crates # Per-crate sizes, blaming the earliest instantiating crate.
$ cargo bloated --output sections # ELF section sizes.
$ cargo bloated --output functions # Details of each function symbol.
```

Run `cargo bloated --help` to see all arguments available.

## Comparing to cargo-bloat

- Currently only Linux/ELF is supported, because I have no Windows machine.

- Proper CLI parsing via `clap` for least surprise, eg. correct multiple
  `--features` handling. `goblin` is used for ELF parsing.

- Analyze `--release` build by default.

- Colored output and `--color`. The setting is also correctly forwarded to `cargo`.

- Automatic pagination via `PAGER` for terminal stdout.

- ELF section size summary, to check if your executable is bloated by static
  data or [dynamic relocations](https://github.com/unicode-rs/unicode-normalization/pull/86).

- `strip`-aware. We disable stripping to compile the binary for analyzing, but
  the size percentage in report is calculated based on the size after stripping.
  So you will get a more accurate estimation of percentages in your stripped release
  build. Both sizes before and after stripping is shown in the report.

- `-Cprefer-dynamic` by default, excluding std from calculation. If std code
  size is a concern, you should already be using dynamic linking.

- `-Csymbol-mangling-version=v0` by default. Properly parse v0 mangled symbols, using
  `rustc_demangle` and `syn`. Generic types, constants and full paths are
  properly demangled. Disambiguators are also handled, so crates with the same
  name will not collide during calculation.

  The most downstream crate in the dependency graph mentioned by the the
  function path is to blame.
  This is correct for both `impl DepTrait<LocalType> for DepType` and
  `impl LocalTrait for DepType` where method function names "appeared" to be
  under dependency crates.

- Properly handle and show different symbols at the same address. These groups of symbols
  occupy the same spaces in executable, but their symbol names are still important.
  A heuristic algorithm is performed to decide which crate is to blame.
  Do not blame the crate for using a generic function already instantiated in
  their dependency, eg. `drop_in_place::<String>` and `drop_in_place::<MyStringWrapper>`.

<br>

#### License

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>

<br>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
</sub>