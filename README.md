# cargo-bloated

Find out what takes most of the space in your executable.

A more bloated but feature-rich reimplementation of
[cargo-bloat](https://github.com/RazrFalcon/cargo-bloat)
optimized for my personal use.
Use more dependencies rather than reinventing wheels.

Notable features/differences:

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
