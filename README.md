# cargo-bloated

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

Sample output:

```console
$ cargo bloated
   Compiling testy v0.1.0 (/tmp/testy)
    Finished `release` profile [optimized] target(s) in 1.00s
   Analyzing binary "testy": /tmp/testy/target/release/testy
   File   Size Section
100.0% 1470KiB (file)
143.6% 2.06MiB (unstripped)
 52.2%  768KiB .text
 21.8%  320KiB .rodata
  8.6%  126KiB .eh_frame
  5.9% 86.8KiB .gcc_except_table

  File  .text    Size  Crate
 64.3% 123.1%  945KiB  *
 11.8%  22.6%  173KiB  cyper
 11.5%  22.1%  169KiB  idna
  6.3%  12.1% 92.6KiB  hyper
  5.8%  11.1% 85.3KiB  http
  3.4%   6.5% 50.0KiB  compio_net
  3.2%   6.1% 46.9KiB  encoding_rs
  3.1%   6.0% 45.7KiB  url
  2.7%   5.1% 39.4KiB  compio_driver

  File    Size  .text  .rodata   (SHR) .data.rel.ro   (SHR) Crates                           Name
  9.3%  136KiB  173  B  136KiB    0  B       376  B    0  B idna                             idna::domain_to_ascii_from_cow
  1.2% 17.0KiB 16.5KiB  209  B 21.1KiB       264  B   32  B cyper,hyper_util                 <hyper_util::client::legacy::client::Client<cyper::connector::Connector, cyper::body::Body>>::send_request::{closure#0}
  0.8% 11.2KiB 10.6KiB  596  B    0  B         0  B    0  B http                             <http::header::name::StandardHeader>::from_bytes
  0.7% 10.7KiB 10.1KiB  230  B 19.3KiB       352  B   32  B testy,compio_runtime,scoped_tls  <scoped_tls::ScopedKey<compio_runtime::runtime::Runtime>>::set::<<compio_runtime::runtime::Runtime>::block_on<testy::main::{closure#0}>::{closure#0}, ()>
  0.7% 10.4KiB 1281  B 2.59KiB 21.1KiB      6.53KiB  160  B encoding_rs                      <encoding_rs::Encoding>::for_label
  0.7% 10.1KiB 9.72KiB   24  B 19.4KiB       384  B   32  B hyper                            <hyper::proto::h1::role::Client as hyper::proto::h1::Http1Transaction>::parse
  0.6% 9.12KiB 8.91KiB    0  B 20.5KiB       216  B    0  B idna                             <idna::uts46::Uts46>::process_innermost
  0.6% 8.49KiB 8.07KiB  185  B 20.7KiB       240  B   72  B cyper,core,send_wrapper          <send_wrapper::SendWrapper<<cyper::stream::HttpStream>::connect::{closure#0}> as core::future::future::Future>::poll
```

## Comparing to cargo-bloat

- Supports rough `.rodata` and `.data.rel.ro` usage tracking by parsing ELF and linker map.
  This requires bundled `ld.lld` from Rust toolchain, but should work
  out-of-box on latest stable rustc.

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