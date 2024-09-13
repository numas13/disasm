#[cfg(feature = "print")]
use std::io::{Cursor, Write};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
#[cfg(feature = "print")]
use disasm_core::printer::FormatterFn;
use disasm_core::{insn::Bundle, Options};
use disasm_test::test::Parser;

const SOURCES: &[(&str, &str)] = &[
    (
        "legacy_intel",
        concat!(
            include_str!("../tests/amd64_intel.test"),
            include_str!("../tests/x87_intel.test"),
            include_str!("../tests/ext_intel.test"),
        ),
    ),
    ("sse_intel", include_str!("../tests/sse_intel.test")),
    ("vex_intel", include_str!("../tests/vex_intel.test")),
    ("evex_intel", include_str!("../tests/evex_intel.test")),
    (
        "evex_bcst_intel",
        include_str!("../tests/evex_bcst_intel.test"),
    ),
    ("evex_er_intel", include_str!("../tests/evex_er_intel.test")),
    (
        "evex_sae_intel",
        include_str!("../tests/evex_sae_intel.test"),
    ),
];

fn bench_impl<const PRINT: bool>(c: &mut Criterion, name: &str) {
    let mut group = c.benchmark_group(name);
    for (name, source) in SOURCES {
        let (_, code, _) = Parser::parse_all(source, false).unwrap();

        let opts = Options {
            alias: true,
            ..Default::default()
        };
        let opts_arch = disasm_x86::Options {
            att: false,
            ext: disasm_x86::Extensions::all(),
            ..Default::default()
        };
        let mut decoder = disasm_x86::decoder(&opts, &opts_arch);
        #[cfg(feature = "print")]
        let printer = disasm_x86::printer(&opts, &opts_arch);
        #[cfg(feature = "print")]
        let mut buffer = Cursor::new(Vec::new());
        let mut bundle = Bundle::empty();

        group.throughput(Throughput::Bytes(code.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), &code, |b, code| {
            b.iter(|| {
                let mut offset = 0;
                let mut count = 0;
                while offset < code.len() {
                    match decoder.decode(0, &code[offset..], &mut bundle) {
                        Ok(len) => {
                            count += 1;
                            offset += len / 8;

                            #[cfg(feature = "print")]
                            if PRINT {
                                let display = FormatterFn(|fmt| {
                                    let insn = &bundle[0];
                                    printer.print_mnemonic(fmt, &(), insn, false)?;
                                    printer.print_operands(fmt, &(), insn)?;
                                    Ok(())
                                });
                                buffer.set_position(0);
                                write!(&mut buffer, "{display}").unwrap();
                            }
                        }
                        Err(_) => panic!(),
                    }
                }
                count
            })
        });
    }
}

fn x86_bench(c: &mut Criterion) {
    bench_impl::<false>(c, "decode");
    #[cfg(feature = "print")]
    bench_impl::<true>(c, "print");
}

criterion_group!(benches, x86_bench);
criterion_main!(benches);
