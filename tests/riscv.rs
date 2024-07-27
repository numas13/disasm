mod common;

macro_rules! test {
    ($name:ident, $file:expr, $alias:expr) => {
        #[test]
        #[cfg(all(feature = "print", feature = "riscv"))]
        fn $name() -> Result<(), String> {
            use self::common::test;
            use disasm::{arch::riscv, Arch, Options};

            test::run($file, include_str!($file), |test| {
                let arch = Arch::Riscv(riscv::Options {
                    xlen: riscv::Xlen::X64,
                    ext: riscv::Extensions::all(),
                });

                let mut opts = Options {
                    alias: $alias,
                    ..Options::default()
                };

                for (flag, name) in test::parse_flags(test.comment) {
                    match name {
                        "alias" => opts.alias = flag,
                        _ => {}
                    }
                }

                (arch, opts)
            })
        }
    };
}

test!(rv32i, "riscv/rv32i.test", false);
test!(rv32m, "riscv/rv32m.test", false);

test!(rv64i, "riscv/rv64i.test", false);
test!(rv64m, "riscv/rv64m.test", false);

test!(zicsr, "riscv/zicsr.test", false);
