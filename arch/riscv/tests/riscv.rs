use disasm_core::{printer::ArchPrinter, ArchDecoder, Options};
use disasm_riscv as riscv;
use disasm_test::test::{self, Runner, Test};

#[derive(Default)]
struct Riscv {
    alias: bool,
}

impl Runner<riscv::Options> for Riscv {
    fn create(&mut self, test: &Test) -> (Box<dyn ArchDecoder>, Box<dyn ArchPrinter<()>>) {
        let mut opts = Options {
            alias: self.alias,
            ..Options::default()
        };

        let opts_arch = riscv::Options {
            xlen: riscv::Xlen::X64,
            ext: riscv::Extensions::all(),
        };

        for (name, state) in test::parse_flags(test.comment) {
            match name {
                "alias" => opts.alias = state,
                _ => panic!("unexpected flag {name}"),
            }
        }

        let decoder = riscv::decoder(&opts, &opts_arch);
        let printer = riscv::printer(&opts, &opts_arch);

        (decoder, printer)
    }
}

macro_rules! test {
    ($name:ident, $file:expr, $alias:expr) => {
        #[test]
        fn $name() -> Result<(), String> {
            Riscv { alias: $alias }.run($file, include_str!($file))
        }
    };
}

test!(rv32i, "rv32i.test", false);
test!(rv32m, "rv32m.test", false);
test!(rv32f, "rv32f.test", false);
test!(rv32a, "rv32a.test", false);

test!(rv64i, "rv64i.test", false);
test!(rv64m, "rv64m.test", false);
test!(rv64f, "rv64f.test", false);
test!(rv64d, "rv64d.test", false);
test!(rv64a, "rv64a.test", false);

test!(zicsr, "zicsr.test", false);
