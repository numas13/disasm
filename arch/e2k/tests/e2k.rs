use disasm_core::Options;
use disasm_e2k as e2k;
use disasm_test::test::{self, Runner, Test};

#[derive(Default)]
struct E2K {
    isa: Option<u8>,
}

impl Runner<e2k::Decoder, e2k::Printer> for E2K {
    fn create(&mut self, test: &Test) -> (e2k::Decoder, e2k::Printer) {
        let mut opts = Options::default();
        let mut opts_arch = e2k::Options::default();

        if let Some(isa) = self.isa {
            opts_arch.isa = isa;
        }

        for (name, state) in test::parse_flags(test.comment) {
            match name {
                "alias" => opts.alias = state,
                _ => panic!("unexpected flag {name}"),
            }
        }

        let decoder = e2k::Decoder::new(&opts, &opts_arch);
        let printer = e2k::Printer::new(&opts, &opts_arch);

        (decoder, printer)
    }

    fn bundle_end(&self) -> &'static str {
        "--"
    }
}

macro_rules! test {
    ($name:ident, $file:expr $(, $isa:expr)?) => {
        #[test]
        fn $name() -> Result<(), String> {
            E2K {
                $(isa: Some($isa),)?
                .. E2K::default()
            }.run($file, include_str!($file))
        }
    };
}

test!(registers, "registers.test");

test!(v1, "v1.test", 1);
test!(v2, "v2.test", 2);
test!(v3, "v3.test", 3);
test!(v4, "v4.test", 4);
test!(v5, "v5.test", 5);
test!(v6, "v6.test", 6);
test!(v7, "v7.test", 7);
