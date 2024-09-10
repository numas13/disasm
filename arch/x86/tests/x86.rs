use disasm_core::{printer::ArchPrinter, ArchDecoder, Options};
use disasm_test::test::{self, Runner, Test};
use disasm_x86 as x86;

#[derive(Default)]
struct X86 {
    flags: &'static str,
}

impl Runner<x86::Options> for X86 {
    fn create(&mut self, test: &Test) -> (Box<dyn ArchDecoder>, Box<dyn ArchPrinter<()>>) {
        let mut opts = Options {
            alias: true,
            ..Options::default()
        };
        let mut opts_arch = x86::Options {
            ext: x86::Extensions::all(),
            ..x86::Options::default()
        };

        let flags = test::parse_flags(self.flags).chain(test::parse_flags(test.comment));
        for (name, state) in flags {
            match name {
                "alias" => opts.alias = state,
                "i386" => opts_arch.ext.i386 = state,
                "amd64" => opts_arch.ext.amd64 = state,
                "att" => opts_arch.att = state,
                "suffix" => opts_arch.suffix_always = state,
                _ => panic!("unexpected flag {name}"),
            }
        }

        let decoder = x86::decoder(&opts, &opts_arch);
        let printer = x86::printer(&opts, &opts_arch);

        (decoder, printer)
    }
}

macro_rules! test {
    ($name:ident, $file:expr, $flags:expr) => {
        #[test]
        fn $name() -> Result<(), String> {
            X86 { flags: $flags }.run($file, include_str!($file))
        }
    };
}

test!(registers_intel, "registers_intel.test", "+amd64");

test!(nop, "nop.test", "");
test!(absolute_address, "absolute_address.test", "");

test!(i386_intel, "i386_intel.test", "+i386 -amd64");
test!(i386_att, "i386_att.test", "+i386 -amd64 +att");

test!(amd64_intel, "amd64_intel.test", "+amd64");
test!(amd64_att, "amd64_att.test", "+amd64 +att");
test!(amd64_att_suffix, "amd64_att_suffix.test", "+amd64 +att");

test!(x87_intel, "x87_intel.test", "+amd64");
test!(x87_att, "x87_att.test", "+amd64 +att");
test!(bmi_intel, "bmi_intel.test", "+amd64");
test!(aes_intel, "aes_intel.test", "+amd64");
test!(mpx_intel, "mpx_intel.test", "+amd64");
test!(ext_intel, "ext_intel.test", "+amd64");

test!(sse_intel, "sse_intel.test", "+amd64");
test!(vex_intel, "vex_intel.test", "+amd64");
test!(evex_intel, "evex_intel.test", "+amd64");
test!(evex_bcst_intel, "evex_bcst_intel.test", "+amd64");
test!(evex_er_intel, "evex_er_intel.test", "+amd64");
test!(evex_sae_intel, "evex_sae_intel.test", "+amd64");
