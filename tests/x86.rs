mod common;

macro_rules! test {
    ($name:ident, $file:expr, $flags:expr) => {
        #[test]
        #[cfg(all(feature = "print", feature = "x86"))]
        fn $name() -> Result<(), String> {
            use self::common::test;
            use disasm::{arch::x86, Arch, Options};

            test::run($file, include_str!($file), |test| {
                let mut opts_arch = x86::Options {
                    ext: x86::Extensions::all(),
                    ..x86::Options::default()
                };

                let mut opts = Options {
                    alias: true,
                    ..Options::default()
                };

                let flags = test::parse_flags($flags).chain(test::parse_flags(test.comment));
                for (flag, name) in flags {
                    match name {
                        "alias" => opts.alias = flag,
                        "i386" => opts_arch.ext.i386 = flag,
                        "amd64" => opts_arch.ext.amd64 = flag,
                        "att" => opts_arch.att = flag,
                        "suffix" => opts_arch.suffix_always = flag,
                        _ => {}
                    }
                }

                (Arch::X86(opts_arch), opts)
            })
        }
    };
}

test!(registers_intel, "x86/registers_intel.test", "+amd64");

test!(nop, "x86/nop.test", "");
test!(absolute_address, "x86/absolute_address.test", "");

test!(i386_intel, "x86/i386_intel.test", "+i386 -amd64");
test!(i386_att, "x86/i386_att.test", "+i386 -amd64 +att");

test!(amd64_intel, "x86/amd64_intel.test", "+amd64");
test!(amd64_att, "x86/amd64_att.test", "+amd64 +att");
test!(amd64_att_suffix, "x86/amd64_att_suffix.test", "+amd64 +att");

test!(x87_intel, "x86/x87_intel.test", "+amd64");
test!(x87_att, "x86/x87_att.test", "+amd64 +att");
test!(bmi_intel, "x86/bmi_intel.test", "+amd64");
test!(aes_intel, "x86/aes_intel.test", "+amd64");
test!(mpx_intel, "x86/mpx_intel.test", "+amd64");
test!(ext_intel, "x86/ext_intel.test", "+amd64");

test!(sse_intel, "x86/sse_intel.test", "+amd64");
test!(vex_intel, "x86/vex_intel.test", "+amd64");
test!(evex_intel, "x86/evex_intel.test", "+amd64");
test!(evex_bcst_intel, "x86/evex_bcst_intel.test", "+amd64");
test!(evex_er_intel, "x86/evex_er_intel.test", "+amd64");
test!(evex_sae_intel, "x86/evex_sae_intel.test", "+amd64");
