mod common;

macro_rules! test {
    ($name:ident, $file:expr $(, $isa:expr)?) => {
        #[test]
        #[cfg(all(feature = "print", feature = "e2k"))]
        fn $name() -> Result<(), String> {
            use self::common::test;
            use disasm::{arch::e2k, Arch, Options};

            test::run($file, include_str!($file), "--", |test| {
                let arch = Arch::E2K(e2k::Options {
                    $(isa: $isa,)?
                    .. e2k::Options::default()
                });

                let mut opts = Options::default();

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

test!(registers, "e2k/registers.test");

test!(v1, "e2k/v1.test", 1);
test!(v2, "e2k/v2.test", 2);
test!(v3, "e2k/v3.test", 3);
test!(v4, "e2k/v4.test", 4);
test!(v5, "e2k/v5.test", 5);
test!(v6, "e2k/v6.test", 6);
test!(v7, "e2k/v7.test", 7);
