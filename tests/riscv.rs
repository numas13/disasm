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

#[cfg(all(test, feature = "print", feature = "riscv"))]
mod print {
    use disasm::{arch::riscv, Arch, Disasm, Options, PrintError};

    use crate::common::{test::Parser, utils::check};

    const TEST: &str = "
0000000000001000 <_start>:
    1000:	4505                	li	a0,1
    1002:	4589                	li	a1,2
    1004:	01c000ef          	jal	1020 <func>
    1008:	05d00893          	li	a7,93
    100c:	00000073          	ecall
	...

0000000000001020 <func>:
    1020:	0505                	addi	a0,a0,1
    1022:	02b50533          	mul	a0,a0,a1
    1026:	8082                	ret
";

    #[test]
    fn complete() -> Result<(), String> {
        let expect = TEST;
        let section_name = ".text";
        let (address, data, mut symbols) = Parser::parse_all(expect)?;
        let info = symbols.as_info();
        let mut dis = Disasm::new(
            Arch::Riscv(riscv::Options {
                xlen: riscv::Xlen::X64,
                ext: riscv::Extensions::all(),
            }),
            address,
            Options {
                alias: true,
                ..Options::default()
            },
        );
        let result = dis
            .print_to_string(&data, section_name, &info, true)
            .unwrap();
        check("input", expect, &result)
    }

    #[test]
    fn streaming() -> Result<(), String> {
        use std::io::Cursor;

        let expect = TEST;
        let section_name = ".text";
        let (address, data, mut symbols) = Parser::parse_all(expect)?;
        let info = symbols.as_info();
        let mut dis = Disasm::new(
            Arch::Riscv(riscv::Options {
                xlen: riscv::Xlen::X64,
                ext: riscv::Extensions::all(),
            }),
            address,
            Options {
                alias: true,
                ..Options::default()
            },
        );

        let mut cur = Cursor::new(Vec::new());
        let mut offset = 0;
        let mut len = 0;
        let mut first = true;

        // print body
        while len < data.len() {
            match dis.print_streaming(&mut cur, &data[offset..len], section_name, &info, first) {
                Err(PrintError::More(done, more)) => {
                    offset += done;
                    len += more;
                }
                // TODO: make no sense for streaming, needs refactoring...
                Ok(_) => panic!(),
                Err(err) => panic!("error: {err}"),
            }
            if first {
                first = false;
            }
        }

        // print tail
        if offset < data.len() {
            dis.print(&mut cur, &data[offset..], section_name, &info, first)
                .unwrap();
        }

        let result = String::from_utf8(cur.into_inner()).unwrap();
        check("input", expect, &result)
    }
}
