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
    use std::io::Cursor;

    use disasm::{arch::riscv, Arch, Decoder, Options};

    use crate::common::{test::Parser, utils::check};

    fn run_test(expect: &str) -> Result<(), String> {
        let section_name = ".text";
        let (address, data, mut symbols) = Parser::parse_all(expect)?;
        let arch = Arch::Riscv(riscv::Options {
            xlen: riscv::Xlen::X64,
            ext: riscv::Extensions::all(),
        });
        let opts = Options {
            alias: true,
            ..Options::default()
        };
        let result = Decoder::new(arch, address, opts)
            .printer(symbols.as_info(), section_name)
            .print_to_string(&data, true)
            .unwrap();
        let res_complete = check("complete", expect, &result);

        let mut dis = Decoder::new(arch, address, opts).printer(symbols.as_info(), section_name);
        let mut cur = Cursor::new(Vec::new());
        let mut offset = 0;
        let mut len = 0;
        let mut first = true;

        // print body
        while len < data.len() {
            match dis.print_streaming(&mut cur, &data[offset..len], first) {
                Ok((done, more)) => {
                    offset += done;
                    len += more;
                }
                Err(err) => panic!("error: {err}"),
            }
            if first {
                first = false;
            }
        }

        // print tail
        if offset < data.len() {
            dis.print(&mut cur, &data[offset..], first).unwrap();
        }

        let result = String::from_utf8(cur.into_inner()).unwrap();
        let res_streaming = check("streaming", expect, &result);

        if res_complete.is_ok() && res_streaming.is_ok() {
            Ok(())
        } else {
            println!("input:");
            let n = 4;
            let mut address = address;
            for c in data.chunks(n) {
                print!(" {:x}:", address);
                for i in c {
                    print!(" {i:02x}");
                }
                address += n as u64;
                println!();
            }
            Err(String::from("some tests are failed"))
        }
    }

    macro_rules! test_print {
        ($($name:ident = $expect:expr),+ $(,)?) => (
            $(#[test]
            fn $name() -> Result<(), String> {
                run_test($expect)
            })+
        )
    }

    test_print! {

    complex = "
0000000000001000 <_start>:
    1000:	4505                	li	a0,1
    1002:	4589                	li	a1,2
    1004:	040000ef          	jal	1044 <func>
    1008:	05d00893          	li	a7,93
    100c:	00000073          	ecall
	...
    1020:	0001                	nop
    1022:	0001                	nop
	...

0000000000001034 <zeroes>:
	...

0000000000001044 <func>:
    1044:	0505                	addi	a0,a0,1
    1046:	02b50533          	mul	a0,a0,a1
    104a:	8082                	ret
	...

0000000000001054 <end>:
    1054:	8082                	ret
",

    zeroes_start = "
0000000000001000 <zeroes>:
	...

0000000000001010 <_start>:
    1010:	8082                	ret
",

    zeroes_start2 = "
0000000000001000 <_start>:
    1000:	0001                	nop
	...

0000000000001004 <zeroes>:
	...

0000000000001006 <end>:
    1006:	0000                	unimp
    1008:	0001                	nop
",

    zeroes_multiple_symbols = "
0000000000001000 <_start>:
    1000:	0001                	nop

0000000000001002 <zeroes1>:
	...

0000000000001012 <zeroes2>:
	...

0000000000001022 <zeroes3>:
	...

0000000000001032 <end>:
    1032:	0001                	nop
",

    undefined_all = "
0000000000001000 <.text>:
    1000:	0001                	nop
    1002:	0001                	nop
    1004:	0001                	nop
    1006:	0001                	nop
",

    undefined_text_start = "
0000000000001000 <_start-0x4>:
    1000:	0001                	nop
    1002:	0001                	nop

0000000000001004 <_start>:
    1004:	8082                	ret
",
        }
}
