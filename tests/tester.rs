mod common;

use common::test::{Parser, Test};

#[test]
fn parse_flags() {
    let src = " +a\t+b  -abc-foo -foo  +bar+foo";
    let mut flags = common::test::parse_flags(src);
    assert_eq!(flags.next(), Some((true, "a")));
    assert_eq!(flags.next(), Some((true, "b")));
    assert_eq!(flags.next(), Some((false, "abc-foo")));
    assert_eq!(flags.next(), Some((false, "foo")));
    assert_eq!(flags.next(), Some((true, "bar+foo")));
    assert_eq!(flags.next(), None);
}

#[test]
fn parse() -> Result<(), String> {
    let src = r#"# comment
        1000: 00 00     ud # comment
        1000: 00 01     insn1 a,b # +alias
        1004: 00 02     insn2 a,b,c
              00 03     "prefix insn3" a,b,c,d
              03020100  nop
              00        "aa"
              00        aax
    "#;

    let mut parser = Parser::new("input", src);
    let mut test = Test::default();

    assert!(parser.parse(&mut test)?);
    assert_eq!(test.line, 2);
    assert_eq!(test.address, 0x1000);
    assert_eq!(test.bytes, &[0x00, 0x00]);
    assert_eq!(test.asm[0], ("ud", ""));

    assert!(parser.parse(&mut test)?);
    assert_eq!(test.line, 3);
    assert_eq!(test.address, 0x1000);
    assert_eq!(test.bytes, &[0x00, 0x01]);
    assert_eq!(test.asm[0], ("insn1", "a,b"));
    assert_eq!(test.comment, "+alias");

    assert!(parser.parse(&mut test)?);
    assert_eq!(test.line, 4);
    assert_eq!(test.address, 0x1004);
    assert_eq!(test.bytes, &[0x00, 0x02]);
    assert_eq!(test.asm[0], ("insn2", "a,b,c"));

    assert!(parser.parse(&mut test)?);
    assert_eq!(test.bytes, &[0x00, 0x03]);
    assert_eq!(test.asm[0], ("prefix insn3", "a,b,c,d"));

    assert!(parser.parse(&mut test)?);
    assert_eq!(test.bytes, &[0x00, 0x01, 0x02, 0x03]);
    assert_eq!(test.asm[0], ("nop", ""));

    assert!(parser.parse(&mut test)?);
    assert_eq!(test.bytes, &[0x00]);
    assert_eq!(test.asm[0], ("aa", ""));

    assert!(parser.parse(&mut test)?);
    assert_eq!(test.bytes, &[0x00]);
    assert_eq!(test.asm[0], ("aax", ""));

    assert!(!parser.parse(&mut test)?);

    Ok(())
}
