use std::{
    borrow::Cow,
    fmt::{self, Display, Write},
};

use disasm_core::{
    insn::{Insn, Slot},
    operand::{Operand, OperandKind, Reg, RegClass},
    printer::{ArchPrinter, FormatterFn, PrinterExt, Separator},
    utils::zextract,
};

use super::{consts::*, opcode, E2KOperand, Options};

#[rustfmt::skip]
const GPR_NAME: [&str; 256] = [
    "b0",   "b1",   "b2",   "b3",   "b4",   "b5",   "b6",   "b7",
    "b8",   "b9",   "b10",  "b11",  "b12",  "b13",  "b14",  "b15",
    "b16",  "b17",  "b18",  "b19",  "b20",  "b21",  "b22",  "b23",
    "b24",  "b25",  "b26",  "b27",  "b28",  "b29",  "b30",  "b31",
    "b32",  "b33",  "b34",  "b35",  "b36",  "b37",  "b38",  "b39",
    "b40",  "b41",  "b42",  "b43",  "b44",  "b45",  "b46",  "b47",
    "b48",  "b49",  "b50",  "b51",  "b52",  "b53",  "b54",  "b55",
    "b56",  "b57",  "b58",  "b59",  "b60",  "b61",  "b62",  "b63",
    "b64",  "b65",  "b66",  "b67",  "b68",  "b69",  "b70",  "b71",
    "b72",  "b73",  "b74",  "b75",  "b76",  "b77",  "b78",  "b79",
    "b80",  "b81",  "b82",  "b83",  "b84",  "b85",  "b86",  "b87",
    "b88",  "b89",  "b90",  "b91",  "b92",  "b93",  "b94",  "b95",
    "b96",  "b97",  "b98",  "b99",  "b100", "b101", "b102", "b103",
    "b104", "b105", "b106", "b107", "b108", "b109", "b110", "b111",
    "b112", "b113", "b114", "b115", "b116", "b117", "b118", "b119",
    "b120", "b121", "b122", "b123", "b124", "b125", "b126", "b127",
    "r0",   "r1",   "r2",   "r3",   "r4",   "r5",   "r6",   "r7",
    "r8",   "r9",   "r10",  "r11",  "r12",  "r13",  "r14",  "r15",
    "r16",  "r17",  "r18",  "r19",  "r20",  "r21",  "r22",  "r23",
    "r24",  "r25",  "r26",  "r27",  "r28",  "r29",  "r30",  "r31",
    "r32",  "r33",  "r34",  "r35",  "r36",  "r37",  "r38",  "r39",
    "r40",  "r41",  "r42",  "r43",  "r44",  "r45",  "r46",  "r47",
    "r48",  "r49",  "r50",  "r51",  "r52",  "r53",  "r54",  "r55",
    "r56",  "r57",  "r58",  "r59",  "r60",  "r61",  "r62",  "r63",
    "",     "",     "",     "",     "",     "",     "",     "",
    "",     "",     "",     "",     "",     "",     "",     "",
    "",     "",     "",     "",     "",     "",     "",     "",
    "",     "",     "",     "",     "",     "",     "",     "",
    "g0",   "g1",   "g2",   "g3",   "g4",   "g5",   "g6",   "g7",
    "g8",   "g9",   "g10",  "g11",  "g12",  "g13",  "g14",  "g15",
    "g16",  "g17",  "g18",  "g19",  "g20",  "g21",  "g22",  "g23",
    "g24",  "g25",  "g26",  "g27",  "g28",  "g29",  "g30",  "g31",
];

#[rustfmt::skip]
const PREG_NAME: [&str; 32] = [
  "p0",   "p1",   "p2",   "p3",   "p4",   "p5",   "p6",   "p7",
  "p8",   "p9",   "p10",  "p11",  "p12",  "p13",  "p14",  "p15",
  "p16",  "p17",  "p18",  "p19",  "p20",  "p21",  "p22",  "p23",
  "p24",  "p25",  "p26",  "p27",  "p28",  "p29",  "p30",  "p31",
];

#[rustfmt::skip]
const PCNT_NAME: [&str; 32] = [
  "pcnt0",   "pcnt1",   "pcnt2",   "pcnt3",
  "pcnt4",   "pcnt5",   "pcnt6",   "pcnt7",
  "pcnt8",   "pcnt9",   "pcnt10",  "pcnt11",
  "pcnt12",  "pcnt13",  "pcnt14",  "pcnt15",
  "pcnt16",  "pcnt17",  "pcnt18",  "pcnt19",
  "pcnt20",  "pcnt21",  "pcnt22",  "pcnt23",
  "pcnt24",  "pcnt25",  "pcnt26",  "pcnt27",
  "pcnt28",  "pcnt29",  "pcnt30",  "pcnt31"
];

#[rustfmt::skip]
const CTPR_NAME: [&str; 4] = ["", "ctpr1", "ctpr2", "ctpr3"];

#[rustfmt::skip]
const SREG_NAME: [&str; 256] = [
  /* 0x00 */ "psr",
  /* 0x01 */ "wd",
  /* 0x02 */ "",
  /* 0x03 */ "",
  /* 0x04 */ "core_mode",
  /* 0x05 */ "",
  /* 0x06 */ "cwd",
  /* 0x07 */ "psp.hi",
  /* 0x08 */ "",
  /* 0x09 */ "psp.lo",
  /* 0x0a */ "",
  /* 0x0b */ "pshtp",
  /* 0x0c */ "",
  /* 0x0d */ "pcsp.hi",
  /* 0x0e */ "",
  /* 0x0f */ "pcsp.lo",
  /* 0x10 */ "",
  /* 0x11 */ "",
  /* 0x12 */ "",
  /* 0x13 */ "pcshtp",
  /* 0x14 */ "",
  /* 0x15 */ "ctpr1",
  /* 0x16 */ "ctpr2",
  /* 0x17 */ "ctpr3",
  /* 0x18 */ "",
  /* 0x19 */ "",
  /* 0x1a */ "",
  /* 0x1b */ "",
  /* 0x1c */ "",
  /* 0x1d */ "",
  /* 0x1e */ "sbr",
  /* 0x1f */ "",
  /* 0x10 */ "",
  /* 0x21 */ "cutd",
  /* 0x22 */ "",
  /* 0x23 */ "eir",
  /* 0x24 */ "tsd", /* deprecated */
  /* 0x25 */ "cuir",
  /* 0x26 */ "oscud.hi",
  /* 0x27 */ "oscud.lo",
  /* 0x28 */ "osgd.hi",
  /* 0x29 */ "osgd.lo",
  /* 0x2a */ "osem",
  /* 0x2b */ "",
  /* 0x2c */ "usd.hi",
  /* 0x2d */ "usd.lo",
  /* 0x2e */ "tr", /* deprecated */
  /* 0x2f */ "osr0",
  /* 0x30 */ "cud.hi",
  /* 0x31 */ "cud.lo",
  /* 0x32 */ "gd.hi",
  /* 0x33 */ "gd.lo",
  /* 0x34 */ "cs.hi",
  /* 0x35 */ "cs.lo",
  /* 0x36 */ "ds.hi",
  /* 0x37 */ "ds.lo",
  /* 0x38 */ "es.hi",
  /* 0x39 */ "es.lo",
  /* 0x3a */ "fs.hi",
  /* 0x3b */ "fs.lo",
  /* 0x3c */ "gs.hi",
  /* 0x3d */ "gs.lo",
  /* 0x3e */ "ss.hi",
  /* 0x3f */ "ss.lo",
  /* 0x40 */ "dibcr",
  /* 0x41 */ "dimcr",
  /* 0x42 */ "dibsr",
  /* 0x43 */ "dtcr",
  /* 0x44 */ "",
  /* 0x45 */ "",
  /* 0x46 */ "",
  /* 0x47 */ "",
  /* 0x48 */ "dibar0",
  /* 0x49 */ "dibar1",
  /* 0x4a */ "dibar2",
  /* 0x4b */ "dibar3",
  /* 0x4c */ "dimar0",
  /* 0x4d */ "dimar1",
  /* 0x4e */ "dtarf",
  /* 0x4f */ "dtart",
  /* 0x50 */ "",
  /* 0x51 */ "cr0.hi",
  /* 0x52 */ "",
  /* 0x53 */ "cr0.lo",
  /* 0x54 */ "",
  /* 0x55 */ "cr1.hi",
  /* 0x56 */ "",
  /* 0x57 */ "cr1.lo",
  /* 0x58 */ "",
  /* 0x59 */ "",
  /* 0x5a */ "",
  /* 0x5b */ "",
  /* 0x5c */ "",
  /* 0x5d */ "",
  /* 0x5e */ "",
  /* 0x5f */ "",
  /* 0x60 */ "",
  /* 0x61 */ "",
  /* 0x62 */ "",
  /* 0x63 */ "",
  /* 0x64 */ "",
  /* 0x65 */ "",
  /* 0x66 */ "",
  /* 0x67 */ "",
  /* 0x68 */ "",
  /* 0x69 */ "",
  /* 0x6a */ "",
  /* 0x6b */ "",
  /* 0x6c */ "",
  /* 0x6d */ "",
  /* 0x6e */ "",
  /* 0x6f */ "",
  /* 0x70 */ "sclkm1",
  /* 0x71 */ "sclkm2",
  /* 0x72 */ "",
  /* 0x73 */ "",
  /* 0x74 */ "",
  /* 0x75 */ "",
  /* 0x76 */ "",
  /* 0x77 */ "",
  /* 0x78 */ "cu_hw0",
  /* 0x79 */ "",
  /* 0x7a */ "",
  /* 0x7b */ "",
  /* 0x7c */ "",
  /* 0x7d */ "",
  /* 0x7e */ "",
  /* 0x7f */ "",
  /* 0x80 */ "upsr",
  /* 0x81 */ "ip",
  /* 0x82 */ "nip",
  /* 0x83 */ "lsr",
  /* 0x84 */ "pfpfr",
  /* 0x85 */ "fpcr",
  /* 0x86 */ "fpsr",
  /* 0x87 */ "ilcr",
  /* 0x88 */ "br",
  /* 0x89 */ "bgr",
  /* 0x8a */ "idr",
  /* 0x8b */ "",
  /* 0x8c */ "",
  /* 0x8d */ "",
  /* 0x8e */ "",
  /* 0x8f */ "",
  /* 0x90 */ "clkr",
  /* 0x91 */ "rndpr",
  /* 0x92 */ "sclkr",
  /* 0x93 */ "",
  /* 0x94 */ "",
  /* 0x95 */ "",
  /* 0x96 */ "",
  /* 0x97 */ "",
  /* 0x98 */ "",
  /* 0x99 */ "",
  /* 0x9a */ "",
  /* 0x9b */ "",
  /* 0x9c */ "tir.hi",
  /* 0x9d */ "tir.lo",
  /* 0x9e */ "",
  /* 0x9f */ "",
  /* 0xa0 */ "rpr",
  /* 0xa1 */ "sbbp",
  /* 0xa2 */ "rpr.hi",
  /* 0xa3 */ "",
  /* 0xa4 */ "",
  /* 0xa5 */ "",
  /* 0xa6 */ "",
  /* 0xa7 */ "",
  /* 0xa8 */ "",
  /* 0xa9 */ "",
  /* 0xaa */ "",
  /* 0xab */ "",
  /* 0xac */ "",
  /* 0xad */ "",
  /* 0xae */ "",
  /* 0xaf */ "",
  /* 0xb0 */ "",
  /* 0xb1 */ "",
  /* 0xb2 */ "",
  /* 0xb3 */ "",
  /* 0xb4 */ "",
  /* 0xb5 */ "",
  /* 0xb6 */ "",
  /* 0xb7 */ "",
  /* 0xb8 */ "",
  /* 0xb9 */ "",
  /* 0xba */ "",
  /* 0xbb */ "",
  /* 0xbc */ "",
  /* 0xbd */ "",
  /* 0xbe */ "",
  /* 0xbf */ "",
  /* 0xc0 */ "upsrm",
  /* 0xc1 */ "",
  /* 0xc2 */ "",
  /* 0xc3 */ "lsr1", /* v5+ */
  /* 0xc4 */ "",
  /* 0xc5 */ "",
  /* 0xc6 */ "",
  /* 0xc7 */ "ilcr1", /* v5+ */
  /* 0xc8 */ "",
  /* 0xc9 */ "",
  /* 0xca */ "",
  /* 0xcb */ "",
  /* 0xcc */ "",
  /* 0xcd */ "",
  /* 0xce */ "",
  /* 0xcf */ "",
  /* 0xd0 */ "",
  /* 0xd1 */ "",
  /* 0xd2 */ "",
  /* 0xd3 */ "",
  /* 0xd4 */ "",
  /* 0xd5 */ "",
  /* 0xd6 */ "",
  /* 0xd7 */ "",
  /* 0xd8 */ "",
  /* 0xd9 */ "",
  /* 0xda */ "",
  /* 0xdb */ "",
  /* 0xdc */ "",
  /* 0xdd */ "",
  /* 0xde */ "",
  /* 0xdf */ "",
  /* 0xe0 */ "",
  /* 0xe1 */ "",
  /* 0xe2 */ "",
  /* 0xe3 */ "",
  /* 0xe4 */ "",
  /* 0xe5 */ "",
  /* 0xe6 */ "",
  /* 0xe7 */ "",
  /* 0xe8 */ "",
  /* 0xe9 */ "",
  /* 0xea */ "",
  /* 0xeb */ "",
  /* 0xec */ "",
  /* 0xed */ "",
  /* 0xee */ "",
  /* 0xef */ "",
  /* 0xf0 */ "",
  /* 0xf1 */ "",
  /* 0xf2 */ "",
  /* 0xf3 */ "",
  /* 0xf4 */ "",
  /* 0xf5 */ "",
  /* 0xf6 */ "",
  /* 0xf7 */ "",
  /* 0xf8 */ "",
  /* 0xf9 */ "",
  /* 0xfa */ "",
  /* 0xfb */ "",
  /* 0xfc */ "",
  /* 0xfd */ "",
  /* 0xfe */ "",
  /* 0xff */ "",
];

#[rustfmt::skip]
const AAD_NAME: [&str; 32] = [
    "aad0",   "aad1",   "aad2",   "aad3",   "aad4",   "aad5",   "aad6",   "aad7",
    "aad8",   "aad9",   "aad10",  "aad11",  "aad12",  "aad13",  "aad14",  "aad15",
    "aad16",  "aad17",  "aad18",  "aad19",  "aad20",  "aad21",  "aad22",  "aad23",
    "aad24",  "aad25",  "aad26",  "aad27",  "aad28",  "aad29",  "aad30",  "aad31",
];

#[rustfmt::skip]
const AASTI_NAME: [&str; 16] = [
  "aasti0",   "aasti1",   "aasti2",   "aasti3",
  "aasti4",   "aasti5",   "aasti6",   "aasti7",
  "aasti8",   "aasti9",   "aasti10",  "aasti11",
  "aasti12",  "aasti13",  "aasti14",  "aasti15",
];

#[rustfmt::skip]
const AAIND_NAME: [&str; 16] = [
  "aaind0",   "aaind1",   "aaind2",   "aaind3",
  "aaind4",   "aaind5",   "aaind6",   "aaind7",
  "aaind8",   "aaind9",   "aaind10",  "aaind11",
  "aaind12",  "aaind13",  "aaind14",  "aaind15",
];

#[rustfmt::skip]
const AAINCR_NAME: [&str; 8] = [
  "aaincr0", "aaincr1", "aaincr2", "aaincr3",
  "aaincr4", "aaincr5", "aaincr6", "aaincr7",
];

#[rustfmt::skip]
const IPR_NAME: [&str; 8] = [
  "ipr0", "ipr1", "ipr2", "ipr3", "ipr4", "ipr5", "ipr6", "ipr7"
];

#[rustfmt::skip]
const PRND_NAME: [&str; 32] = [
  "bgrpred",    "rndpred1",   "rndpred2",   "rndpred3",
  "rndpred4",   "rndpred5",   "rndpred6",   "rndpred7",
  "rndpred8",   "rndpred9",   "rndpred10",  "rndpred11",
  "rndpred12",  "rndpred13",  "rndpred14",  "rndpred15",
  "rndpred16",  "rndpred17",  "rndpred18",  "rndpred19",
  "rndpred20",  "rndpred21",  "rndpred22",  "rndpred23",
  "rndpred24",  "rndpred25",  "rndpred26",  "rndpred27",
  "rndpred28",  "rndpred29",  "rndpred30",  "rndpred31"
];

const ALC_NAME: [&str; 6] = ["alc0", "alc1", "alc2", "alc3", "alc4", "alc5"];

fn invert(c: bool) -> impl fmt::Display {
    FormatterFn(move |fmt| if c { fmt.write_char('~') } else { Ok(()) })
}

fn print_plu_cond(fmt: &mut fmt::Formatter, ext: &impl PrinterExt, pred: u8) -> fmt::Result {
    invert(pred & 1 != 0).fmt(fmt)?;
    match pred & 6 {
        0 => ext.print_register(fmt, "plu0")?,
        2 => ext.print_register(fmt, "plu1")?,
        4 => ext.print_register(fmt, "plu2")?,
        _ => write!(fmt, "<invalid plu cond:{pred:02x}>")?,
    }
    Ok(())
}

fn print_cmp_cond(
    fmt: &mut fmt::Formatter,
    ext: &impl PrinterExt,
    index: usize,
    inv: bool,
) -> fmt::Result {
    invert(inv).fmt(fmt)?;
    ext.print_register(fmt, ALC_NAME[[0, 1, 3, 4][index]])
}

fn print_dt_al(fmt: &mut fmt::Formatter, ext: &impl PrinterExt, pred: u8) -> fmt::Result {
    ext.print_register(
        fmt,
        FormatterFn(|fmt| {
            let map = ['0', '1', '3', '4'];
            fmt.write_str("dt_al")?;
            for (i, c) in map.iter().enumerate() {
                if pred & (1 << i) != 0 {
                    fmt.write_char(*c)?;
                }
            }
            Ok(())
        }),
    )
}

fn print_ct_cond(
    fmt: &mut fmt::Formatter,
    ext: &impl PrinterExt,
    cond: u8,
    pred: u8,
) -> fmt::Result {
    match cond {
        operand::CT_COND_NONE => unreachable!(),
        operand::CT_COND_ALWAYS => unreachable!(),
        operand::CT_COND_PREG => {
            ext.print_register(fmt, PREG_NAME[pred as usize])?;
        }
        operand::CT_COND_NOT_PREG => {
            fmt.write_char('~')?;
            ext.print_register(fmt, PREG_NAME[pred as usize])?;
        }
        operand::CT_COND_LOOP_END => {
            ext.print_register(fmt, "loop_end")?;
        }
        operand::CT_COND_NOT_LOOP_END => {
            fmt.write_char('~')?;
            ext.print_register(fmt, "loop_end")?;
        }
        operand::CT_COND_PREG_OR_LOOP_END => {
            ext.print_register(fmt, PREG_NAME[pred as usize])?;
            fmt.write_str(" || ")?;
            ext.print_register(fmt, "loop_end")?;
        }
        operand::CT_COND_NOT_PREG_AND_NOT_LOOP_END => {
            fmt.write_char('~')?;
            ext.print_register(fmt, PREG_NAME[pred as usize])?;
            fmt.write_str(" && ")?;
            fmt.write_char('~')?;
            ext.print_register(fmt, "loop_end")?;
        }
        operand::CT_COND_MLOCK_OR_DTAL => {
            ext.print_register(fmt, "mlock")?;
            if pred != 0 {
                fmt.write_str(" || ")?;
                print_dt_al(fmt, ext, pred)?;
            }
        }
        operand::CT_COND_MLOCK_OR_CMP => {
            ext.print_register(fmt, "mlock")?;
            fmt.write_str(" || ")?;
            match pred & 0x18 {
                0x00 => {
                    let index = zextract(pred, 1, 2) as usize;
                    print_cmp_cond(fmt, ext, index, pred & 1 != 0)?;
                }
                0x08 => {
                    let index = if pred & 4 != 0 { 2 } else { 0 };
                    print_cmp_cond(fmt, ext, index, pred & 2 != 0)?;
                    fmt.write_str(" || ")?;
                    print_cmp_cond(fmt, ext, index + 1, pred & 1 != 0)?;
                }
                0x10 => print_plu_cond(fmt, ext, pred)?,
                _ => write!(fmt, "<invalid cond:{cond}:{pred:02x}>")?,
            }
        }
        operand::CT_COND_CMP_CLP => {
            if pred & 0x10 != 0 {
                print_plu_cond(fmt, ext, pred)?;
            } else {
                let index = zextract(pred, 1, 2) as usize;
                print_cmp_cond(fmt, ext, index, pred & 1 != 0)?;
            }
        }
        operand::CT_COND_NOT_PREG_OR_LOOP_END => {
            fmt.write_char('~')?;
            ext.print_register(fmt, PREG_NAME[pred as usize])?;
            fmt.write_str(" || ")?;
            ext.print_register(fmt, "loop_end")?;
        }
        operand::CT_COND_PREG_AND_NOT_LOOP_END => {
            ext.print_register(fmt, PREG_NAME[pred as usize])?;
            fmt.write_str(" && ")?;
            fmt.write_char('~')?;
            ext.print_register(fmt, "loop_end")?;
        }
        _ => {
            write!(fmt, "<invalid cond:{cond}:{pred:02x}>")?;
        }
    }
    Ok(())
}

fn print_cond(
    fmt: &mut fmt::Formatter,
    ext: &impl PrinterExt,
    inv: bool,
    cond: impl fmt::Display,
) -> fmt::Result {
    invert(inv).fmt(fmt)?;
    ext.print_register(fmt, cond)
}

fn print_named(
    fmt: &mut fmt::Formatter,
    ext: &impl PrinterExt,
    name: &'static str,
    value: impl fmt::Display,
) -> fmt::Result {
    fmt.write_str(name)?;
    fmt.write_char('=')?;
    ext.print_immediate(fmt, value)
}

fn print_named_hex(
    fmt: &mut fmt::Formatter,
    ext: &impl PrinterExt,
    name: &'static str,
    value: impl fmt::LowerHex,
) -> fmt::Result {
    print_named(fmt, ext, name, FormatterFn(|fmt| write!(fmt, "{value:#x}")))
}

struct Printer {}

impl Printer {
    fn new(_: &disasm_core::Options, _: &Options) -> Self {
        Self {}
    }
}

impl<E: PrinterExt> ArchPrinter<E> for Printer {
    fn mnemonic(&self, insn: &Insn) -> Option<(&'static str, &'static str)> {
        super::mnemonic(insn)
    }

    fn register_name(&self, reg: Reg) -> Cow<'static, str> {
        match reg.class() {
            RegClass::INT => {
                let index = reg.index() as usize;
                if !(0xc0..0xe0).contains(&index) {
                    GPR_NAME[index].into()
                } else {
                    format!("<invalid gpr:{index:02x}>").into()
                }
            }
            reg_class::PREG => PREG_NAME[reg.index() as usize & 31].into(),
            reg_class::PCNT => PCNT_NAME[reg.index() as usize & 31].into(),
            reg_class::PRND => PRND_NAME[reg.index() as usize & 31].into(),
            reg_class::CTPR => CTPR_NAME[reg.index() as usize].into(),
            reg_class::SREG => {
                let index = reg.index() as usize;
                let s = SREG_NAME[index];
                if s.is_empty() {
                    format!("<invalid sr:{index:02x}>").into()
                } else {
                    s.into()
                }
            }
            reg_class::AAD => AAD_NAME[reg.index() as usize].into(),
            reg_class::AASTI => AASTI_NAME[reg.index() as usize].into(),
            reg_class::AAIND => AAIND_NAME[reg.index() as usize].into(),
            reg_class::AAINCR => AAINCR_NAME[reg.index() as usize].into(),
            reg_class::IPR => IPR_NAME[reg.index() as usize].into(),
            _ => todo!(),
        }
    }

    fn insn_separator(&self) -> Separator {
        Separator::Width(12)
    }

    fn print_operand(
        &self,
        fmt: &mut alloc::fmt::Formatter,
        ext: &E,
        insn: &Insn,
        operand: &Operand,
    ) -> alloc::fmt::Result {
        match operand.kind() {
            OperandKind::ArchSpec(id, x, y) => match E2KOperand::from_u64(*id).unwrap() {
                E2KOperand::Literal => {
                    let lit = x;
                    let size = y;
                    let lit = FormatterFn(|fmt| match size {
                        16 | 32 => {
                            if lit >> (size - 1) & 1 != 0 {
                                write!(fmt, "{lit:#x}_i{size}")
                            } else {
                                write!(fmt, "{lit:#x}")
                            }
                        }
                        64 => write!(fmt, "{lit:#x}"),
                        _ => write!(fmt, "<invalid literal:{lit:02x}>"),
                    });
                    ext.print_immediate(fmt, lit)?;
                }
                E2KOperand::Empty => ext.print_register(fmt, "_")?,
                E2KOperand::Uimm => ext.print_immediate(fmt, x)?,
                E2KOperand::Mas => print_named_hex(fmt, ext, "mas", x)?,
                E2KOperand::Lcntex => print_cond(fmt, ext, *y != 0, "lcntex")?,
                E2KOperand::LoopEnd => print_cond(fmt, ext, *y != 0, "loop_end")?,
                E2KOperand::Spred => {
                    let cond = FormatterFn(|fmt| {
                        fmt.write_str("spred")?;
                        for i in 0..6 {
                            if *x & (1 << i) != 0 {
                                i.fmt(fmt)?;
                            }
                        }
                        Ok(())
                    });
                    print_cond(fmt, ext, *y != 0, cond)?;
                }
                E2KOperand::Wait => {
                    use super::Cs1;
                    type CheckFn = fn(&Cs1) -> bool;
                    let fields: [(CheckFn, _); 9] = [
                        (Cs1::wait_sal, "sal"),
                        (Cs1::wait_sas, "sas"),
                        (Cs1::wait_trap, "trap"),
                        (Cs1::wait_ma_c, "ma_c"),
                        (Cs1::wait_fl_c, "fl_c"),
                        (Cs1::wait_ld_c, "ld_c"),
                        (Cs1::wait_st_c, "st_c"),
                        (Cs1::wait_all_e, "all_e"),
                        (Cs1::wait_all_c, "all_c"),
                    ];
                    let cs1 = Cs1(*x as u32);
                    let mut first = true;
                    for (check, name) in &fields {
                        if check(&cs1) {
                            if !first {
                                fmt.write_str(", ")?;
                            }
                            fmt.write_str(name)?;
                            first = false;
                        }
                    }
                }
                E2KOperand::Vfbg => {
                    let cs1 = super::Cs1(*x as u32);
                    print_named(fmt, ext, "umask", cs1.vfbg_umask())?;
                    fmt.write_str(", ")?;
                    print_named(fmt, ext, "dmask", cs1.vfbg_dmask())?;
                    fmt.write_str(", ")?;
                    print_named(fmt, ext, "chkm4", cs1.vfbg_chkm4())?;
                }
                E2KOperand::Ipd => fmt.write_str("ipd")?,
                E2KOperand::NoSs => fmt.write_str("<missing ss>")?,
                E2KOperand::NoMrgc => fmt.write_str("<missing mrgc>")?,
                E2KOperand::Plu => {
                    let cond = FormatterFn(|fmt| write!(fmt, "plu{x}"));
                    print_cond(fmt, ext, *y != 0, cond)?;
                }
                E2KOperand::Fdam => fmt.write_str("fdam")?,
                E2KOperand::Trar => fmt.write_str("trar")?,
                E2KOperand::CtCond => print_ct_cond(fmt, ext, *x as u8, *y as u8)?,
                E2KOperand::Area => {
                    ext.print_immediate(fmt, y)?;
                    fmt.write_char('(')?;
                    ext.print_immediate(fmt, x)?;
                    fmt.write_char(')')?;
                }
                E2KOperand::ApbCt => print_named(fmt, ext, "ct", x)?,
                E2KOperand::ApbDpl => print_named(fmt, ext, "dpl", x)?,
                E2KOperand::ApbDcd => print_named(fmt, ext, "dcd", x)?,
                E2KOperand::ApbFmt => print_named(fmt, ext, "fmt", x)?,
                E2KOperand::ApbMrng => print_named(fmt, ext, "mrng", x)?,
                E2KOperand::ApbAsz => print_named(fmt, ext, "asz", x)?,
                E2KOperand::ApbAbs => print_named(fmt, ext, "abs", x)?,
                E2KOperand::CondStart => {} // handled in print_operands
            },
            _ => {
                if let OperandKind::Reg(reg) = operand.kind() {
                    match reg.class() {
                        reg_class::PREG | reg_class::PCNT | reg_class::PRND => {
                            if reg.index() & operand::PSRC_INVERT as u64 != 0 {
                                fmt.write_char('~')?;
                            }
                        }
                        _ => {}
                    }
                }

                self.print_operand_default(fmt, ext, insn, operand)?;
            }
        }
        Ok(())
    }

    fn print_mnemonic(
        &self,
        fmt: &mut fmt::Formatter,
        ext: &E,
        insn: &Insn,
        separator: bool,
    ) -> fmt::Result {
        let slot = insn.slot();
        let mut print_slot = |first: Slot, name| {
            ext.print_slot(
                fmt,
                FormatterFn(|fmt| {
                    let id = slot.raw() - first.raw();
                    fmt.write_str(name)?;
                    id.fmt(fmt)
                }),
            )
        };
        match slot {
            Slot::NONE => fmt.write_str("    ")?,
            slot::ALC0 | slot::ALC1 | slot::ALC2 | slot::ALC3 | slot::ALC4 | slot::ALC5 => {
                print_slot(slot::ALC0, "alc")?;
            }
            slot::APB0 | slot::APB1 | slot::APB2 | slot::APB3 => {
                print_slot(slot::APB0, "apb")?;
            }
            slot::PLU0 | slot::PLU1 | slot::PLU2 => {
                print_slot(slot::PLU0, "plu")?;
            }
            _ => unreachable!("unexpected slot {slot:?}"),
        }

        if insn.flags().any(insn::SM) {
            ext.print_sub_mnemonic(fmt, ".sm ")?;
        } else {
            fmt.write_str("    ")?;
        }

        match insn.opcode() {
            // do not print with color for better readability
            opcode::BUNDLE_END => fmt.write_str("--"),
            _ => self.print_mnemonic_default(fmt, ext, insn, separator),
        }
    }

    fn print_operands(&self, fmt: &mut fmt::Formatter, ext: &E, insn: &Insn) -> fmt::Result {
        let mut first = true;
        let mut iter = insn.operands().iter().filter(|i| i.is_printable());
        for operand in iter.by_ref() {
            match operand.kind() {
                OperandKind::ArchSpec(id, ..) if *id == E2KOperand::CondStart as u64 => {
                    fmt.write_str(if first { "? " } else { " ? " })?;
                    break;
                }
                _ => {
                    if !first {
                        fmt.write_str(", ")?;
                    }
                    self.print_operand(fmt, ext, insn, operand)?;
                }
            }
            first = false;
        }

        if let Some(operand) = iter.next() {
            self.print_operand(fmt, ext, insn, operand)?;
            for operand in iter {
                fmt.write_str(" && ")?;
                self.print_operand(fmt, ext, insn, operand)?;
            }
        }

        Ok(())
    }
}

pub fn printer<E: PrinterExt>(
    opts: &disasm_core::Options,
    opts_arch: &Options,
) -> Box<dyn ArchPrinter<E>> {
    Box::new(Printer::new(opts, opts_arch))
}
