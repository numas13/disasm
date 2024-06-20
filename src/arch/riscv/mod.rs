mod gen;

#[cfg(feature = "print")]
use core::fmt;

use alloc::borrow::Cow;

#[cfg(feature = "print")]
use crate::Operand;
use crate::{Bundle, Insn, Reg, RegClass};

use self::gen::RiscvDecode;

pub use self::gen::opcode;

pub const REG_CLASS_CSR: RegClass = RegClass::arch(0);

const INSN_AQ: u32 = 1 << 16;
const INSN_RL: u32 = 1 << 17;

pub const RM_RNE: u8 = 0;
pub const RM_RTZ: u8 = 1;
pub const RM_RDN: u8 = 2;
pub const RM_RUP: u8 = 3;
pub const RM_RMM: u8 = 4;
pub const RM_DYN: u8 = 7;

const OPERAND_FENCE: u64 = 0;
const OPERAND_RM: u64 = 1;

#[rustfmt::skip]
const X_NAME: [&str; 32] = [
    "x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",
    "x8",  "x9",  "x10", "x11", "x12", "x13", "x14", "x15",
    "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
    "x24", "x25", "x26", "x27", "x28", "x29", "x30", "x31",
];

#[rustfmt::skip]
const X_ABI_NAME: [&str; 32] = [
    "zero", "ra",   "sp",   "gp",   "tp",   "t0",   "t1",   "t2",
    "s0",   "s1",   "a0",   "a1",   "a2",   "a3",   "a4",   "a5",
    "a6",   "a7",   "s2",   "s3",   "s4",   "s5",   "s6",   "s7",
    "s8",   "s9",   "s10",  "s11",  "t3",   "t4",   "t5",   "t6",
];

#[rustfmt::skip]
const F_NAME: [&str; 32] = [
    "f0",  "f1",  "f2",  "f3",  "f4",  "f5",  "f6",  "f7",
    "f8",  "f9",  "f10", "f11", "f12", "f13", "f14", "f15",
    "f16", "f17", "f18", "f19", "f20", "f21", "f22", "f23",
    "f24", "f25", "f26", "f27", "f28", "f29", "f30", "f31",
];

#[rustfmt::skip]
const F_ABI_NAME: [&str; 32] = [
    "ft0",  "ft1", "ft2",  "ft3",   "ft4",  "ft5", "ft6",  "ft7",
    "fs0",  "fs1", "fa0",  "fa1",   "fa2",  "fa3", "fa4",  "fa5",
    "fa6",  "fa7", "fs2",  "fs3",   "fs4",  "fs5", "fs6",  "fs7",
    "fs8",  "fs9", "fs10", "fs11",  "ft8",  "ft9", "ft10", "ft11",
];

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Xlen {
    X32,
    X64,
    X128,
}

impl Default for Xlen {
    fn default() -> Self {
        Self::X64
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Extensions {
    pub a: bool,
    pub c: bool,
    pub d: bool,
    pub f: bool,
    pub m: bool,
    pub zcb: bool,
    pub zfh: bool,
    pub zicsr: bool,
}

impl Extensions {
    pub fn all() -> Self {
        Self {
            a: true,
            c: true,
            d: true,
            f: true,
            m: true,
            zcb: true,
            zfh: true,
            zicsr: true,
        }
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Options {
    pub xlen: Xlen,
    pub ext: Extensions,
}

pub(crate) struct Decoder {
    opts: crate::Options,
    rv_opts: Options,
}

impl Decoder {
    pub(crate) fn new(opts: crate::Options, rv_opts: Options) -> Self {
        Self { opts, rv_opts }
    }
}

impl super::Decoder for Decoder {
    fn decode(&mut self, address: u64, bytes: &[u8], out: &mut Bundle) -> Result<usize, usize> {
        let len = bytes
            .first()
            .map(|i| if i & 3 == 3 { 4 } else { 2 })
            .ok_or(2_usize)?;

        if bytes.len() < len || (len == 2 && !self.rv_opts.ext.c) {
            return Err(len);
        }
        out.clear();
        let mut raw = [0; 4];
        raw[..len].copy_from_slice(&bytes[..len]);
        if RiscvDecode::decode(self, u32::from_le_bytes(raw), address, out.peek()) {
            // decoded len bytes
            out.next();
            Ok(len)
        } else {
            // failed to decode len bytes
            Err(len)
        }
    }

    #[cfg(feature = "print")]
    fn register_name(&self, reg: Reg) -> Cow<'static, str> {
        let index = reg.index() as usize;
        match reg.class() {
            RegClass::INT => {
                let names = if self.opts.abi_regs {
                    X_ABI_NAME
                } else {
                    X_NAME
                };
                names[index].into()
            }
            RegClass::FLOAT => {
                let names = if self.opts.abi_regs {
                    F_ABI_NAME
                } else {
                    F_NAME
                };
                names[index].into()
            }
            REG_CLASS_CSR => match index {
                0x001 => "fflags",
                0x002 => "frm",
                0x003 => "fcsr",
                _ => return format!("csr:{index}").into(),
            }
            .into(),
            _ => todo!(),
        }
    }

    #[cfg(feature = "mnemonic")]
    fn mnemonic(&self, insn: &Insn) -> Option<(&'static str, &'static str)> {
        let m = self::gen::mnemonic(insn.opcode())?;
        let flags = insn.flags();
        let s = match (flags & INSN_AQ != 0, flags & INSN_RL != 0) {
            (true, true) => "aqrl",
            (true, false) => "aq",
            (false, true) => "rl",
            (false, false) => "",
        };
        Some((m, s))
    }

    #[cfg(feature = "print")]
    #[allow(unused_variables)]
    fn print_operand_check(&self, operand: &Operand) -> bool {
        if let Operand::ArchSpec(ty, value) = operand {
            !matches!(*ty, OPERAND_RM if *value == 7)
        } else {
            true
        }
    }

    #[cfg(feature = "print")]
    fn print_operand(
        &self,
        fmt: &mut fmt::Formatter,
        operand: &Operand,
    ) -> Result<bool, fmt::Error> {
        if let &Operand::ArchSpec(ty, value) = operand {
            match ty {
                OPERAND_FENCE => {
                    assert!(value < 4); // TODO:
                    if value & 2 != 0 {
                        write!(fmt, "r")?;
                    }
                    if value & 1 != 0 {
                        write!(fmt, "w")?;
                    }
                    Ok(true)
                }
                OPERAND_RM => {
                    let s = match value as u8 {
                        RM_RNE => "rne",
                        RM_RTZ => "rtz",
                        RM_RDN => "rdn",
                        RM_RUP => "rup",
                        RM_RMM => "rmm",
                        RM_DYN => "dyn",
                        _ => todo!(),
                    };
                    fmt.write_str(s)?;
                    Ok(true)
                }
                _ => todo!(),
            }
        } else {
            Ok(false)
        }
    }
}

macro_rules! impl_ex_shift {
    ($($name:ident = $shift:expr),+ $(,)?) => {
        $(fn $name(&mut self, value: isize) -> isize {
            value << $shift
        })+
    };
}

macro_rules! impl_has_ext {
    ($($func:ident = $name:ident),+$(,)?) => {
        $(fn $func(&self) -> bool {
            self.rv_opts.ext.$name
        })+
    }
}

impl RiscvDecode for Decoder {
    fn alias(&self) -> bool {
        self.opts.alias
    }

    fn has_rv64i(&self) -> bool {
        self.rv_opts.xlen == Xlen::X64
    }

    fn has_rv128i(&self) -> bool {
        self.rv_opts.xlen == Xlen::X128
    }

    impl_has_ext! {
        has_a = a,
        has_d = d,
        has_f = f,
        has_m = m,
        has_zcb = zcb,
        has_zfh = zfh,
        has_zicsr = zicsr,
    }

    impl_ex_shift! {
        ex_shift_1 = 1,
        ex_shift_2 = 2,
        ex_shift_3 = 3,
        ex_shift_4 = 4,
        ex_shift_12 = 12,
    }

    fn ex_plus_1(&mut self, value: isize) -> isize {
        value + 1
    }

    fn ex_sreg_register(&mut self, value: isize) -> isize {
        if value < 2 {
            value + 8
        } else {
            value + 16
        }
    }

    fn ex_rvc_register(&mut self, value: isize) -> isize {
        value + 8
    }

    fn ex_rvc_shiftli(&mut self, value: isize) -> isize {
        // TODO: rv128c
        value
    }

    fn ex_rvc_shiftri(&mut self, value: isize) -> isize {
        // TODO: rv128c
        value
    }

    // fn set_args<A: Args>(&mut self, address: u64, out: &mut Insn, args: A) {
    //     args.set(self, address, out);
    // }

    fn set_rd(&mut self, _: u64, out: &mut Insn, value: i64) {
        out.push_reg(x(value));
    }

    /// C-ext, rd = op(rd, ...)
    fn set_rds(&mut self, _: u64, out: &mut Insn, value: i64) {
        out.push_reg(x(value));
    }

    fn set_rs1(&mut self, _: u64, out: &mut Insn, value: i64) {
        out.push_reg(x(value));
    }

    fn set_rs2(&mut self, _: u64, out: &mut Insn, value: i64) {
        out.push_reg(x(value));
    }

    fn set_fd(&mut self, _: u64, out: &mut Insn, value: i64) {
        out.push_reg(f(value));
    }

    fn set_fs1(&mut self, _: u64, out: &mut Insn, value: i64) {
        out.push_reg(f(value));
    }

    fn set_fs2(&mut self, _: u64, out: &mut Insn, value: i64) {
        out.push_reg(f(value));
    }

    fn set_fs3(&mut self, _: u64, out: &mut Insn, value: i64) {
        out.push_reg(f(value));
    }

    fn set_rm(&mut self, _: u64, out: &mut Insn, value: i64) {
        out.push_arch_spec(OPERAND_RM, value as u64);
    }

    fn set_vm(&mut self, _: u64, _: &mut Insn, _: i64) {
        // TODO:
    }

    fn set_zimm(&mut self, _: u64, _: &mut Insn, _: i64) {
        // TODO:
    }

    fn set_pred(&mut self, _: u64, out: &mut Insn, value: i64) {
        out.push_arch_spec(OPERAND_FENCE, value as u64);
    }

    fn set_succ(&mut self, _: u64, out: &mut Insn, value: i64) {
        out.push_arch_spec(OPERAND_FENCE, value as u64);
    }

    fn set_addr_reg(&mut self, _: u64, out: &mut Insn, value: i64) {
        out.push_addr_reg(x(value));
    }

    fn set_rel(&mut self, address: u64, out: &mut Insn, rel: i64) {
        out.push_addr(rel_addr(address, rel as isize));
    }

    fn set_aq(&mut self, _: u64, out: &mut Insn, aq: i64) {
        out.insert_flags(aq != 0, INSN_AQ);
    }

    fn set_rl(&mut self, _: u64, out: &mut Insn, rl: i64) {
        out.insert_flags(rl != 0, INSN_RL);
    }

    fn set_csr(&mut self, _: u64, out: &mut Insn, value: i64) {
        out.push_reg(csr(value));
    }

    fn set_imm(&mut self, _: u64, out: &mut Insn, value: i64) {
        out.push_imm(value);
    }

    fn set_uimm(&mut self, _: u64, out: &mut Insn, value: i64) {
        out.push_uimm(value as u64);
    }

    fn set_imm_u(&mut self, _: u64, out: &mut Insn, value: i64) {
        out.push_uimm((value as u64 >> 12) & 0xfffff);
    }

    fn set_args_j(&mut self, address: u64, insn: &mut Insn, args: &gen::args_j) {
        if !self.alias() || args.rd != 1 {
            insn.push_reg(x(args.rd as i64));
        }
        insn.push_addr(rel_addr(address, args.imm));
    }

    fn set_args_jr(&mut self, _: u64, insn: &mut Insn, args: &gen::args_jr) {
        let rs1 = x(args.rs1 as i64);
        if args.imm != 0 {
            insn.push_offset(rs1, args.imm as i64);
        } else {
            insn.push_reg(rs1);
        }
    }

    fn set_args_jalr(&mut self, _: u64, insn: &mut Insn, args: &gen::args_jalr) {
        if !self.alias() || args.rd != 1 {
            insn.push_reg(x(args.rd as i64));
        }
        if !self.alias() || args.imm != 0 {
            insn.push_offset(x(args.rs1 as i64), args.imm as i64);
        } else {
            insn.push_reg(x(args.rs1 as i64));
        }
    }

    fn set_args_l(&mut self, _: u64, insn: &mut Insn, args: &gen::args_l) {
        insn.push_reg(x(args.rd as i64));
        insn.push_offset(x(args.rs1 as i64), args.imm as i64);
    }

    fn set_args_s(&mut self, _: u64, insn: &mut Insn, args: &gen::args_s) {
        insn.push_reg(x(args.rs2 as i64));
        insn.push_offset(x(args.rs1 as i64), args.imm as i64);
    }

    fn set_args_fl(&mut self, _: u64, insn: &mut Insn, args: &gen::args_fl) {
        insn.push_reg(f(args.fd as i64));
        insn.push_offset(x(args.rs1 as i64), args.imm as i64);
    }

    fn set_args_fs(&mut self, _: u64, insn: &mut Insn, args: &gen::args_fs) {
        insn.push_reg(f(args.fs2 as i64));
        insn.push_offset(x(args.rs1 as i64), args.imm as i64);
    }

    fn set_args_rmrr(&mut self, _: u64, _: &mut Insn, _: &gen::args_rmrr) {
        // TODO:
    }

    fn set_args_rmr(&mut self, _: u64, _: &mut Insn, _: &gen::args_rmr) {
        // TODO:
    }

    fn set_args_r2nfvm(&mut self, _: u64, _: &mut Insn, _: &gen::args_r2nfvm) {
        // TODO:
    }

    fn set_args_rnfvm(&mut self, _: u64, _: &mut Insn, _: &gen::args_rnfvm) {
        // TODO:
    }

    fn set_args_k_aes(&mut self, _: u64, _: &mut Insn, _: &gen::args_k_aes) {
        // TODO:
    }

    fn set_args_cmpp(&mut self, _: u64, _: &mut Insn, _: &gen::args_cmpp) {
        // TODO:
    }

    fn set_args_cmjt(&mut self, _: u64, _: &mut Insn, _: &gen::args_cmjt) {
        // TODO:
    }
}

fn x(index: i64) -> Reg {
    Reg::new(RegClass::INT, index as u64)
}

fn f(index: i64) -> Reg {
    Reg::new(RegClass::FLOAT, index as u64)
}

fn csr(index: i64) -> Reg {
    Reg::new(REG_CLASS_CSR, index as u64)
}

fn rel_addr(address: u64, offset: isize) -> u64 {
    (address as i64).wrapping_add(offset as i64) as u64
}
