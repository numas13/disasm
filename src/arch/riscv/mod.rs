mod generated;

#[cfg(feature = "print")]
use core::fmt;

use alloc::borrow::Cow;

#[cfg(feature = "print")]
use crate::Operand;
use crate::{Bundle, Insn, Reg, RegClass};

use self::generated::RiscvDecode;

pub use self::generated::opcode;

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
    address: u64,
}

impl Decoder {
    pub(crate) fn new(opts: crate::Options, rv_opts: Options) -> Self {
        Self {
            opts,
            rv_opts,
            address: 0,
        }
    }

    fn alias(&self) -> bool {
        self.opts.alias
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
        self.address = address;
        if RiscvDecode::decode(self, u32::from_le_bytes(raw), out.peek()) {
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
        let m = self::generated::mnemonic(insn.opcode())?;
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
                    let fence = ['w', 'r', 'o', 'i'];
                    for i in (0..4).rev() {
                        if value & (1 << i) != 0 {
                            write!(fmt, "{}", fence[i])?;
                        }
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
        $(fn $name(&self, value: i32) -> i32 {
            value << $shift
        })+
    };
}

macro_rules! impl_cond_ext {
    ($($func:ident = $name:ident),+$(,)?) => {
        $(fn $func(&self) -> bool {
            self.rv_opts.ext.$name
        })+
    }
}

impl RiscvDecode for Decoder {
    fn cond_alias(&self) -> bool {
        self.alias()
    }

    fn cond_rv64i(&self) -> bool {
        self.rv_opts.xlen == Xlen::X64
    }

    fn cond_rv128i(&self) -> bool {
        self.rv_opts.xlen == Xlen::X128
    }

    impl_cond_ext! {
        cond_a = a,
        cond_d = d,
        cond_f = f,
        cond_m = m,
        cond_zcb = zcb,
        cond_zfh = zfh,
        cond_zicsr = zicsr,
    }

    fn cond_is_same_rs1_rs2(&self, insn: u32) -> bool {
        self.extract_rs1(insn) == self.extract_rs2(insn)
    }

    impl_ex_shift! {
        ex_shift_1 = 1,
        ex_shift_2 = 2,
        ex_shift_3 = 3,
        ex_shift_4 = 4,
        ex_shift_12 = 12,
    }

    fn ex_plus_1(&self, value: i32) -> i32 {
        value + 1
    }

    fn ex_sreg_register(&self, value: i32) -> i32 {
        if value < 2 {
            value + 8
        } else {
            value + 16
        }
    }

    fn ex_rvc_register(&self, value: i32) -> i32 {
        value + 8
    }

    fn ex_rvc_shiftli(&self, value: i32) -> i32 {
        // TODO: rv128c
        value
    }

    fn ex_rvc_shiftri(&self, value: i32) -> i32 {
        // TODO: rv128c
        value
    }

    fn set_rd(&mut self, out: &mut Insn, value: i32) {
        out.push_reg(x(value));
    }

    /// C-ext, rd = op(rd, ...)
    fn set_rds(&mut self, out: &mut Insn, value: i32) {
        out.push_reg(x(value));
    }

    fn set_rs1(&mut self, out: &mut Insn, value: i32) {
        out.push_reg(x(value));
    }

    fn set_rs2(&mut self, out: &mut Insn, value: i32) {
        out.push_reg(x(value));
    }

    fn set_fd(&mut self, out: &mut Insn, value: i32) {
        out.push_reg(f(value));
    }

    fn set_fs1(&mut self, out: &mut Insn, value: i32) {
        out.push_reg(f(value));
    }

    fn set_fs2(&mut self, out: &mut Insn, value: i32) {
        out.push_reg(f(value));
    }

    fn set_fs3(&mut self, out: &mut Insn, value: i32) {
        out.push_reg(f(value));
    }

    fn set_rm(&mut self, out: &mut Insn, value: i32) {
        out.push_arch_spec(OPERAND_RM, value as u64);
    }

    fn set_vm(&mut self, _: &mut Insn, _: i32) {
        // TODO:
    }

    fn set_addr_reg(&mut self, out: &mut Insn, value: i32) {
        out.push_addr_reg(x(value));
    }

    fn set_rel(&mut self, out: &mut Insn, rel: i32) {
        out.push_addr(rel_addr(self.address, rel));
    }

    fn set_aq(&mut self, out: &mut Insn, aq: i32) {
        out.insert_flags(aq != 0, INSN_AQ);
    }

    fn set_rl(&mut self, out: &mut Insn, rl: i32) {
        out.insert_flags(rl != 0, INSN_RL);
    }

    fn set_csr(&mut self, out: &mut Insn, value: i32) {
        out.push_reg(csr(value));
    }

    fn set_imm(&mut self, out: &mut Insn, value: i32) {
        out.push_imm(value as i64);
    }

    fn set_uimm(&mut self, out: &mut Insn, value: i32) {
        out.push_uimm(value as u64);
    }

    fn set_imm_u(&mut self, out: &mut Insn, value: i32) {
        out.push_uimm((value as u64 >> 12) & 0xfffff);
    }

    fn set_args_offset(&mut self, insn: &mut Insn, args: generated::args_offset) {
        insn.push_offset(x(args.rs1), args.imm as i64);
    }

    fn set_args_j(&mut self, insn: &mut Insn, args: generated::args_j) {
        if !self.alias() || args.rd != 1 {
            insn.push_reg(x(args.rd));
        }
        insn.push_addr(rel_addr(self.address, args.imm));
    }

    fn set_args_jr(&mut self, insn: &mut Insn, args: generated::args_jr) {
        let rs1 = x(args.rs1);
        if args.imm != 0 {
            insn.push_offset(rs1, args.imm as i64);
        } else {
            insn.push_reg(rs1);
        }
    }

    fn set_args_jalr(&mut self, insn: &mut Insn, args: generated::args_jalr) {
        if !self.alias() || args.rd != 1 {
            insn.push_reg(x(args.rd));
        }
        if !self.alias() || args.imm != 0 {
            insn.push_offset(x(args.rs1), args.imm as i64);
        } else {
            insn.push_reg(x(args.rs1));
        }
    }

    fn set_args_fence(&mut self, insn: &mut Insn, args: generated::args_fence) {
        if !self.alias() || args.pred != 0b1111 || args.succ != 0b1111 {
            insn.push_arch_spec(OPERAND_FENCE, args.pred as u64);
            insn.push_arch_spec(OPERAND_FENCE, args.succ as u64);
        }
    }

    fn set_args_rmrr(&mut self, _: &mut Insn, _: generated::args_rmrr) {
        // TODO:
    }

    fn set_args_rmr(&mut self, _: &mut Insn, _: generated::args_rmr) {
        // TODO:
    }

    fn set_args_r2nfvm(&mut self, _: &mut Insn, _: generated::args_r2nfvm) {
        // TODO:
    }

    fn set_args_rnfvm(&mut self, _: &mut Insn, _: generated::args_rnfvm) {
        // TODO:
    }

    fn set_args_k_aes(&mut self, _: &mut Insn, _: generated::args_k_aes) {
        // TODO:
    }

    // fn set_args_cmpp(&mut self, _: &mut Insn, _: generated::args_cmpp) {
    //     // TODO:
    // }

    // fn set_args_cmjt(&mut self, _: &mut Insn, _: generated::args_cmjt) {
    //     // TODO:
    // }
}

fn x(index: i32) -> Reg {
    Reg::new(RegClass::INT, index as u64)
}

fn f(index: i32) -> Reg {
    Reg::new(RegClass::FLOAT, index as u64)
}

fn csr(index: i32) -> Reg {
    Reg::new(REG_CLASS_CSR, index as u64)
}

fn rel_addr(address: u64, offset: i32) -> u64 {
    (address as i64).wrapping_add(offset as i64) as u64
}
