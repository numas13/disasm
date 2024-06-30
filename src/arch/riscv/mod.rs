mod generated;
#[cfg(feature = "print")]
mod printer;

use crate::{Bundle, Insn, Operand, Reg, RegClass};

use self::generated::RiscvDecode;

pub use self::generated::opcode;

#[cfg(feature = "print")]
pub(crate) use self::printer::printer;

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

struct Decoder {
    opts: crate::Options,
    opts_arch: Options,
    address: u64,
}

impl Decoder {
    fn new(opts: crate::Options, opts_arch: Options) -> Self {
        Self {
            opts,
            opts_arch,
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

        if bytes.len() < len || (len == 2 && !self.opts_arch.ext.c) {
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

    fn insn_size_min(&self) -> u16 {
        if self.opts_arch.ext.c {
            2
        } else {
            4
        }
    }

    fn insn_size_max(&self) -> u16 {
        4
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
            self.opts_arch.ext.$name
        })+
    }
}

impl RiscvDecode for Decoder {
    fn cond_alias(&self) -> bool {
        self.alias()
    }

    fn cond_rv64i(&self) -> bool {
        self.opts_arch.xlen == Xlen::X64
    }

    fn cond_rv128i(&self) -> bool {
        self.opts_arch.xlen == Xlen::X128
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
        out.push_reg(x(value).write());
    }

    fn set_rd_implicit(&mut self, out: &mut Insn, value: i32) {
        out.push_reg(x(value).write().implicit());
    }

    /// C-ext, rd = op(rd, ...)
    fn set_rds(&mut self, out: &mut Insn, value: i32) {
        out.push_reg(x(value).read().write());
    }

    fn set_rs1(&mut self, out: &mut Insn, value: i32) {
        out.push_reg(x(value).read());
    }

    fn set_rs1_implicit(&mut self, out: &mut Insn, value: i32) {
        out.push_reg(x(value).read().implicit());
    }

    fn set_rs2(&mut self, out: &mut Insn, value: i32) {
        out.push_reg(x(value).read());
    }

    fn set_fd(&mut self, out: &mut Insn, value: i32) {
        out.push_reg(f(value).write());
    }

    fn set_fs1(&mut self, out: &mut Insn, value: i32) {
        out.push_reg(f(value).read());
    }

    fn set_fs2(&mut self, out: &mut Insn, value: i32) {
        out.push_reg(f(value).read());
    }

    fn set_fs3(&mut self, out: &mut Insn, value: i32) {
        out.push_reg(f(value).read());
    }

    fn set_rm(&mut self, out: &mut Insn, value: i32) {
        out.push_operand(
            Operand::arch(OPERAND_RM, value as u64).non_printable(value as u8 == RM_DYN),
        )
    }

    fn set_vm(&mut self, _: &mut Insn, _: i32) {
        // TODO:
    }

    fn set_addr_reg(&mut self, out: &mut Insn, value: i32) {
        out.push_addr_reg(x(value).read());
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
        // TODO: csr read/write
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
        insn.push_offset(x(args.rs1).read(), args.imm as i64);
    }

    fn set_args_offset_implicit(&mut self, insn: &mut Insn, args: generated::args_offset_implicit) {
        insn.push_offset(x(args.rs1).read().implicit(), args.imm as i64);
    }

    fn set_args_j(&mut self, insn: &mut Insn, args: generated::args_j) {
        insn.push_operand(
            Operand::reg(x(args.rd).write()).non_printable(self.alias() && args.rd == 1),
        );
        insn.push_addr(rel_addr(self.address, args.imm));
    }

    fn set_args_jr(&mut self, insn: &mut Insn, args: generated::args_jr) {
        let rs1 = x(args.rs1).read();
        if args.imm != 0 {
            insn.push_offset(rs1, args.imm as i64);
        } else {
            insn.push_reg(rs1);
        }
    }

    fn set_args_jalr(&mut self, insn: &mut Insn, args: generated::args_jalr) {
        insn.push_operand(
            Operand::reg(x(args.rd).write()).non_printable(self.alias() && args.rd == 1),
        );
        let rs1 = x(args.rs1).read();
        if self.alias() && args.imm == 0 {
            insn.push_reg(rs1);
        } else {
            insn.push_offset(rs1, args.imm as i64);
        }
    }

    fn set_args_fence(&mut self, insn: &mut Insn, args: generated::args_fence) {
        // TODO: non_printable
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

pub(crate) fn decoder(opts: crate::Options, opts_arch: Options) -> Box<dyn crate::Decoder> {
    Box::new(Decoder::new(opts, opts_arch))
}
