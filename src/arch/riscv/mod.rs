mod gen;

use core::ops::Range;

use alloc::borrow::Cow;

use crate::{Bundle, Insn, Options, Reg, RegClass};

use self::gen::{Args, RiscvDecode};

pub use self::gen::opcode;

pub const REG_CLASS_CSR: RegClass = RegClass::arch(0);

const REG_X: Range<isize> = 0..32;
const REG_F: Range<isize> = REG_X.end..REG_X.end + 32;
const REG_V: Range<isize> = REG_F.end..REG_F.end + 32;
const REG_CSR: Range<isize> = REG_V.end..REG_V.end + 4096;

const INSN_AQ: u32 = 1 << 16;
const INSN_RL: u32 = 1 << 17;

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

pub(crate) struct RiscvDecoder {
    opts: Options,
}

impl RiscvDecoder {
    pub(crate) fn new(opts: Options) -> Self {
        Self { opts }
    }
}

impl super::Decoder for RiscvDecoder {
    fn decode(&mut self, address: u64, bytes: &[u8], out: &mut Bundle) -> Result<usize, usize> {
        let len = bytes
            .first()
            .map(|i| if i & 3 == 3 { 4 } else { 2 })
            .ok_or(2_usize)?;

        if bytes.len() < len {
            // need len bytes
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
            (true, true) => "sc",
            (true, false) => "aq",
            (false, true) => "rl",
            (false, false) => "",
        };
        Some((m, s))
    }
}

macro_rules! impl_ex_shift {
    ($($name:ident = $shift:expr),+ $(,)?) => {
        $(fn $name(&mut self, value: isize) -> isize {
            value << $shift
        })+
    };
}

impl RiscvDecode for RiscvDecoder {
    fn opts(&self) -> &Options {
        &self.opts
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

    fn ex_freg(&mut self, value: isize) -> isize {
        value + REG_F.start
    }

    // fn ex_vreg(&mut self, value: isize) -> isize {
    //     value + REG_V.start
    // }

    fn ex_csr(&mut self, value: isize) -> isize {
        value + REG_CSR.start
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

    fn ex_rvc_freg(&mut self, value: isize) -> isize {
        let value = self.ex_rvc_register(value);
        self.ex_freg(value)
    }

    fn ex_rvc_shiftli(&mut self, value: isize) -> isize {
        // TODO: rv128c
        value
    }

    fn ex_rvc_shiftri(&mut self, value: isize) -> isize {
        // TODO: rv128c
        value
    }

    fn set_args<A: Args>(&mut self, address: u64, out: &mut Insn, args: A) {
        args.set(self, address, out);
    }

    fn set_rd(&mut self, _: u64, out: &mut Insn, value: i64) {
        out.push_reg(reg(value as isize));
    }

    /// C-ext, rd = op(rd, ...)
    fn set_rds(&mut self, _: u64, out: &mut Insn, value: i64) {
        out.push_reg(reg(value as isize));
    }

    fn set_rs1(&mut self, _: u64, out: &mut Insn, value: i64) {
        out.push_reg(reg(value as isize));
    }

    fn set_rs2(&mut self, _: u64, out: &mut Insn, value: i64) {
        out.push_reg(reg(value as isize));
    }

    fn set_fd(&mut self, _: u64, out: &mut Insn, value: i64) {
        out.push_reg(reg(value as isize));
    }

    fn set_fs1(&mut self, _: u64, out: &mut Insn, value: i64) {
        out.push_reg(reg(value as isize));
    }

    fn set_fs2(&mut self, _: u64, out: &mut Insn, value: i64) {
        out.push_reg(reg(value as isize));
    }

    fn set_fs3(&mut self, _: u64, out: &mut Insn, value: i64) {
        out.push_reg(reg(value as isize));
    }

    fn set_rm(&mut self, _: u64, _: &mut Insn, _: i64) {
        // TODO:
    }

    fn set_vm(&mut self, _: u64, _: &mut Insn, _: i64) {
        // TODO:
    }

    fn set_pred(&mut self, _: u64, _: &mut Insn, _: i64) {
        // TODO:
    }

    fn set_zimm(&mut self, _: u64, _: &mut Insn, _: i64) {
        // TODO:
    }

    fn set_succ(&mut self, _: u64, _: &mut Insn, _: i64) {
        // TODO:
    }

    fn set_addr_reg(&mut self, _: u64, out: &mut Insn, value: i64) {
        out.push_addr_reg(reg(value as isize));
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

    fn set_csr(&mut self, _: u64, out: &mut Insn, csr: i64) {
        out.push_reg(reg(csr as isize));
    }

    fn set_imm(&mut self, _: u64, out: &mut Insn, value: i64) {
        out.push_imm(value as i64);
    }

    fn set_uimm(&mut self, _: u64, out: &mut Insn, value: i64) {
        out.push_uimm(value as u64);
    }
}

// TODO: generate Args impls???

fn reg(value: isize) -> Reg {
    let (class, offset) = match value {
        _ if REG_X.contains(&value) => (RegClass::INT, REG_X.start),
        _ if REG_F.contains(&value) => (RegClass::FLOAT, REG_F.start),
        _ if REG_V.contains(&value) => (RegClass::VECTOR, REG_V.start),
        _ if REG_CSR.contains(&value) => (REG_CLASS_CSR, REG_CSR.start),
        _ => todo!(),
    };
    Reg::new(class, value as u64 - offset as u64)
}

impl Args for &gen::args_i {
    fn set(&self, _: &RiscvDecoder, _: u64, insn: &mut Insn) {
        insn.push_reg(reg(self.rd));
        insn.push_reg(reg(self.rs1));
        insn.push_imm(self.imm as i64);
    }
}

impl Args for &gen::args_i2 {
    fn set(&self, _: &RiscvDecoder, _: u64, insn: &mut Insn) {
        insn.push_reg(reg(self.rd));
        insn.push_imm(self.imm as i64);
    }
}

impl Args for &gen::args_j {
    fn set(&self, dec: &RiscvDecoder, address: u64, insn: &mut Insn) {
        if !dec.opts.alias || self.rd != 1 {
            insn.push_reg(reg(self.rd));
        }
        insn.push_addr(rel_addr(address, self.imm));
    }
}

impl Args for &gen::args_j2 {
    fn set(&self, _: &RiscvDecoder, address: u64, insn: &mut Insn) {
        insn.push_addr(rel_addr(address, self.imm));
    }
}

impl Args for &gen::args_jr {
    fn set(&self, _: &RiscvDecoder, _: u64, insn: &mut Insn) {
        let rs1 = reg(self.rs1);
        if self.imm != 0 {
            insn.push_offset(rs1, self.imm as i64);
        } else {
            insn.push_reg(rs1);
        }
    }
}

impl Args for &gen::args_jalr {
    fn set(&self, dec: &RiscvDecoder, _: u64, insn: &mut Insn) {
        if !dec.opts.alias || self.rd != 1 {
            insn.push_reg(reg(self.rd));
        }
        if self.imm != 0 {
            insn.push_offset(reg(self.rs1), self.imm as i64);
        } else {
            insn.push_reg(reg(self.rs1));
        }
    }
}

impl Args for &gen::args_r2 {
    fn set(&self, _: &RiscvDecoder, _: u64, insn: &mut Insn) {
        insn.push_reg(reg(self.rd));
        insn.push_reg(reg(self.rs1));
    }
}

impl Args for &gen::args_r2_s {
    fn set(&self, _: &RiscvDecoder, _: u64, insn: &mut Insn) {
        insn.push_reg(reg(self.rs1));
        insn.push_reg(reg(self.rs2));
    }
}

impl Args for &gen::args_r3 {
    fn set(&self, _: &RiscvDecoder, _: u64, insn: &mut Insn) {
        insn.push_reg(reg(self.rd));
        insn.push_reg(reg(self.rs2));
    }
}

impl Args for &gen::args_l {
    fn set(&self, _: &RiscvDecoder, _: u64, insn: &mut Insn) {
        insn.push_reg(reg(self.rd));
        insn.push_offset(reg(self.rs1), self.imm as i64);
    }
}

impl Args for &gen::args_s {
    fn set(&self, _: &RiscvDecoder, _: u64, insn: &mut Insn) {
        insn.push_reg(reg(self.rs2));
        insn.push_offset(reg(self.rs1), self.imm as i64);
    }
}

impl Args for &gen::args_u {
    fn set(&self, _: &RiscvDecoder, _: u64, insn: &mut Insn) {
        insn.push_reg(reg(self.rd));
        insn.push_uimm((self.imm as u64 >> 12) & 0xfffff);
    }
}

impl Args for &gen::args_shift {
    fn set(&self, _: &RiscvDecoder, _: u64, insn: &mut Insn) {
        insn.push_reg(reg(self.rd));
        insn.push_reg(reg(self.rs1));
        insn.push_uimm(self.shamt as u64);
    }
}

impl Args for &gen::args_shift_c {
    fn set(&self, _: &RiscvDecoder, _: u64, insn: &mut Insn) {
        insn.push_reg(reg(self.rd));
        insn.push_uimm(self.shamt as u64);
    }
}

impl Args for &gen::args_rmrr {
    fn set(&self, _: &RiscvDecoder, _address: u64, _insn: &mut Insn) {
        // TODO:
    }
}

impl Args for &gen::args_rmr {
    fn set(&self, _: &RiscvDecoder, _address: u64, _insn: &mut Insn) {
        // TODO:
    }
}

impl Args for &gen::args_r2nfvm {
    fn set(&self, _: &RiscvDecoder, _address: u64, _insn: &mut Insn) {
        // TODO:
    }
}

impl Args for &gen::args_rnfvm {
    fn set(&self, _: &RiscvDecoder, _address: u64, _insn: &mut Insn) {
        // TODO:
    }
}

impl Args for &gen::args_k_aes {
    fn set(&self, _: &RiscvDecoder, _address: u64, _insn: &mut Insn) {
        // TODO:
    }
}

impl Args for &gen::args_cmpp {
    fn set(&self, _: &RiscvDecoder, _: u64, _insn: &mut Insn) {
        // TODO:
    }
}

impl Args for &gen::args_cmjt {
    fn set(&self, _: &RiscvDecoder, _: u64, _insn: &mut Insn) {
        // TODO:
    }
}

fn rel_addr(address: u64, offset: isize) -> u64 {
    (address as i64).wrapping_add(offset as i64) as u64
}
