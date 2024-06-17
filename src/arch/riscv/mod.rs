mod gen;

use crate::{Insn, Operand, Options};

use self::gen::{RiscvDecode, Args};

const INSN_AQ: u32 = 1 << 16;
const INSN_RL: u32 = 1 << 17;

pub struct RiscvDecoder {
    opts: Options,
}

impl RiscvDecoder {
    pub fn new(opts: Options) -> Self {
        Self { opts }
    }
}

impl super::Decoder for RiscvDecoder {
    fn decode(&mut self, address: u64, bytes: &[u8], out: &mut Insn) -> Result<usize, usize> {
        let len = bytes.first()
            .map(|i| if i & 3 == 3 { 4} else { 2 })
            .ok_or(2_usize)?;

        if bytes.len() < len {
            // need len bytes
            return Err(len);
        }
        out.clear();
        let mut raw = [0; 4];
        raw[..len].copy_from_slice(&bytes[..len]);
        if RiscvDecode::decode(self, u32::from_le_bytes(raw), address, out) {
            // decoded len bytes
            Ok(len)
        } else {
            // failed to decode len bytes
            Err(len)
        }
    }

    #[cfg(feature = "print")]
    fn register_name(&self, reg: u16) -> Option<&'static str> {
        #[rustfmt::skip]
        const X_ABI_NAME: [&str; 32] = [
            "zero", "ra",   "sp",   "gp",   "tp",   "t0",   "t1",   "t2",
            "s0",   "s1",   "a0",   "a1",   "a2",   "a3",   "a4",   "a5",
            "a6",   "a7",   "s2",   "s3",   "s4",   "s5",   "s6",   "s7",
            "s8",   "s9",   "s10",  "s11",  "t3",   "t4",   "t5",   "t6",
        ];
        X_ABI_NAME.get(reg as usize).copied()
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

    fn ex_sreg_register(&mut self, _value: isize) -> isize {
        todo!()
    }

    fn ex_rvc_register(&mut self, _value: isize) -> isize {
        todo!()
    }

    fn ex_rvc_shiftli(&mut self, _value: isize) -> isize {
        todo!()
    }

    fn ex_rvc_shiftri(&mut self, _value: isize) -> isize {
        todo!()
    }

    fn set_args<A: Args>(&mut self, address: u64, out: &mut Insn, args: A) {
        args.set(address, out);
    }
}

// TODO: generate Args impls???

impl Args for &gen::args_b {
    fn set(&self, address: u64, insn: &mut Insn) {
        insn.push_operand(Operand::Reg(self.rs1 as u16));
        insn.push_operand(Operand::Reg(self.rs2 as u16));
        insn.push_operand(Operand::Address(rel_addr(address, self.imm)));
    }
}

impl Args for &gen::args_b2 {
    fn set(&self, address: u64, insn: &mut Insn) {
        insn.push_operand(Operand::Reg(self.rs1 as u16));
        insn.push_operand(Operand::Address(rel_addr(address, self.imm)));
    }
}

impl Args for &gen::args_i {
    fn set(&self, _: u64, insn: &mut Insn) {
        insn.push_operand(Operand::Reg(self.rd as u16));
        insn.push_operand(Operand::Reg(self.rs1 as u16));
        insn.push_operand(Operand::Imm(self.imm as i64));
    }
}

impl Args for &gen::args_i_2 {
    fn set(&self, _: u64, insn: &mut Insn) {
        insn.push_operand(Operand::Reg(self.rd as u16));
        insn.push_operand(Operand::Imm(self.imm as i64));
    }
}

impl Args for &gen::args_j {
    fn set(&self, address: u64, insn: &mut Insn) {
        if self.rd != 1 {
            insn.push_operand(Operand::Reg(self.rd as u16));
        }
        insn.push_operand(Operand::Address(rel_addr(address, self.imm)));
    }
}

impl Args for &gen::args_j2 {
    fn set(&self, address: u64, insn: &mut Insn) {
        insn.push_operand(Operand::Address(rel_addr(address, self.imm)));
    }
}

impl Args for &gen::args_jr {
    fn set(&self, _: u64, insn: &mut Insn) {
        if self.imm != 0 {
            insn.push_operand(Operand::Offset(self.rs1 as u16, self.imm as i64));
        } else {
            insn.push_operand(Operand::Reg(self.rs1 as u16));
        }
    }
}

impl Args for &gen::args_jalr {
    fn set(&self, _: u64, insn: &mut Insn) {
        if self.rd != 1 {
            insn.push_operand(Operand::Reg(self.rd as u16));
        }
        if self.imm != 0 {
            insn.push_operand(Operand::Offset(self.rs1 as u16, self.imm as i64));
        } else {
            insn.push_operand(Operand::Reg(self.rs1 as u16));
        }
    }
}

impl Args for &gen::args_r {
    fn set(&self, _: u64, insn: &mut Insn) {
        insn.push_operand(Operand::Reg(self.rd as u16));
        insn.push_operand(Operand::Reg(self.rs1 as u16));
        insn.push_operand(Operand::Reg(self.rs2 as u16));
    }
}

impl Args for &gen::args_r2 {
    fn set(&self, _: u64, insn: &mut Insn) {
        insn.push_operand(Operand::Reg(self.rd as u16));
        insn.push_operand(Operand::Reg(self.rs1 as u16));
    }
}

impl Args for &gen::args_r2_s {
    fn set(&self, _: u64, insn: &mut Insn) {
        insn.push_operand(Operand::Reg(self.rs1 as u16));
        insn.push_operand(Operand::Reg(self.rs2 as u16));
    }
}

impl Args for &gen::args_r3 {
    fn set(&self, _: u64, insn: &mut Insn) {
        insn.push_operand(Operand::Reg(self.rd as u16));
        insn.push_operand(Operand::Reg(self.rs2 as u16));
    }
}

impl Args for &gen::args_l {
    fn set(&self, _: u64, insn: &mut Insn) {
        insn.push_operand(Operand::Reg(self.rd as u16));
        insn.push_operand(Operand::Offset(self.rs1 as u16, self.imm as i64));
    }
}

impl Args for &gen::args_s {
    fn set(&self, _: u64, insn: &mut Insn) {
        insn.push_operand(Operand::Reg(self.rs2 as u16));
        insn.push_operand(Operand::Offset(self.rs1 as u16, self.imm as i64));
    }
}

impl Args for &gen::args_u {
    fn set(&self, _: u64, insn: &mut Insn) {
        insn.push_operand(Operand::Reg(self.rd as u16));
        insn.push_operand(Operand::Uimm((self.imm as u64 >> 12) & 0xfffff));
    }
}

impl Args for &gen::args_shift {
    fn set(&self, _: u64, insn: &mut Insn) {
        insn.push_operand(Operand::Reg(self.rd as u16));
        insn.push_operand(Operand::Reg(self.rs1 as u16));
        insn.push_operand(Operand::Uimm(self.shamt as u64));
    }
}

impl Args for &gen::args_atomic_ld {
    fn set(&self, _: u64, insn: &mut Insn) {
        insn.insert_flags(self.aq != 0, INSN_AQ);
        insn.insert_flags(self.rl != 0, INSN_RL);
        insn.push_operand(Operand::Reg(self.rd as u16));
        insn.push_operand(Operand::AddressReg(self.rs1 as u16));
    }
}

impl Args for &gen::args_atomic_st {
    fn set(&self, _: u64, insn: &mut Insn) {
        insn.insert_flags(self.aq != 0, INSN_AQ);
        insn.insert_flags(self.rl != 0, INSN_RL);
        insn.push_operand(Operand::Reg(self.rd as u16));
        insn.push_operand(Operand::Reg(self.rs2 as u16));
        insn.push_operand(Operand::AddressReg(self.rs1 as u16));
    }
}

impl Args for &gen::args_rmrr {
    fn set(&self, _address: u64, _insn: &mut Insn) {
        // TODO:
    }
}

impl Args for &gen::args_rmr {
    fn set(&self, _address: u64, _insn: &mut Insn) {
        // TODO:
    }
}

impl Args for &gen::args_r2nfvm {
    fn set(&self, _address: u64, _insn: &mut Insn) {
        // TODO:
    }
}

impl Args for &gen::args_rnfvm {
    fn set(&self, _address: u64, _insn: &mut Insn) {
        // TODO:
    }
}

impl Args for &gen::args_k_aes {
    fn set(&self, _address: u64, _insn: &mut Insn) {
        // TODO:
    }
}

impl Args for &gen::args_ci {
    fn set(&self, _: u64, insn: &mut Insn) {
        insn.push_operand(Operand::Reg(self.rd as u16));
        insn.push_operand(Operand::Imm(self.imm as i64));
    }
}

fn rel_addr(address: u64, offset: isize) -> u64 {
    (address as i64).wrapping_add(offset as i64) as u64
}

