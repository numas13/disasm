mod gen;

use crate::{Bundle, Insn, Options, Reg};

use self::gen::{Args, RiscvDecode};

pub use self::gen::opcode;

const INSN_AQ: u32 = 1 << 16;
const INSN_RL: u32 = 1 << 17;

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
    fn register_name(&self, reg: Reg) -> Option<&'static str> {
        #[rustfmt::skip]
        const X_ABI_NAME: [&str; 32] = [
            "zero", "ra",   "sp",   "gp",   "tp",   "t0",   "t1",   "t2",
            "s0",   "s1",   "a0",   "a1",   "a2",   "a3",   "a4",   "a5",
            "a6",   "a7",   "s2",   "s3",   "s4",   "s5",   "s6",   "s7",
            "s8",   "s9",   "s10",  "s11",  "t3",   "t4",   "t5",   "t6",
        ];
        X_ABI_NAME.get(reg.0 as usize).copied()
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

    fn set_args<A: Args>(&mut self, address: u64, out: &mut Insn, args: A) {
        args.set(self, address, out);
    }
}

// TODO: generate Args impls???

impl Args for &gen::args_b {
    fn set(&self, _: &RiscvDecoder, address: u64, insn: &mut Insn) {
        insn.push_reg(Reg(self.rs1 as u16));
        insn.push_reg(Reg(self.rs2 as u16));
        insn.push_addr(rel_addr(address, self.imm));
    }
}

impl Args for &gen::args_b2 {
    fn set(&self, _: &RiscvDecoder, address: u64, insn: &mut Insn) {
        insn.push_reg(Reg(self.rs1 as u16));
        insn.push_addr(rel_addr(address, self.imm));
    }
}

impl Args for &gen::args_i {
    fn set(&self, _: &RiscvDecoder, _: u64, insn: &mut Insn) {
        insn.push_reg(Reg(self.rd as u16));
        insn.push_reg(Reg(self.rs1 as u16));
        insn.push_imm(self.imm as i64);
    }
}

impl Args for &gen::args_i2 {
    fn set(&self, _: &RiscvDecoder, _: u64, insn: &mut Insn) {
        insn.push_reg(Reg(self.rd as u16));
        insn.push_imm(self.imm as i64);
    }
}

impl Args for &gen::args_j {
    fn set(&self, dec: &RiscvDecoder, address: u64, insn: &mut Insn) {
        if !dec.opts.alias || self.rd != 1 {
            insn.push_reg(Reg(self.rd as u16));
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
        if self.imm != 0 {
            insn.push_offset(Reg(self.rs1 as u16), self.imm as i64);
        } else {
            insn.push_reg(Reg(self.rs1 as u16));
        }
    }
}

impl Args for &gen::args_jalr {
    fn set(&self, dec: &RiscvDecoder, _: u64, insn: &mut Insn) {
        if !dec.opts.alias || self.rd != 1 {
            insn.push_reg(Reg(self.rd as u16));
        }
        if self.imm != 0 {
            insn.push_offset(Reg(self.rs1 as u16), self.imm as i64);
        } else {
            insn.push_reg(Reg(self.rs1 as u16));
        }
    }
}

impl Args for &gen::args_r {
    fn set(&self, _: &RiscvDecoder, _: u64, insn: &mut Insn) {
        insn.push_reg(Reg(self.rd as u16));
        insn.push_reg(Reg(self.rs1 as u16));
        insn.push_reg(Reg(self.rs2 as u16));
    }
}

impl Args for &gen::args_r2 {
    fn set(&self, _: &RiscvDecoder, _: u64, insn: &mut Insn) {
        insn.push_reg(Reg(self.rd as u16));
        insn.push_reg(Reg(self.rs1 as u16));
    }
}

impl Args for &gen::args_r2_s {
    fn set(&self, _: &RiscvDecoder, _: u64, insn: &mut Insn) {
        insn.push_reg(Reg(self.rs1 as u16));
        insn.push_reg(Reg(self.rs2 as u16));
    }
}

impl Args for &gen::args_r3 {
    fn set(&self, _: &RiscvDecoder, _: u64, insn: &mut Insn) {
        insn.push_reg(Reg(self.rd as u16));
        insn.push_reg(Reg(self.rs2 as u16));
    }
}

impl Args for &gen::args_l {
    fn set(&self, _: &RiscvDecoder, _: u64, insn: &mut Insn) {
        insn.push_reg(Reg(self.rd as u16));
        insn.push_offset(Reg(self.rs1 as u16), self.imm as i64);
    }
}

impl Args for &gen::args_s {
    fn set(&self, _: &RiscvDecoder, _: u64, insn: &mut Insn) {
        insn.push_reg(Reg(self.rs2 as u16));
        insn.push_offset(Reg(self.rs1 as u16), self.imm as i64);
    }
}

impl Args for &gen::args_u {
    fn set(&self, _: &RiscvDecoder, _: u64, insn: &mut Insn) {
        insn.push_reg(Reg(self.rd as u16));
        insn.push_uimm((self.imm as u64 >> 12) & 0xfffff);
    }
}

impl Args for &gen::args_shift {
    fn set(&self, _: &RiscvDecoder, _: u64, insn: &mut Insn) {
        insn.push_reg(Reg(self.rd as u16));
        insn.push_reg(Reg(self.rs1 as u16));
        insn.push_uimm(self.shamt as u64);
    }
}

impl Args for &gen::args_shift_c {
    fn set(&self, _: &RiscvDecoder, _: u64, insn: &mut Insn) {
        insn.push_reg(Reg(self.rd as u16));
        insn.push_uimm(self.shamt as u64);
    }
}

impl Args for &gen::args_atomic_ld {
    fn set(&self, _: &RiscvDecoder, _: u64, insn: &mut Insn) {
        insn.insert_flags(self.aq != 0, INSN_AQ);
        insn.insert_flags(self.rl != 0, INSN_RL);
        insn.push_reg(Reg(self.rd as u16));
        insn.push_addr_reg(Reg(self.rs1 as u16));
    }
}

impl Args for &gen::args_atomic_st {
    fn set(&self, _: &RiscvDecoder, _: u64, insn: &mut Insn) {
        insn.insert_flags(self.aq != 0, INSN_AQ);
        insn.insert_flags(self.rl != 0, INSN_RL);
        insn.push_reg(Reg(self.rd as u16));
        insn.push_reg(Reg(self.rs2 as u16));
        insn.push_addr_reg(Reg(self.rs1 as u16));
    }
}

impl Args for &gen::args_csr {
    fn set(&self, _: &RiscvDecoder, _: u64, insn: &mut Insn) {
        insn.push_reg(Reg(self.rd as u16));
        insn.push_uimm(self.csr as u64); // TODO: csr reg
        insn.push_reg(Reg(self.rs1 as u16));
    }
}

impl Args for &gen::args_csri {
    fn set(&self, _: &RiscvDecoder, _: u64, insn: &mut Insn) {
        insn.push_reg(Reg(self.rd as u16));
        insn.push_uimm(self.csr as u64); // TODO: csr reg
        insn.push_uimm(self.imm as u64);
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

impl Args for &gen::args_ci {
    fn set(&self, _: &RiscvDecoder, _: u64, insn: &mut Insn) {
        insn.push_reg(Reg(self.rd as u16));
        // TODO: insn.push_reg(Reg(self.rs1 as u16));
        insn.push_imm(self.imm as i64);
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
