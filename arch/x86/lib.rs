#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod consts;
mod generated;

#[cfg(feature = "print")]
mod printer;

use core::ops::{Deref, DerefMut};

use disasm_core::{
    bytes::Bytes,
    error::Error,
    insn::{Bundle, Insn},
    operand::{Access, Operand, OperandKind, Reg, RegClass},
    utils::zextract,
    ArchDecoder,
};

use self::{consts::operand::X86Operand, generated::*};

pub use self::consts::*;
pub use self::generated::opcode;
#[cfg(feature = "print")]
pub use self::printer::Printer;

const GPR_MASK: u64 = 15;

type Result<T = (), E = Error> = core::result::Result<T, E>;

const NONE: Reg = Reg::new(RegClass::INT, 0x1000);
const RIP: Reg = Reg::new(RegClass::INT, 0x1001);

const INSN_MAX_LEN: usize = 15;

// size of fixed legacy prefix and an opcode
const INSN_FIXED_SIZE: usize = 24;

// x86 prefixes
const PREFIX_OPERAND_SIZE: u8 = 0x66;
const PREFIX_ADDRESS_SIZE: u8 = 0x67;
const PREFIX_CS: u8 = 0x2e;
const PREFIX_ES: u8 = 0x26;
const PREFIX_SS: u8 = 0x36;
const PREFIX_DS: u8 = 0x3e;
const PREFIX_FS: u8 = 0x64;
const PREFIX_GS: u8 = 0x65;
const PREFIX_LOCK: u8 = 0xf0;
const PREFIX_REPNZ: u8 = 0xf2;
const PREFIX_REPZ: u8 = 0xf3;
const PREFIX_REX: u8 = 0x40;
const PREFIX_REX_MASK: u8 = 0xf0;

const MODE_REGISTER_DIRECT: u8 = 3;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Repeat {
    None,
    RepZ,
    RepNZ,
}

impl Default for Repeat {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum Size {
    None,

    // 8-bit
    Byte,
    // 16-bit
    Word,
    // 32-bit
    Long,
    // 64-bit
    Quad,
    // 128-bit
    Octo,

    // 64-bit
    Mm,
    // 128-bit
    Xmm,
    // 256-bit
    Ymm,
    // 512-bit
    Zmm,

    Tbyte,

    Far48,
    Far80,
}

impl Default for Size {
    fn default() -> Self {
        Self::Byte
    }
}

impl Size {
    fn bits(&self) -> usize {
        match self {
            Size::None => 0,
            Self::Byte => 8,
            Self::Word => 16,
            Self::Long => 32,
            Self::Quad => 64,
            Self::Octo => 128,
            Self::Mm => 64,
            Self::Xmm => 128,
            Self::Ymm => 256,
            Self::Zmm => 512,
            Self::Tbyte => 80,
            Self::Far48 => 48,
            Self::Far80 => 80,
        }
    }

    fn op_size(&self) -> u8 {
        match self {
            Self::None => operand::SIZE_NONE,
            Self::Byte => operand::SIZE_BYTE,
            Self::Word => operand::SIZE_WORD,
            Self::Long => operand::SIZE_DWORD,
            Self::Quad => operand::SIZE_QWORD,
            Self::Octo => operand::SIZE_OWORD,
            Self::Mm => operand::SIZE_QWORD,
            Self::Xmm => operand::SIZE_XMMWORD,
            Self::Ymm => operand::SIZE_YMMWORD,
            Self::Zmm => operand::SIZE_ZMMWORD,
            Self::Tbyte => operand::SIZE_TBYTE,
            Self::Far48 => operand::SIZE_FWORD_48,
            Self::Far80 => operand::SIZE_FWORD_80,
        }
    }

    fn op_size_vec(&self, access: MemAccess) -> u8 {
        match (self, access) {
            (Self::Byte, MemAccess::Tuple2) => operand::SIZE_WORD,
            (Self::Byte, MemAccess::Tuple4) => operand::SIZE_DWORD,
            (Self::Byte, MemAccess::Tuple8) => operand::SIZE_QWORD,
            (Self::Word, MemAccess::Tuple2) => operand::SIZE_DWORD,
            (Self::Word, MemAccess::Tuple4) => operand::SIZE_QWORD,
            (Self::Word, MemAccess::Tuple8) => operand::SIZE_XMMWORD,
            (Self::Long, MemAccess::Tuple2) => operand::SIZE_QWORD,
            (Self::Long, MemAccess::Tuple4) => operand::SIZE_XMMWORD,
            (Self::Long, MemAccess::Tuple8) => operand::SIZE_YMMWORD,
            (Self::Quad, MemAccess::Tuple2) => operand::SIZE_XMMWORD,
            (Self::Quad, MemAccess::Tuple4) => operand::SIZE_YMMWORD,
            _ => self.op_size(),
        }
    }

    fn suffix(&self) -> usize {
        match self {
            Self::Byte => 0,
            Self::Word => 1,
            Self::Long => 2,
            Self::Quad => 3,
            _ => unreachable!(),
        }
    }

    fn encode_gpr(&self, index: u8, rex: bool) -> u64 {
        let (size, index) = match self {
            Self::Byte => {
                if rex && (4..8).contains(&index) {
                    (0, index + 12)
                } else {
                    (0, index)
                }
            }
            Self::Word => (1, index),
            Self::Long => (2, index),
            Self::Quad => (3, index),
            Self::Far48 => (3, index),
            Self::Far80 => (3, index),
            _ => unreachable!("{:?}", self),
        };
        (size << 5) | (index as u64)
    }

    fn decode_gpr(reg: u64) -> (Size, usize) {
        match reg >> 5 {
            0 => (Size::Byte, (reg as usize) & 31),
            1 => (Size::Word, (reg as usize) & 15),
            2 => (Size::Long, (reg as usize) & 15),
            3 => (Size::Quad, (reg as usize) & 15),
            _ => unreachable!(),
        }
    }

    fn encode_vec(&self, index: u8) -> u64 {
        debug_assert!(index < 32);
        let class = match self {
            Self::Mm => 0,
            Self::Xmm => 1,
            Self::Ymm => 2,
            Self::Zmm => 3,
            _ => unreachable!(),
        };
        ((class as u64) << 5) | (index as u64)
    }

    fn decode_vec(reg: u64) -> (Size, usize) {
        let size = match reg >> 5 {
            0 => Self::Mm,
            1 => Self::Xmm,
            2 => Self::Ymm,
            3 => Self::Zmm,
            _ => unreachable!(),
        };
        (size, reg as usize & 31)
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum MemAccess {
    Full,
    Half,
    Quarter,
    Eighth,
    Tuple1,
    Tuple2,
    Tuple4,
    Tuple8,
    Fixed,
    Fixed1,
    Fixed2,
    Mem128,
}

impl Default for MemAccess {
    fn default() -> Self {
        Self::Full
    }
}

trait InsnExt {
    fn push_st(&mut self);
    fn push_sti(&mut self, value: u64);
}

impl InsnExt for Insn {
    fn push_st(&mut self) {
        self.push_arch_spec1(X86Operand::ST);
    }

    fn push_sti(&mut self, value: u64) {
        self.push_arch_spec2(X86Operand::STI, value);
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AddrSize {
    Auto,
    Addr32,
    Addr64,
}

impl Default for AddrSize {
    fn default() -> Self {
        Self::Auto
    }
}

// TODO: need ?macro? to define extensions and dependencies
#[derive(Copy, Clone, Debug, Default)]
pub struct Extensions {
    pub i386: bool,
    pub amd64: bool,
    pub x87: bool,
    pub cmov: bool,
    pub cmpxchg8b: bool,
    pub cmpxchg16b: bool,
    pub cpuid: bool,
    pub mmx: bool,
    pub sse: bool,
    pub sse2: bool,
    pub sse3: bool,
    pub ssse3: bool,
    pub sse4_1: bool,
    pub sse4_2: bool,
    pub avx: bool,
    pub avx2: bool,
    pub avx_vnni: bool,
    pub avx512vl: bool,
    pub avx512f: bool,
    pub avx512bw: bool,
    pub avx512dq: bool,
    pub avx512cd: bool,
    pub avx512fp16: bool,
    pub avx512bf16: bool,
    pub avx512_vbmi: bool,
    pub avx512_vbmi2: bool,
    pub avx512_vnni: bool,
    pub avx512_ifma: bool,
    pub avx512_bitalg: bool,
    pub avx512_vpopcntdq: bool,
    pub fma: bool,
    pub fma4: bool,
    pub aes: bool,
    pub vaes: bool,
    pub aeskle: bool,
    pub adx: bool,
    pub abm: bool,
    pub bmi: bool,
    pub bmi2: bool,
    pub mcommit: bool,
    pub monitorx: bool,
    pub movbe: bool,
    pub popcnt: bool,
    pub lzcnt: bool,
    pub rtm: bool,
    pub hle: bool,
    pub tsc: bool,
    pub rdtscp: bool,
    pub cet_ss: bool,
    pub cet_ibt: bool,
    pub mpx: bool,
    pub smap: bool,
    pub pclmulqdq: bool,
    pub vpclmulqdq: bool,
    pub fsgsbase: bool,
    pub rdpid: bool,
    pub rdrand: bool,
    pub rdseed: bool,
    pub uintr: bool,
    pub serialize: bool,
    pub sha: bool,
    pub waitpkg: bool,
    pub f16c: bool,
    pub wbnoinvd: bool,
    pub gfni: bool,
}

impl Extensions {
    pub fn all() -> Self {
        Self {
            x87: true,
            cmov: true,
            cmpxchg8b: true,
            cmpxchg16b: true,
            cpuid: true,
            mmx: true,
            sse: true,
            sse2: true,
            sse3: true,
            ssse3: true,
            sse4_1: true,
            sse4_2: true,
            avx: true,
            avx2: true,
            avx_vnni: true,
            avx512vl: true,
            avx512f: true,
            avx512bw: true,
            avx512dq: true,
            avx512cd: true,
            avx512fp16: true,
            avx512bf16: true,
            avx512_vbmi: true,
            avx512_vbmi2: true,
            avx512_vnni: true,
            avx512_ifma: true,
            avx512_bitalg: true,
            avx512_vpopcntdq: true,
            fma: true,
            fma4: true,
            aes: true,
            vaes: true,
            aeskle: true,
            i386: true,
            amd64: true,
            adx: true,
            abm: true,
            bmi: true,
            bmi2: true,
            mcommit: true,
            monitorx: true,
            movbe: true,
            popcnt: true,
            lzcnt: true,
            rtm: true,
            hle: true,
            tsc: true,
            rdtscp: true,
            cet_ss: true,
            cet_ibt: true,
            mpx: true,
            smap: true,
            pclmulqdq: true,
            vpclmulqdq: true,
            fsgsbase: true,
            rdpid: true,
            rdrand: true,
            rdseed: true,
            uintr: true,
            serialize: true,
            sha: true,
            waitpkg: true,
            f16c: true,
            wbnoinvd: true,
            gfni: true,
        }
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Options {
    pub ext: Extensions,
    pub att: bool,
    pub suffix_always: bool,
    pub addr_size: AddrSize,
}

#[derive(Default)]
struct State {
    // instruction format for decodetree
    raw: u64,

    no_ptr: bool,
    has_gpr: bool,
    need_suffix: bool,

    // prefix counters
    prefix_66: u8,
    prefix_67: u8,

    // repeat prefix
    repeat: Repeat,

    rex: bool,
    evex: bool,
    w: bool,

    // memory mode
    mode: u8,
    broadcast: bool,
    broadcast_force: bool,
    broadcast_size: u8,

    operand_size: Size,
    address_size: Size,
    // special case for evex vgather/vscatter
    vext: u8,
    vl: u8,
    vec_size: Size,
    mem_size_override: bool,
    mem_access: MemAccess,

    operand_mask: Option<Operand>,

    segment: u32,
    indirect: bool,
}

struct Inner<'a> {
    opts: &'a disasm_core::Options,
    opts_arch: &'a Options,
    bytes: Bytes<'a>,
    address: u64,
    state: State,
}

impl<'a> Deref for Inner<'a> {
    type Target = State;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl<'a> DerefMut for Inner<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.state
    }
}

impl<'a> Inner<'a> {
    #[inline(always)]
    fn is_att(&self) -> bool {
        self.opts_arch.att
    }

    #[inline(always)]
    fn is_amd64(&self) -> bool {
        self.opts_arch.ext.amd64
    }

    fn operand_size(&self, value: i32) -> usize {
        match value.abs() {
            1 => self.operand_size.bits(),
            2 => self.address_size.bits(),
            3 if self.w => 64,
            3 => 32,
            4 if self.is_amd64() && self.prefix_66 > 0 => 32,
            4 if self.is_amd64() => 64,
            4 if self.prefix_66 > 0 => 16,
            4 => 32,
            s => s as usize,
        }
    }

    #[inline(always)]
    fn operand_size_bwlq(&self) -> Size {
        if self.raw & 0x10000 == 0 {
            Size::Byte
        } else {
            self.operand_size
        }
    }

    #[inline(always)]
    fn operand_size_wlq(&self) -> Size {
        self.operand_size
    }

    #[inline(always)]
    fn operand_size_bwl(&self) -> Size {
        if self.raw & 0x10000 == 0 {
            Size::Byte
        } else if self.prefix_66 > 0 {
            Size::Word
        } else {
            Size::Long
        }
    }

    #[inline(always)]
    fn set_66(&mut self) {
        self.raw |= 0x1000;
    }

    #[inline(always)]
    fn set_f2(&mut self) {
        self.raw |= 0x2000;
    }

    #[inline(always)]
    fn set_f3(&mut self) {
        self.raw |= 0x4000;
    }

    #[inline(always)]
    fn set_mode(&mut self, modrm: u8) {
        self.mode = modrm >> 6;
    }

    #[inline(always)]
    fn set_legacy_opcode_modrm(&mut self, opcode: u8, modrm: u8) {
        self.raw |= (opcode as u64) << 16;
        self.raw |= (modrm as u64) << 24;
        self.set_mode(modrm);
    }

    #[inline(always)]
    fn set_operand_size(&mut self, size: Size) {
        self.operand_size = size;
    }

    #[inline(always)]
    fn set_w(&mut self) {
        self.w = true;
        self.set_operand_size(Size::Quad);
    }

    #[inline(always)]
    fn set_rex(&mut self, rex: u8) {
        self.rex = true;
        if rex & 8 != 0 {
            self.set_w();
            self.raw |= 1 << 15;
        }
        self.raw |= ((rex & 7) as u64) << 5;
    }

    #[inline(always)]
    fn set_vl(&mut self, vl: u8) {
        self.vl = vl;
        self.vec_size = match vl {
            0 => Size::Xmm,
            1 => Size::Ymm,
            _ => Size::Zmm,
        };
    }

    #[inline(always)]
    fn set_vex(&mut self, vex: [u8; 3]) -> Result<()> {
        self.raw = 0;
        for (i, b) in vex.into_iter().enumerate() {
            self.raw |= (b as u64) << (i * 8);
        }
        if self.raw & 0x8000 != 0 {
            self.set_w();
        }
        self.set_vl(zextract(self.raw, 10, 1) as u8);

        // vzeroupper and vzeroall do not use modrm
        if vex[2] != 0b01110111 {
            let modrm = self.bytes.read_u8()?;
            self.set_mode(modrm);
            self.raw |= (modrm as u64) << 24;
        }

        Ok(())
    }

    #[inline(always)]
    fn set_evex(&mut self, evex: [u8; 5]) {
        self.set_mode(evex[4]);
        self.evex = true;
        self.raw = 0;
        for (i, b) in evex.into_iter().enumerate() {
            self.raw |= (b as u64) << (i * 8);
        }
        if self.raw & 0x8000 != 0 {
            self.set_w();
        }
        self.vext = zextract(evex[2], 3, 1) ^ 1;
        self.set_vl(zextract(evex[2], 5, 2));

        self.broadcast = evex[2] & 0x10 != 0;

        let mask = (zextract(evex[2], 7, 1) << 3) | zextract(evex[2], 0, 3);
        if mask & 7 != 0 {
            let mask = Reg::new(reg_class::K_MASK, mask.into()).read();
            self.operand_mask = Some(Operand::reg(mask));
        }
    }

    fn imm_size(&self, value: i32) -> usize {
        match value {
            0 => unreachable!("size must not be zero"),
            1 => 8 << self.operand_size.suffix(),
            2 if self.w => 32,
            2 => 8 << self.operand_size.suffix(),
            _ => value as usize,
        }
    }

    fn read_uimm(&mut self, value: i32) -> Result<(usize, u64), Error> {
        let size = self.imm_size(value);
        let imm = match size {
            8 => self.bytes.read_u8()? as u64,
            16 => self.bytes.read_u16()? as u64,
            32 => self.bytes.read_u32()? as u64,
            64 => self.bytes.read_u64()?,
            _ => unreachable!("invalid size {size}"),
        };
        Ok((size, imm))
    }

    fn set_simm_impl(&mut self, out: &mut Insn, value: i32, to: usize) -> Result {
        let (size, imm) = self.read_uimm(value)?;
        out.push_uimm(sign_extend(imm, size, to));
        self.need_suffix = true;
        Ok(())
    }

    fn evex_disp8(&self, out: &Insn, mut offset: i32) -> i32 {
        if !self.evex {
            return offset;
        }

        if self.broadcast && self.broadcast_size != 0 {
            match self.broadcast_size {
                4 => offset *= 2,
                5 => offset *= 4,
                6 => offset *= 8,
                _ => unreachable!(),
            }
            return offset;
        }

        match self.mem_access {
            MemAccess::Full => match self.vec_size {
                Size::Xmm if out.opcode() == opcode::VMOVDDUP => offset *= 8,
                Size::Xmm => offset *= 16,
                Size::Ymm => offset *= 32,
                Size::Zmm => offset *= 64,
                _ => unreachable!(),
            },
            MemAccess::Half => match self.vec_size {
                Size::Xmm => offset *= 8,
                Size::Ymm => offset *= 16,
                Size::Zmm => offset *= 32,
                _ => unreachable!(),
            },
            MemAccess::Quarter => match self.vec_size {
                Size::Xmm => offset *= 4,
                Size::Ymm => offset *= 8,
                Size::Zmm => offset *= 16,
                _ => unreachable!(),
            },
            MemAccess::Eighth => match self.vec_size {
                Size::Xmm => offset *= 2,
                Size::Ymm => offset *= 4,
                Size::Zmm => offset *= 8,
                _ => unreachable!(),
            },
            MemAccess::Mem128 => offset *= 16,
            MemAccess::Fixed => {}
            MemAccess::Fixed1 => match self.operand_size {
                Size::Long => offset *= 4,
                Size::Quad => offset *= 8,
                _ => unreachable!(),
            },
            MemAccess::Fixed2 => offset *= 2,
            MemAccess::Tuple1 => match self.operand_size {
                Size::Byte => {}
                Size::Word => offset *= 2,
                _ if self.w => offset *= 8,
                _ => offset *= 4,
            },
            MemAccess::Tuple2 => match self.operand_size {
                Size::Long if !self.w => offset *= 8,
                Size::Quad if self.w => offset *= 16,
                Size::Xmm => offset *= 16,
                _ => unreachable!("{:?}", self.operand_size),
            },
            MemAccess::Tuple4 => match self.operand_size {
                Size::Long if !self.w => offset *= 16,
                Size::Quad if self.w => offset *= 32,
                Size::Xmm => offset *= 16,
                Size::Ymm => offset *= 32,
                _ => unreachable!("{:?}", self.operand_size),
            },
            MemAccess::Tuple8 => match self.operand_size {
                Size::Long if !self.w => offset *= 32,
                Size::Ymm => offset *= 32,
                _ => unreachable!("{:?}", self.operand_size),
            },
        }
        offset
    }

    fn decode_mem(
        &mut self,
        out: &mut Insn,
        base: u8,
        size: u8,
        index_size: Size,
    ) -> Result<Operand, Error> {
        let rm = base & 7;
        let kind = if self.mode == 0 && rm == 5 {
            if self.is_amd64() {
                OperandKind::Relative(RIP, self.bytes.read_i32()? as i64)
            } else {
                OperandKind::Absolute(self.bytes.read_u32()? as u64)
            }
        } else {
            let sib = (rm == 4).then(|| self.bytes.read_u8()).transpose()?;
            let mut offset = match self.mode {
                1 if self.evex => {
                    let offset = self.bytes.read_i8()? as i32;
                    Some(self.evex_disp8(out, offset))
                }
                1 => Some(self.bytes.read_i8()? as i32),
                2 => Some(self.bytes.read_i32()?),
                _ => None,
            };
            if let Some(sib) = sib {
                let index = ((base >> 1) & 8) | zextract(sib, 3, 3);
                let index = match index_size {
                    Size::Long | Size::Quad => {
                        Reg::new(RegClass::INT, index_size.encode_gpr(index, self.rex))
                    }
                    Size::Xmm | Size::Ymm | Size::Zmm => {
                        let index = (self.vext << 4) | index;
                        Reg::new(RegClass::VECTOR, index_size.encode_vec(index))
                    }
                    _ => todo!(),
                };
                let base = (base & 8) | zextract(sib, 0, 3);
                let mut base =
                    Reg::new(RegClass::INT, self.address_size.encode_gpr(base, self.rex));
                if self.mode == 0 && (base.index() & GPR_MASK) == 5 {
                    offset = Some(self.bytes.read_i32()?);
                    base = NONE;
                }
                let is_gpr = matches!(index_size, Size::Long | Size::Quad);
                if is_gpr && (index.index() & GPR_MASK) == 4 {
                    if let Some(offset) = offset {
                        if base == NONE {
                            OperandKind::Absolute(offset as u64)
                        } else {
                            OperandKind::Relative(base, offset as i64)
                        }
                    } else {
                        OperandKind::Indirect(base)
                    }
                } else {
                    let scale = 1 << zextract(sib, 6, 2);
                    if let Some(offset) = offset {
                        OperandKind::ScaledIndexRelative(base, index, scale, offset)
                    } else {
                        OperandKind::ScaledIndex(base, index, scale)
                    }
                }
            } else {
                let base = Reg::new(
                    RegClass::INT,
                    self.address_size.encode_gpr(base & 15, self.rex),
                );
                if let Some(offset) = offset {
                    OperandKind::Relative(base, offset as i64)
                } else {
                    OperandKind::Indirect(base)
                }
            }
        };
        let mut op = Operand::new(kind);
        let flags = op.flags_mut();
        if self.segment != insn::SEGMENT_NONE && self.segment != insn::SEGMENT_CS {
            flags.field_set(operand::FIELD_SEGMENT, self.segment);
            self.segment = 0;
        }
        flags
            .set_if(operand::NO_PTR, self.no_ptr)
            .field_set(operand::FIELD_MEM, size as u32);
        self.need_suffix = true;
        Ok(op)
    }

    fn decode(&mut self, out: &mut Bundle) -> Result<usize> {
        self.address_size = if self.is_amd64() {
            Size::Quad
        } else {
            Size::Long
        };
        self.operand_size = Size::Long;

        out.clear();
        let insn = out.peek();

        let result = loop {
            if self.bytes.offset() >= INSN_MAX_LEN {
                return Err(Error::Failed(INSN_MAX_LEN * 8));
            }

            match self.bytes.read_u8()? {
                PREFIX_OPERAND_SIZE => {
                    self.operand_size = Size::Word;
                    self.prefix_66 += 1;
                    self.set_66();
                }
                PREFIX_ADDRESS_SIZE => {
                    self.address_size = if self.is_amd64() {
                        Size::Long
                    } else {
                        Size::Word
                    };
                    self.prefix_67 += 1;
                }
                PREFIX_LOCK => {
                    insn.flags_mut().set(insn::LOCK);
                }
                PREFIX_REPZ => {
                    self.repeat = Repeat::RepZ;
                    self.set_f3();
                }
                PREFIX_REPNZ => {
                    self.repeat = Repeat::RepNZ;
                    self.set_f2();
                }
                PREFIX_CS => self.segment = insn::SEGMENT_CS,
                PREFIX_ES => self.segment = insn::SEGMENT_ES,
                PREFIX_SS => self.segment = insn::SEGMENT_SS,
                PREFIX_DS => self.segment = insn::SEGMENT_DS,
                PREFIX_FS => self.segment = insn::SEGMENT_FS,
                PREFIX_GS => self.segment = insn::SEGMENT_GS,
                0x62 if self.is_amd64() => {
                    let evex = self.bytes.read_array::<5>()?;
                    self.set_evex(evex);
                    break X86DecodeEvex::decode(self, self.raw, insn);
                }
                0xc5 => {
                    let vex = self.bytes.read_array::<2>()?;
                    self.set_vex([(vex[0] & 0x80) | 0x61, vex[0] & 0x7f, vex[1]])?;
                    break X86DecodeVex::decode(self, self.raw as u32, insn);
                }
                0xc4 => {
                    let vex = self.bytes.read_array::<3>()?;
                    self.set_vex(vex)?;
                    break X86DecodeVex::decode(self, self.raw as u32, insn);
                }
                mut opcode => {
                    if opcode & PREFIX_REX_MASK == PREFIX_REX && self.is_amd64() {
                        self.set_rex(opcode);
                        opcode = self.bytes.read_u8()?;
                    }

                    break if opcode == 0x0f {
                        match self.bytes.read_u8()? {
                            0x38 => {
                                let opcode = self.bytes.read_u8()?;
                                let modrm = self.bytes.read_u8()?;
                                self.set_legacy_opcode_modrm(opcode, modrm);
                                X86Decode0f38::decode(self, self.raw as u32, insn)
                            }
                            0x3a => {
                                let opcode = self.bytes.read_u8()?;
                                let modrm = self.bytes.read_u8()?;
                                self.set_legacy_opcode_modrm(opcode, modrm);
                                X86Decode0f3a::decode(self, self.raw as u32, insn)
                            }
                            opcode => {
                                let (size, modrm) = match self.bytes.peek_u8() {
                                    Some(modrm) => (8, modrm),
                                    None => (0, MODE_REGISTER_DIRECT),
                                };
                                self.set_legacy_opcode_modrm(opcode, modrm);
                                X86Decode0f::decode(
                                    self,
                                    self.raw as u32,
                                    INSN_FIXED_SIZE + size,
                                    insn,
                                )
                            }
                        }
                    } else {
                        let (size, modrm) = match self.bytes.peek_u8() {
                            Some(modrm) => (8, modrm),
                            None => (0, MODE_REGISTER_DIRECT),
                        };
                        self.set_legacy_opcode_modrm(opcode, modrm);
                        X86Decode::decode(self, self.raw as u32, INSN_FIXED_SIZE + size, insn)
                    };
                }
            }
        };

        if self.bytes.offset() >= INSN_MAX_LEN {
            return Err(Error::Failed(INSN_MAX_LEN * 8));
        } else if let Err(err) = result {
            return Err(match err {
                Error::Failed(_) => Error::Failed((self.bytes.offset() + 1) * 8),
                Error::More(bits) => Error::More(self.bytes.offset() * 8 + bits),
            });
        }

        // TODO: HLE
        insn.flags_mut()
            .set_if(insn::DATA16, self.prefix_66 > 1)
            .set_if(
                insn::ADDR32,
                self.prefix_67 > 0 && self.mode == MODE_REGISTER_DIRECT,
            )
            .field_set_if(insn::FIELD_SEGMENT, self.segment, self.segment != 0);

        out.next();

        Ok(self.bytes.offset() * 8)
    }

    fn gpr_size(&mut self, value: i32) -> Size {
        match value {
            -1 => Size::Tbyte,

            0 => Size::None,

            1 if self.w => Size::Quad,
            1 if self.prefix_66 > 0 => Size::Word,
            1 => Size::Long,

            2 => self.address_size,

            3 if self.w => Size::Quad,
            3 => Size::Long,

            4 if self.is_amd64() => Size::Quad,
            4 if self.prefix_66 > 0 => Size::Word,
            4 => Size::Long,

            5 if self.is_amd64() => Size::Quad,
            5 => Size::Long,

            6 if self.is_amd64() => {
                if self.prefix_67 > 0 {
                    self.prefix_67 -= 1;
                    Size::Long
                } else {
                    Size::Quad
                }
            }
            6 => {
                if self.prefix_67 > 0 {
                    self.prefix_67 -= 1;
                    Size::Word
                } else {
                    Size::Long
                }
            }

            8 => Size::Byte,
            16 => Size::Word,
            32 => Size::Long,
            64 => Size::Quad,
            128 => Size::Octo,

            512 => Size::Byte, // TODO: 512-bit size mem access

            48 => Size::Far48,
            80 => Size::Far80,

            _ => unreachable!("unexpected operand size override {value}"),
        }
    }

    fn set_fp_suffix(&mut self, out: &mut Insn, value: i32) -> Result {
        // TODO: remove early exit
        if !self.is_att() {
            return Ok(());
        }
        let suffix = match value {
            2 => insn::SUFFIX_FP_T,
            32 => insn::SUFFIX_FP_S,
            64 => insn::SUFFIX_FP_L,
            80 => insn::SUFFIX_FP_LL,
            _ => unreachable!("unexpected fp suffix value={value}"),
        };
        out.flags_mut()
            .field_set(insn::FIELD_SUFFIX, suffix)
            .set(insn::SUFFIX);
        Ok(())
    }

    fn set_imm(&mut self, out: &mut Insn, size: Size) -> Result {
        match size {
            Size::Quad => self.set_simm(out, 32),
            Size::Long => self.set_uimm(out, 32),
            Size::Word => self.set_uimm(out, 16),
            Size::Byte => self.set_uimm(out, 8),
            _ => unreachable!(),
        }
    }

    fn set_gpr_reg(&mut self, out: &mut Insn, index: i32, access: Access, rsz: i32) -> Result {
        let size = self.gpr_size(rsz);
        let reg = Reg::new(RegClass::INT, size.encode_gpr(index as u8, self.rex)).access(access);
        out.push_reg(reg);
        self.has_gpr = true;
        Ok(())
    }

    fn set_gpr_vvv(&mut self, out: &mut Insn, index: i32, access: Access, vsz: i32) -> Result {
        let size = self.gpr_size(vsz);
        let reg = Reg::new(RegClass::INT, size.encode_gpr(index as u8, self.rex)).access(access);
        out.push_reg(reg);
        self.has_gpr = true;
        Ok(())
    }

    fn set_gpr_mem(
        &mut self,
        out: &mut Insn,
        index: i32,
        bsz: i32,
        access: Access,
        msz: i32,
    ) -> Result {
        self.set_mem_size(msz);
        let index = index as u8;
        if self.mode != MODE_REGISTER_DIRECT {
            let mut op =
                self.decode_mem(out, index, self.operand_size.op_size(), self.address_size)?;
            op.flags_mut().set_if(operand::INDIRECT, self.indirect);
            out.push_operand(op);
        } else {
            let size = if bsz != 0 {
                self.gpr_size(bsz)
            } else {
                self.operand_size
            };
            let reg = Reg::new(RegClass::INT, size.encode_gpr(index & 15, self.rex));
            self.has_gpr = true;
            out.push_reg(reg.access(access));
        };
        Ok(())
    }

    fn set_moffset(&mut self, out: &mut Insn, msz: i32, _access: Access) -> Result {
        self.set_mem_size(msz);
        let offset = match self.address_size {
            Size::Word => self.bytes.read_u16()? as u64,
            Size::Long => self.bytes.read_u32()? as u64,
            Size::Quad => self.bytes.read_u64()?,
            _ => unreachable!("unexpected address size {:?}", self.address_size),
        };
        let mut op = Operand::arch2(X86Operand::MemOffset, offset);
        let flags = op.flags_mut();
        if self.segment != insn::SEGMENT_NONE {
            flags.field_set(operand::FIELD_SEGMENT, self.segment);
            self.segment = 0;
        }
        flags.field_set(operand::FIELD_MEM, self.operand_size.op_size() as u32);
        out.push_operand(op);
        self.need_suffix = true;
        Ok(())
    }

    fn push_operand_with_mask(&mut self, out: &mut Insn, operand: Operand) {
        if self.is_att() {
            if let Some(mask) = self.operand_mask.take() {
                out.push_operand(mask);
            }
            out.push_operand(operand);
        } else {
            out.push_operand(operand);
            if let Some(mask) = self.operand_mask.take() {
                out.push_operand(mask);
            }
        }
    }

    fn set_vec_reg(&mut self, out: &mut Insn, value: i32, size: Size, access: Access) -> Result {
        let reg = Reg::new(RegClass::VECTOR, size.encode_vec(value as u8));
        let operand = Operand::reg(reg.access(access));
        self.push_operand_with_mask(out, operand);
        Ok(())
    }

    fn set_vec_mem_impl(
        &mut self,
        out: &mut Insn,
        value: i32,
        size: Size,
        access: Access,
        mem_size: i32,
        index_size: Size,
    ) -> Result<Operand> {
        let mut index = value as u8;
        if self.mode != MODE_REGISTER_DIRECT {
            match mem_size {
                0 => {}
                1 => self.operand_size = size,
                _ => {
                    self.operand_size = self.gpr_size(mem_size);
                    self.mem_size_override = true;
                }
            }
            let mem_size = if self.broadcast && self.broadcast_size != 0 {
                match self.broadcast_size {
                    4 => operand::SIZE_WORD,
                    5 => operand::SIZE_DWORD,
                    6 => operand::SIZE_QWORD,
                    _ => unreachable!(),
                }
            } else if self.mem_size_override {
                self.operand_size.op_size_vec(self.mem_access)
            } else {
                size.op_size_vec(self.mem_access)
            };
            let mut op = self.decode_mem(out, index, mem_size, index_size)?;
            if self.broadcast && self.broadcast_size != 0 {
                let bcst = match size.bits() >> self.broadcast_size as usize {
                    2 => operand::BROADCAST_1TO2,
                    4 => operand::BROADCAST_1TO4,
                    8 => operand::BROADCAST_1TO8,
                    16 => operand::BROADCAST_1TO16,
                    32 => operand::BROADCAST_1TO32,
                    _ => unreachable!(),
                };
                op.flags_mut()
                    .field_set(operand::FIELD_BCST, bcst as u32)
                    .set_if(operand::BCST_FORCE, self.broadcast_force);
            }
            op.flags_mut().set_if(operand::INDIRECT, self.indirect);
            Ok(op)
        } else {
            if !self.evex {
                // NOTE: index[5] is X (raw[0][6]), but it is used only in EVEX
                index &= 15;
            }
            let reg = Reg::new(RegClass::VECTOR, size.encode_vec(index));
            Ok(Operand::reg(reg.access(access)))
        }
    }

    fn set_vec_mem(
        &mut self,
        out: &mut Insn,
        value: i32,
        size: Size,
        access: Access,
        mem_size: i32,
    ) -> Result {
        let operand =
            self.set_vec_mem_impl(out, value, size, access, mem_size, self.address_size)?;
        self.push_operand_with_mask(out, operand);
        Ok(())
    }

    fn set_vec_vmem(
        &mut self,
        out: &mut Insn,
        value: i32,
        access: Access,
        mem_size: i32,
        index_size: Size,
    ) -> Result {
        let operand =
            self.set_vec_mem_impl(out, value, self.vec_size, access, mem_size, index_size)?;
        self.push_operand_with_mask(out, operand);
        Ok(())
    }

    fn get_sae(&self) -> Option<Operand> {
        if self.broadcast && self.mode == MODE_REGISTER_DIRECT {
            Some(Operand::arch2(X86Operand::Sae, self.vl))
        } else {
            None
        }
    }

    fn get_er_sae(&self) -> Option<Operand> {
        if self.broadcast && self.mode == MODE_REGISTER_DIRECT {
            Some(Operand::arch2(X86Operand::SaeEr, self.vl as u64))
        } else {
            None
        }
    }

    fn get_sae_zmm(&mut self) -> Option<Operand> {
        self.get_sae().map(|i| {
            self.vec_size = Size::Zmm;
            i
        })
    }

    fn get_er_sae_zmm(&mut self) -> Option<Operand> {
        self.get_er_sae().map(|i| {
            self.vec_size = Size::Zmm;
            i
        })
    }

    fn set_bcst(&mut self, bcst: i32) {
        if bcst != 0 {
            self.broadcast_force = bcst < 0;
            match bcst.abs() {
                1 if self.w => self.broadcast_size = 6,
                1 => self.broadcast_size = 5,
                16 => self.broadcast_size = 4,
                32 => self.broadcast_size = 5,
                64 => self.broadcast_size = 6,
                _ => unreachable!("unexpected broadcast size {bcst}"),
            }
        }
    }

    fn set_evex_rm_rv(&mut self, out: &mut Insn, args: &args_evex_rm_rv, size: Size) -> Result {
        self.set_gpr_reg(out, args.r, Access::Write, args.rsz)?;
        self.set_vec_mem(out, args.b, size, Access::Read, args.msz)?;
        Ok(())
    }

    fn set_gather_vvv(
        &mut self,
        out: &mut Insn,
        args: &args_gather,
        bsz: Size,
        vsz: Size,
    ) -> Result {
        let index_size = match args.isz {
            1 => self.vec_size,
            128 => Size::Xmm,
            256 => Size::Ymm,
            512 => Size::Zmm,
            _ => todo!(),
        };
        self.set_vec_reg(out, args.r, bsz, Access::ReadWrite)?;
        self.set_vec_vmem(out, args.b, Access::Read, args.msz, index_size)?;
        self.set_vec_reg(out, args.v, vsz, Access::ReadWrite)?;
        Ok(())
    }

    fn set_evex_gather(
        &mut self,
        out: &mut Insn,
        args: &args_evex_gather,
        bsz: Size,
        isz: Size,
    ) -> Result {
        self.mem_access = MemAccess::Tuple1;
        self.set_vec_reg(out, args.r, bsz, Access::Write)?;
        self.set_vec_vmem(out, args.b, Access::Read, args.msz, isz)?;
        Ok(())
    }

    fn set_evex_scatter(
        &mut self,
        out: &mut Insn,
        args: &args_evex_scatter,
        bsz: Size,
        isz: Size,
    ) -> Result {
        self.mem_access = MemAccess::Tuple1;
        self.set_vec_vmem(out, args.b, Access::Write, args.msz, isz)?;
        self.set_vec_reg(out, args.r, bsz, Access::Read)?;
        Ok(())
    }

    fn set_evex_rvm_vvr(&mut self, out: &mut Insn, args: &args_evex_rvm_vvr, size: Size) -> Result {
        self.set_vec_reg(out, args.r, size, Access::Write)?;
        self.set_vec_reg(out, args.v, size, Access::Read)?;
        self.set_gpr_mem(out, args.b, 0, Access::Read, args.msz)?;
        Ok(())
    }

    fn set_vec_is4(&mut self, out: &mut Insn, value: i32, size: Size, access: Access) -> Result {
        if value != 0 {
            let value = self.read_uimm(8)?.1 >> 4;
            self.set_vec_reg(out, value as i32, size, access)?;
        }
        Ok(())
    }

    fn set_k_vvv(&mut self, out: &mut Insn, value: i32, access: Access) -> Result {
        let reg = Reg::new(reg_class::K, value as u64);
        out.push_reg(reg.access(access));
        Ok(())
    }

    fn set_k_reg(&mut self, out: &mut Insn, value: i32, access: Access) -> Result {
        let reg = Reg::new(reg_class::K, value as u64);
        let operand = Operand::reg(reg.access(access));
        self.push_operand_with_mask(out, operand);
        Ok(())
    }

    fn set_k_mem(&mut self, out: &mut Insn, value: i32, access: Access, msz: i32) -> Result {
        self.set_mem_size(msz);
        let index = value as u8;
        if self.mode != MODE_REGISTER_DIRECT {
            let mut op = self.decode_mem(out, index, operand::SIZE_DWORD, self.address_size)?;
            op.flags_mut()
                .field_set(operand::FIELD_MEM, self.operand_size.op_size() as u32);
            out.push_operand(op);
        } else {
            let op = Operand::reg(Reg::new(reg_class::K, value as u64).access(access));
            out.push_operand(op);
        }
        Ok(())
    }

    fn set_bnd_reg(&mut self, out: &mut Insn, value: i32, access: Access) -> Result {
        out.push_reg(Reg::new(reg_class::BND, value as u64).access(access));
        Ok(())
    }

    fn set_mem_size(&mut self, msz: i32) {
        self.operand_size = self.gpr_size(msz);
        if msz != 1 {
            self.mem_size_override = true;
        }
    }

    fn vec_half(&self) -> (Size, i32) {
        match self.vec_size {
            Size::Xmm => (Size::Xmm, 64),
            Size::Ymm => (Size::Xmm, 1),
            Size::Zmm => (Size::Ymm, 1),
            _ => unreachable!(),
        }
    }

    fn vec_quarter(&self) -> (Size, i32) {
        match self.vec_size {
            Size::Xmm => (Size::Xmm, 32),
            Size::Ymm => (Size::Xmm, 64),
            Size::Zmm => (Size::Xmm, 1),
            _ => unreachable!(),
        }
    }

    fn vec_eighth(&self) -> (Size, i32) {
        match self.vec_size {
            Size::Xmm => (Size::Xmm, 16),
            Size::Ymm => (Size::Xmm, 32),
            Size::Zmm => (Size::Xmm, 64),
            _ => unreachable!(),
        }
    }

    fn vec_reg_half(&mut self) -> Size {
        if matches!(self.vec_size, Size::Xmm | Size::Ymm) {
            self.broadcast_force = true;
        }
        self.vec_half().0
    }

    fn vec_mem_half(&mut self) -> (Size, i32) {
        self.mem_access = MemAccess::Half;
        self.vec_half()
    }

    fn vec_mem_quarter(&mut self) -> (Size, i32) {
        self.mem_access = MemAccess::Quarter;
        self.vec_quarter()
    }

    fn vec_mem_eighth(&mut self) -> (Size, i32) {
        self.mem_access = MemAccess::Eighth;
        self.vec_eighth()
    }

    fn set_rel_impl(&mut self, out: &mut Insn, disp: i64) -> Result {
        let address = self.address.wrapping_add(self.bytes.offset() as u64);
        out.push_pc_rel(address, disp);
        Ok(())
    }

    fn impl_args_b(&mut self, out: &mut Insn, args: &args_b, access: Access) -> Result {
        self.mode = 3; // FIXME: addr32 xchg
        self.set_gpr_reg(out, args.r, access, args.rsz)
    }

    fn impl_args_m(&mut self, out: &mut Insn, args: &args_m, access: Access, msz: i32) -> Result {
        self.set_gpr_mem(out, args.b, 0, access, msz)
    }

    fn impl_args_fldst_env(&mut self, out: &mut Insn, args: &args_m, access: Access) -> Result {
        self.no_ptr = true;
        self.set_gpr_mem(out, args.b, 0, access, 8)
    }

    fn impl_args_fbldst(&mut self, out: &mut Insn, args: &args_m, access: Access) -> Result {
        self.set_gpr_mem(out, args.b, 0, access, -1)
    }

    fn impl_args_fldstt(&mut self, out: &mut Insn, args: &args_m, access: Access) -> Result {
        self.set_gpr_mem(out, args.b, 0, access, -1)?;
        self.set_fp_suffix(out, 2)
    }

    fn impl_args_m_bwlq(&mut self, out: &mut Insn, args: &args_m, access: Access) -> Result {
        let sz = self.operand_size_bwlq().bits() as i32;
        self.set_gpr_mem(out, args.b, 0, access, sz)?;
        self.set_suffix(out, sz)
    }

    fn impl_args_m_cl(&mut self, out: &mut Insn, args: &args_m, access: Access) -> Result {
        let sz = self.operand_size_bwlq().bits() as i32;
        self.set_gpr_mem(out, args.b, 0, access, sz)?;
        self.set_gpr_reg(out, 1, Access::Read, 8)?;
        self.has_gpr = false; // ignore cl
        self.set_suffix(out, sz)
    }

    fn impl_args_rm_rr(&mut self, out: &mut Insn, args: &args_rm_rr, access: Access) -> Result {
        self.set_gpr_reg(out, args.r, access, args.rsz)?;
        self.set_gpr_mem(out, args.b, 0, Access::Read, args.msz)
    }

    fn impl_args_mr_rr(&mut self, out: &mut Insn, args: &args_mr_rr, access: Access) -> Result {
        self.set_gpr_mem(out, args.b, 0, access, args.msz)?;
        self.set_gpr_reg(out, args.r, Access::Read, args.rsz)
    }

    fn impl_args_rm(&mut self, out: &mut Insn, args: &args_rm, access: Access, sz: i32) -> Result {
        self.set_gpr_reg(out, args.r, access, sz)?;
        self.set_gpr_mem(out, args.b, 0, Access::Read, sz)?;
        self.set_suffix(out, sz)
    }

    fn impl_args_rm_wlq(&mut self, out: &mut Insn, args: &args_rm, access: Access) -> Result {
        let sz = self.operand_size_wlq().bits() as i32;
        self.impl_args_rm(out, args, access, sz)
    }

    fn impl_args_rm_bwlq(&mut self, out: &mut Insn, args: &args_rm, access: Access) -> Result {
        let sz = self.operand_size_bwlq().bits() as i32;
        self.impl_args_rm(out, args, access, sz)
    }

    fn impl_args_mr_base(
        &mut self,
        out: &mut Insn,
        args: &args_mr,
        mem_access: Access,
        reg_access: Access,
        sz: i32,
    ) -> Result {
        self.set_gpr_mem(out, args.b, 0, mem_access, sz)?;
        self.set_gpr_reg(out, args.r, reg_access, sz)?;
        self.set_suffix(out, sz)
    }

    fn impl_args_mr_bwlq(&mut self, out: &mut Insn, args: &args_mr, access: Access) -> Result {
        let sz = self.operand_size_bwlq().bits() as i32;
        self.impl_args_mr_base(out, args, access, Access::Read, sz)
    }

    fn impl_args_mr_cl(&mut self, out: &mut Insn, args: &args_mr, access: Access) -> Result {
        let sz = self.operand_size_wlq().bits() as i32;
        self.set_gpr_mem(out, args.b, 0, access, sz)?;
        self.set_gpr_reg(out, args.r, Access::Read, sz)?;
        self.set_gpr_reg(out, 1, Access::Read, 8)?;
        self.set_suffix(out, sz)
    }

    fn impl_args_mr_u8(&mut self, out: &mut Insn, args: &args_mr, access: Access) -> Result {
        let sz = self.operand_size_wlq().bits() as i32;
        self.set_gpr_mem(out, args.b, 0, access, sz)?;
        self.set_gpr_reg(out, args.r, Access::Read, sz)?;
        self.set_uimm(out, 8)?;
        self.set_suffix(out, sz)
    }

    fn impl_args_ri_bwlq(&mut self, out: &mut Insn, args: &args_r, access: Access) -> Result {
        let size = self.operand_size_bwlq();
        let sz = size.bits() as i32;
        self.set_gpr_reg(out, args.r, access, sz)?;
        self.set_imm(out, size)?;
        self.set_suffix(out, sz)
    }

    fn impl_args_mi_bwlq(&mut self, out: &mut Insn, args: &args_m, access: Access) -> Result {
        let size = self.operand_size_bwlq();
        let sz = size.bits() as i32;
        self.set_gpr_mem(out, args.b, 0, access, sz)?;
        self.set_imm(out, size)?;
        self.set_suffix(out, sz)
    }

    fn impl_args_mi_u8(&mut self, out: &mut Insn, args: &args_m, access: Access) -> Result {
        let size = self.operand_size_bwlq();
        let sz = size.bits() as i32;
        self.set_gpr_mem(out, args.b, 0, access, sz)?;
        self.set_uimm(out, 8)?;
        self.set_suffix(out, sz)
    }

    fn impl_args_mi_s8(&mut self, out: &mut Insn, args: &args_m, access: Access) -> Result {
        let size = self.operand_size_bwlq();
        let sz = size.bits() as i32;
        self.set_gpr_mem(out, args.b, 0, access, sz)?;
        self.set_simm(out, 8)?;
        self.set_suffix(out, sz)
    }

    fn impl_args_mi_one(&mut self, out: &mut Insn, args: &args_m, access: Access) -> Result {
        let size = self.operand_size_bwlq();
        let sz = size.bits() as i32;
        self.set_gpr_mem(out, args.b, 0, access, sz)?;
        out.push_imm(1);
        self.set_suffix(out, sz)
    }

    fn impl_args_fld(&mut self, out: &mut Insn, args: &args_m, msz: i32, sz: i32) -> Result {
        self.set_gpr_mem(out, args.b, 0, Access::Read, msz)?;
        self.set_fp_suffix(out, sz)
    }

    fn impl_args_fst(&mut self, out: &mut Insn, args: &args_m, msz: i32, sz: i32) -> Result {
        self.set_gpr_mem(out, args.b, 0, Access::Write, msz)?;
        self.set_fp_suffix(out, sz)
    }

    fn impl_args_rm_vr(
        &mut self,
        out: &mut Insn,
        args: &args_rm_vr,
        access: Access,
        msz: i32,
    ) -> Result {
        self.set_vec_reg(out, args.r, self.vec_size, access)?;
        self.set_gpr_mem(out, args.b, 0, Access::Read, msz)
    }

    fn impl_args_mr_rx(&mut self, out: &mut Insn, args: &args_mr_rx, msz: i32) -> Result {
        self.set_gpr_mem(out, args.b, 0, Access::Write, msz)?;
        self.set_vec_reg(out, args.r, Size::Xmm, Access::Read)
    }

    fn impl_args_mr_rx_mem(
        &mut self,
        out: &mut Insn,
        args: &args_mr_rx,
        msz: i32,
        mem: MemAccess,
    ) -> Result {
        self.mem_access = mem;
        self.impl_args_mr_rx(out, args, msz)
    }

    fn impl_args_rm_vv(
        &mut self,
        out: &mut Insn,
        args: &args_rm_vv,
        access: Access,
        msz: i32,
    ) -> Result {
        self.set_vec_reg(out, args.r, self.vec_size, access)?;
        self.set_vec_mem(out, args.b, self.vec_size, Access::Read, msz)
    }

    fn impl_args_rm_vv_mem(
        &mut self,
        out: &mut Insn,
        args: &args_rm_vv,
        access: Access,
        msz: i32,
        mem: MemAccess,
    ) -> Result {
        self.mem_access = mem;
        self.impl_args_rm_vv(out, args, access, msz)
    }

    fn impl_args_rm_vv_bcst(
        &mut self,
        out: &mut Insn,
        args: &args_rm_vv,
        access: Access,
        bcst: i32,
    ) -> Result {
        self.set_bcst(bcst);
        self.impl_args_rm_vv(out, args, access, 1)
    }

    fn impl_args_rm_vv_bcst_er(
        &mut self,
        out: &mut Insn,
        args: &args_rm_vv,
        access: Access,
        bcst: i32,
    ) -> Result {
        let er = self.get_er_sae_zmm();
        self.impl_args_rm_vv_bcst(out, args, access, bcst)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn impl_args_rm_vv_bcst_sae(
        &mut self,
        out: &mut Insn,
        args: &args_rm_vv,
        access: Access,
        bcst: i32,
    ) -> Result {
        let er = self.get_sae_zmm();
        self.impl_args_rm_vv_bcst(out, args, access, bcst)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn impl_args_rm_vy(&mut self, out: &mut Insn, args: &args_rm_vy, msz: i32) -> Result {
        self.set_vec_reg(out, args.r, self.vec_size, Access::Write)?;
        self.set_vec_mem(out, args.b, Size::Ymm, Access::Read, msz)
    }

    fn impl_args_rm_vy_mem(
        &mut self,
        out: &mut Insn,
        args: &args_rm_vy,
        msz: i32,
        mem: MemAccess,
    ) -> Result {
        self.mem_access = mem;
        self.impl_args_rm_vy(out, args, msz)
    }

    fn impl_args_rm_vx(&mut self, out: &mut Insn, args: &args_rm_vx, msz: i32) -> Result {
        self.set_vec_reg(out, args.r, self.vec_size, Access::Write)?;
        self.set_vec_mem(out, args.b, Size::Xmm, Access::Read, msz)
    }

    fn impl_args_rm_vx_mem(
        &mut self,
        out: &mut Insn,
        args: &args_rm_vx,
        msz: i32,
        mem: MemAccess,
    ) -> Result {
        self.mem_access = mem;
        self.impl_args_rm_vx(out, args, msz)
    }

    fn impl_args_rm_xv(&mut self, out: &mut Insn, args: &args_rm_xv, msz: i32) -> Result {
        self.set_vec_reg(out, args.r, Size::Xmm, Access::Write)?;
        self.set_vec_mem(out, args.b, self.vec_size, Access::Read, msz)
    }

    fn impl_args_rm_xr(&mut self, out: &mut Insn, args: &args_rm_xr, access: Access) -> Result {
        self.set_vec_reg(out, args.r, Size::Xmm, access)?;
        self.set_gpr_mem(out, args.b, 0, Access::Read, args.msz)?;
        Ok(())
    }

    fn impl_args_rm_xx(
        &mut self,
        out: &mut Insn,
        args: &args_rm_xx,
        msz: i32,
        access: Access,
    ) -> Result {
        self.set_vec_reg(out, args.r, Size::Xmm, access)?;
        self.set_vec_mem(out, args.b, Size::Xmm, Access::Read, msz)
    }

    fn impl_args_rm_xx_mem(
        &mut self,
        out: &mut Insn,
        args: &args_rm_xx,
        msz: i32,
        mem: MemAccess,
    ) -> Result {
        self.mem_access = mem;
        self.impl_args_rm_xx(out, args, msz, Access::Write)
    }

    fn impl_args_rm_xx_mem_sae(
        &mut self,
        out: &mut Insn,
        args: &args_rm_xx,
        msz: i32,
        mem: MemAccess,
    ) -> Result {
        let sae = self.get_sae_zmm();
        self.impl_args_rm_xx_mem(out, args, msz, mem)?;
        out.push_operand_if_some(sae);
        Ok(())
    }

    fn impl_args_rm_xm(&mut self, out: &mut Insn, args: &args_rm_xm, msz: i32) -> Result {
        self.set_vec_reg(out, args.r, Size::Xmm, Access::Write)?;
        self.set_vec_mem(out, args.b, Size::Mm, Access::Read, msz)
    }

    fn impl_args_rm_mx(&mut self, out: &mut Insn, args: &args_rm_mx, msz: i32) -> Result {
        self.set_vec_reg(out, args.r, Size::Mm, Access::Write)?;
        self.set_vec_mem(out, args.b, Size::Xmm, Access::Read, msz)
    }

    fn impl_args_rm_mm(
        &mut self,
        out: &mut Insn,
        args: &args_rm_mm,
        msz: i32,
        access: Access,
    ) -> Result {
        self.set_vec_reg(out, args.r, Size::Mm, access)?;
        self.set_vec_mem(out, args.b, Size::Mm, Access::Read, msz)
    }

    fn impl_args_rm_hv(&mut self, out: &mut Insn, args: &args_rm_hv) -> Result {
        let size = self.vec_reg_half();
        self.set_vec_reg(out, args.r, size, Access::Write)?;
        self.set_vec_mem(out, args.b, self.vec_size, Access::Read, 1)
    }

    fn impl_args_rm_hv_bcst(&mut self, out: &mut Insn, args: &args_rm_hv, bcst: i32) -> Result {
        self.set_bcst(bcst);
        self.impl_args_rm_hv(out, args)
    }

    fn impl_args_rm_hv_bcst_er(&mut self, out: &mut Insn, args: &args_rm_hv, bcst: i32) -> Result {
        let er = self.get_er_sae_zmm();
        self.impl_args_rm_hv_bcst(out, args, bcst)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn impl_args_rm_hv_sae(&mut self, out: &mut Insn, args: &args_rm_hv) -> Result {
        let er = self.get_sae_zmm();
        self.impl_args_rm_hv(out, args)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn impl_args_rm_hv_bcst_sae(&mut self, out: &mut Insn, args: &args_rm_hv, bcst: i32) -> Result {
        let er = self.get_sae_zmm();
        self.impl_args_rm_hv_bcst(out, args, bcst)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn impl_args_rm_qv(&mut self, out: &mut Insn, args: &args_rm_qv) -> Result {
        self.broadcast_force = true;
        self.set_vec_reg(out, args.r, Size::Xmm, Access::Write)?;
        self.set_vec_mem(out, args.b, self.vec_size, Access::Read, 1)
    }

    fn impl_args_rm_qv_bcst(&mut self, out: &mut Insn, args: &args_rm_qv, bcst: i32) -> Result {
        self.set_bcst(bcst);
        self.impl_args_rm_qv(out, args)
    }

    fn impl_args_rm_qv_bcst_er(&mut self, out: &mut Insn, args: &args_rm_qv, bcst: i32) -> Result {
        let er = self.get_er_sae_zmm();
        self.impl_args_rm_qv_bcst(out, args, bcst)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn impl_args_rm_vh(&mut self, out: &mut Insn, args: &args_rm_vh) -> Result {
        let (size, msz) = self.vec_mem_half();
        self.set_vec_reg(out, args.r, self.vec_size, Access::Write)?;
        self.set_vec_mem(out, args.b, size, Access::Read, msz)
    }

    fn impl_args_rm_vh_sae(&mut self, out: &mut Insn, args: &args_rm_vh) -> Result {
        let er = self.get_sae_zmm();
        self.impl_args_rm_vh(out, args)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn impl_args_rm_vh_bcst(&mut self, out: &mut Insn, args: &args_rm_vh, bcst: i32) -> Result {
        self.set_bcst(bcst);
        self.impl_args_rm_vh(out, args)
    }

    fn impl_args_rm_vh_bcst_er(&mut self, out: &mut Insn, args: &args_rm_vh, bcst: i32) -> Result {
        let er = self.get_er_sae_zmm();
        self.impl_args_rm_vh_bcst(out, args, bcst)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn impl_args_rm_vh_bcst_sae(&mut self, out: &mut Insn, args: &args_rm_vh, bcst: i32) -> Result {
        let er = self.get_sae_zmm();
        self.impl_args_rm_vh_bcst(out, args, bcst)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn impl_args_rm_vq(&mut self, out: &mut Insn, args: &args_rm_vq) -> Result {
        let (size, msz) = self.vec_mem_quarter();
        self.set_vec_reg(out, args.r, self.vec_size, Access::Write)?;
        self.set_vec_mem(out, args.b, size, Access::Read, msz)
    }

    fn impl_args_rm_vq_bcst(&mut self, out: &mut Insn, args: &args_rm_vq, bcst: i32) -> Result {
        self.set_bcst(bcst);
        self.impl_args_rm_vq(out, args)
    }

    fn impl_args_rm_vq_bcst_er(&mut self, out: &mut Insn, args: &args_rm_vq, bcst: i32) -> Result {
        let er = self.get_er_sae_zmm();
        self.impl_args_rm_vq_bcst(out, args, bcst)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn impl_args_rm_vq_bcst_sae(&mut self, out: &mut Insn, args: &args_rm_vq, bcst: i32) -> Result {
        let er = self.get_sae_zmm();
        self.impl_args_rm_vq_bcst(out, args, bcst)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn impl_args_rm_ve(&mut self, out: &mut Insn, args: &args_rm_ve) -> Result {
        let (size, msz) = self.vec_mem_eighth();
        self.set_vec_reg(out, args.r, self.vec_size, Access::Write)?;
        self.set_vec_mem(out, args.b, size, Access::Read, msz)
    }

    fn impl_args_mr_vv(&mut self, out: &mut Insn, args: &args_mr_vv) -> Result {
        self.set_vec_mem(out, args.b, self.vec_size, Access::Write, 1)?;
        self.set_vec_reg(out, args.r, self.vec_size, Access::Read)
    }

    fn impl_args_mr_vv_mem(&mut self, out: &mut Insn, args: &args_mr_vv, mem: MemAccess) -> Result {
        self.mem_access = mem;
        self.impl_args_mr_vv(out, args)
    }

    fn impl_args_mr_hv(&mut self, out: &mut Insn, args: &args_mr_hv) -> Result {
        let (size, msz) = self.vec_mem_half();
        self.set_vec_mem(out, args.b, size, Access::Write, msz)?;
        self.set_vec_reg(out, args.r, self.vec_size, Access::Read)
    }

    fn impl_args_mr_hv_sae(&mut self, out: &mut Insn, args: &args_mr_hv) -> Result {
        let er = self.get_sae_zmm();
        self.impl_args_mr_hv(out, args)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn impl_args_mr_qv(&mut self, out: &mut Insn, args: &args_mr_qv) -> Result {
        let (size, msz) = self.vec_mem_quarter();
        self.set_vec_mem(out, args.b, size, Access::Write, msz)?;
        self.set_vec_reg(out, args.r, self.vec_size, Access::Read)
    }

    fn impl_args_mr_ev(&mut self, out: &mut Insn, args: &args_mr_ev) -> Result {
        let (size, msz) = self.vec_mem_eighth();
        self.set_vec_mem(out, args.b, size, Access::Write, msz)?;
        self.set_vec_reg(out, args.r, self.vec_size, Access::Read)
    }

    fn impl_args_mr_yv_mem(
        &mut self,
        out: &mut Insn,
        args: &args_mr_yv,
        msz: i32,
        mem: MemAccess,
    ) -> Result {
        self.mem_access = mem;
        self.set_vec_mem(out, args.b, Size::Ymm, Access::Write, msz)?;
        self.set_vec_reg(out, args.r, self.vec_size, Access::Read)
    }

    fn impl_args_mr_xv(&mut self, out: &mut Insn, args: &args_mr_xv, msz: i32) -> Result {
        self.set_vec_mem(out, args.b, Size::Xmm, Access::Write, msz)?;
        self.set_vec_reg(out, args.r, self.vec_size, Access::Read)
    }

    fn impl_args_mr_xv_mem(
        &mut self,
        out: &mut Insn,
        args: &args_mr_xv,
        msz: i32,
        mem: MemAccess,
    ) -> Result {
        self.mem_access = mem;
        self.impl_args_mr_xv(out, args, msz)
    }

    fn impl_args_mr_xx(&mut self, out: &mut Insn, args: &args_mr_xx, msz: i32) -> Result {
        self.set_vec_mem(out, args.b, Size::Xmm, Access::Write, msz)?;
        self.set_vec_reg(out, args.r, Size::Xmm, Access::Read)
    }

    fn impl_args_mr_xx_mem(
        &mut self,
        out: &mut Insn,
        args: &args_mr_xx,
        msz: i32,
        mem: MemAccess,
    ) -> Result {
        self.mem_access = mem;
        self.impl_args_mr_xx(out, args, msz)
    }

    fn impl_args_mr_mm(&mut self, out: &mut Insn, args: &args_mr_mm, msz: i32) -> Result {
        self.set_vec_mem(out, args.b, Size::Mm, Access::Write, msz)?;
        self.set_vec_reg(out, args.r, Size::Mm, Access::Read)
    }

    fn impl_args_rvm_vvv(
        &mut self,
        out: &mut Insn,
        args: &args_rvm_vvv,
        access: Access,
        msz: i32,
    ) -> Result {
        self.set_vec_reg(out, args.r, self.vec_size, access)?;
        self.set_vec_reg(out, args.v, self.vec_size, Access::Read)?;
        self.set_vec_mem(out, args.b, self.vec_size, Access::Read, msz)
    }

    fn impl_args_rvm_vvv_mem(
        &mut self,
        out: &mut Insn,
        args: &args_rvm_vvv,
        access: Access,
        msz: i32,
        mem: MemAccess,
    ) -> Result {
        self.mem_access = mem;
        self.impl_args_rvm_vvv(out, args, access, msz)
    }

    fn impl_args_rvm_vvy_mem(
        &mut self,
        out: &mut Insn,
        args: &args_rvm_vvy,
        mem: MemAccess,
    ) -> Result {
        self.mem_access = mem;
        self.set_vec_reg(out, args.r, self.vec_size, Access::Write)?;
        self.set_vec_reg(out, args.v, self.vec_size, Access::Read)?;
        self.set_vec_mem(out, args.b, Size::Ymm, Access::Read, 1)
    }

    fn impl_args_rvm_vvx(&mut self, out: &mut Insn, args: &args_rvm_vvx) -> Result {
        self.set_vec_reg(out, args.r, self.vec_size, Access::Write)?;
        self.set_vec_reg(out, args.v, self.vec_size, Access::Read)?;
        self.set_vec_mem(out, args.b, Size::Xmm, Access::Read, 1)
    }

    fn impl_args_rvm_vvx_mem(
        &mut self,
        out: &mut Insn,
        args: &args_rvm_vvx,
        mem: MemAccess,
    ) -> Result {
        self.mem_access = mem;
        self.impl_args_rvm_vvx(out, args)
    }

    fn impl_args_rvm_vvv_bcst(
        &mut self,
        out: &mut Insn,
        args: &args_rvm_vvv,
        access: Access,
        bcst: i32,
    ) -> Result {
        self.set_bcst(bcst);
        self.impl_args_rvm_vvv(out, args, access, 1)
    }

    fn impl_args_rvm_vvv_bcst_er(
        &mut self,
        out: &mut Insn,
        args: &args_rvm_vvv,
        access: Access,
        bcst: i32,
    ) -> Result {
        let er = self.get_er_sae_zmm();
        self.impl_args_rvm_vvv_bcst(out, args, access, bcst)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn impl_args_rvm_vvv_bcst_sae(
        &mut self,
        out: &mut Insn,
        args: &args_rvm_vvv,
        access: Access,
        bcst: i32,
    ) -> Result {
        let er = self.get_sae_zmm();
        self.impl_args_rvm_vvv_bcst(out, args, access, bcst)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn impl_args_rvm_xxx(
        &mut self,
        out: &mut Insn,
        args: &args_rvm_xxx,
        access: Access,
        msz: i32,
    ) -> Result {
        self.set_vec_reg(out, args.r, Size::Xmm, access)?;
        self.set_vec_reg(out, args.v, Size::Xmm, Access::Read)?;
        self.set_vec_mem(out, args.b, Size::Xmm, Access::Read, msz)
    }

    fn impl_args_rvm_xxx_mem(
        &mut self,
        out: &mut Insn,
        args: &args_rvm_xxx,
        access: Access,
        msz: i32,
        mem: MemAccess,
    ) -> Result {
        self.mem_access = mem;
        self.impl_args_rvm_xxx(out, args, access, msz)
    }

    fn impl_args_rvm_xxx_mem_er(
        &mut self,
        out: &mut Insn,
        args: &args_rvm_xxx,
        access: Access,
        msz: i32,
        mem: MemAccess,
    ) -> Result {
        let er = self.get_er_sae_zmm();
        self.impl_args_rvm_xxx_mem(out, args, access, msz, mem)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn impl_args_rvm_xxx_mem_sae(
        &mut self,
        out: &mut Insn,
        args: &args_rvm_xxx,
        access: Access,
        msz: i32,
        mem: MemAccess,
    ) -> Result {
        let er = self.get_sae_zmm();
        self.impl_args_rvm_xxx_mem(out, args, access, msz, mem)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn impl_args_rvm_xxr(&mut self, out: &mut Insn, args: &args_rvm_xxr, msz: i32) -> Result {
        self.set_vec_reg(out, args.r, Size::Xmm, Access::Write)?;
        self.set_vec_reg(out, args.v, Size::Xmm, Access::Read)?;
        self.set_gpr_mem(out, args.b, 0, Access::Read, msz)
    }

    fn impl_args_fmadds(&mut self, out: &mut Insn, args: &args_rvm_vvv, msz: i32) -> Result {
        self.set_vec_reg(out, args.r, Size::Xmm, Access::ReadWrite)?;
        self.set_vec_reg(out, args.v, Size::Xmm, Access::Read)?;
        self.set_vec_mem(out, args.b, Size::Xmm, Access::Read, msz)
    }

    fn impl_args_fmadds_er(&mut self, out: &mut Insn, args: &args_rvm_vvv, msz: i32) -> Result {
        self.mem_access = MemAccess::Tuple1;
        let er = self.get_er_sae();
        self.impl_args_fmadds(out, args, msz)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn impl_args_fmaddp(&mut self, out: &mut Insn, args: &args_rvm_vvv) -> Result {
        self.set_vec_reg(out, args.r, self.vec_size, Access::ReadWrite)?;
        self.set_vec_reg(out, args.v, self.vec_size, Access::Read)?;
        self.set_vec_mem(out, args.b, self.vec_size, Access::Read, 1)
    }

    fn impl_args_fmaddp_bcst(&mut self, out: &mut Insn, args: &args_rvm_vvv, bcst: i32) -> Result {
        self.set_bcst(bcst);
        self.impl_args_fmaddp(out, args)
    }

    fn impl_args_fmaddp_bcst_er(
        &mut self,
        out: &mut Insn,
        args: &args_rvm_vvv,
        bcst: i32,
    ) -> Result {
        let er = self.get_er_sae_zmm();
        self.impl_args_fmaddp_bcst(out, args, bcst)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn impl_args_fmadds_4a(&mut self, out: &mut Insn, args: &args_rvm_vvv, msz: i32) -> Result {
        self.set_vec_reg(out, args.r, Size::Xmm, Access::Write)?;
        self.set_vec_reg(out, args.v, Size::Xmm, Access::Read)?;
        self.set_vec_mem(out, args.b, Size::Xmm, Access::Read, msz)?;
        self.set_vec_is4(out, 1, Size::Xmm, Access::Read)
    }

    fn impl_args_fmadds_4b(&mut self, out: &mut Insn, args: &args_rvm_vvv, msz: i32) -> Result {
        self.set_vec_reg(out, args.r, Size::Xmm, Access::Write)?;
        self.set_vec_reg(out, args.v, Size::Xmm, Access::Read)?;
        let mem =
            self.set_vec_mem_impl(out, args.b, Size::Xmm, Access::Read, msz, self.address_size)?;
        self.set_vec_is4(out, 1, Size::Xmm, Access::Read)?;
        self.push_operand_with_mask(out, mem);
        Ok(())
    }

    fn impl_args_fmaddp_4a(&mut self, out: &mut Insn, args: &args_rvm_vvv) -> Result {
        self.set_vec_reg(out, args.r, self.vec_size, Access::Write)?;
        self.set_vec_reg(out, args.v, self.vec_size, Access::Read)?;
        self.set_vec_mem(out, args.b, self.vec_size, Access::Read, 1)?;
        self.set_vec_is4(out, 1, self.vec_size, Access::Read)
    }

    fn impl_args_fmaddp_4b(&mut self, out: &mut Insn, args: &args_rvm_vvv) -> Result {
        self.set_vec_reg(out, args.r, self.vec_size, Access::Write)?;
        self.set_vec_reg(out, args.v, self.vec_size, Access::Read)?;
        let mem = self.set_vec_mem_impl(
            out,
            args.b,
            self.vec_size,
            Access::Read,
            1,
            self.address_size,
        )?;
        self.set_vec_is4(out, 1, self.vec_size, Access::Read)?;
        self.push_operand_with_mask(out, mem);
        Ok(())
    }

    fn impl_args_mvr_vvv(&mut self, out: &mut Insn, args: &args_mvr_vvv) -> Result {
        self.set_vec_mem(out, args.b, self.vec_size, Access::Write, 1)?;
        self.set_vec_reg(out, args.v, self.vec_size, Access::Read)?;
        self.set_vec_reg(out, args.r, self.vec_size, Access::Read)
    }

    fn impl_args_mvr_xxx(&mut self, out: &mut Insn, args: &args_mvr_xxx) -> Result {
        self.set_vec_mem(out, args.b, Size::Xmm, Access::Write, 1)?;
        self.set_vec_reg(out, args.v, Size::Xmm, Access::Read)?;
        self.set_vec_reg(out, args.r, Size::Xmm, Access::Read)
    }

    fn impl_args_rm_kv(&mut self, out: &mut Insn, args: &args_rm_kv) -> Result {
        self.set_k_reg(out, args.r, Access::Write)?;
        self.set_vec_mem(out, args.b, self.vec_size, Access::Read, 1)?;
        Ok(())
    }

    fn impl_args_rm_kv_bcst(&mut self, out: &mut Insn, args: &args_rm_kv, bcst: i32) -> Result {
        self.set_bcst(bcst);
        self.impl_args_rm_kv(out, args)
    }

    fn impl_args_rm_kx_mem(
        &mut self,
        out: &mut Insn,
        args: &args_rm_kx,
        msz: i32,
        mem: MemAccess,
    ) -> Result {
        self.mem_access = mem;
        self.set_k_reg(out, args.r, Access::Write)?;
        self.set_vec_mem(out, args.b, self.vec_size, Access::Read, msz)
    }

    fn impl_args_rm_vk(&mut self, out: &mut Insn, args: &args_rm_vk) -> Result {
        self.set_vec_reg(out, args.r, self.vec_size, Access::Write)?;
        self.set_k_mem(out, args.b, Access::Read, 1)
    }

    fn impl_args_rvm_kvv(&mut self, out: &mut Insn, args: &args_rvm_kvv) -> Result {
        self.set_k_reg(out, args.r, Access::Write)?;
        self.set_vec_reg(out, args.v, self.vec_size, Access::Read)?;
        self.set_vec_mem(out, args.b, self.vec_size, Access::Read, 1)
    }

    fn impl_args_rvm_kvv_bcst(&mut self, out: &mut Insn, args: &args_rvm_kvv, bcst: i32) -> Result {
        self.set_bcst(bcst);
        self.impl_args_rvm_kvv(out, args)
    }

    fn impl_args_rvm_kvv_bcst_sae(
        &mut self,
        out: &mut Insn,
        args: &args_rvm_kvv,
        bcst: i32,
    ) -> Result {
        let er = self.get_sae_zmm();
        self.impl_args_rvm_kvv_bcst(out, args, bcst)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn impl_args_rvm_kxx_mem_sae(
        &mut self,
        out: &mut Insn,
        args: &args_rvm_kxx,
        msz: i32,
        mem: MemAccess,
    ) -> Result {
        let er = self.get_sae_zmm();
        self.mem_access = mem;
        self.set_k_reg(out, args.r, Access::Write)?;
        self.set_vec_reg(out, args.v, Size::Xmm, Access::Read)?;
        self.set_vec_mem(out, args.b, Size::Xmm, Access::Read, msz)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn impl_args_rm_rk(&mut self, out: &mut Insn, args: &args_rm_rk, rsz: i32) -> Result {
        self.set_gpr_reg(out, args.r, Access::Write, rsz)?;
        self.set_k_mem(out, args.b, Access::Read, 1)
    }

    fn impl_args_rm_kk(
        &mut self,
        out: &mut Insn,
        args: &args_rm_kk,
        access: Access,
        msz: i32,
    ) -> Result {
        self.set_k_reg(out, args.r, access)?;
        self.set_k_mem(out, args.b, Access::Read, msz)
    }

    fn impl_args_mr_kk(
        &mut self,
        out: &mut Insn,
        args: &args_mr_kk,
        access: Access,
        msz: i32,
    ) -> Result {
        self.set_k_mem(out, args.b, access, msz)?;
        self.set_k_reg(out, args.r, Access::Read)
    }
}

macro_rules! forward {
    ($($args:ty {
       $(fn $from:ident = $to:ident($($arg:expr),* $(,)?)),* $(,)?
    })*) => (
        $($(fn $from(&mut self, out: &mut Insn, args: &$args) -> Result {
            self.$to(out, args $(, $arg)*)
        })*)*
    );
}

impl SetValue for Inner<'_> {
    type Error = Error;

    fn set_suffix_lazy(&mut self, out: &mut Insn, value: i32) -> Result {
        self.need_suffix = false;
        self.set_suffix(out, value)
    }

    fn set_suffix(&mut self, out: &mut Insn, value: i32) -> Result {
        let size = self.operand_size(value);
        let suffix = match size {
            8 => insn::SUFFIX_B,
            16 => insn::SUFFIX_W,
            32 => insn::SUFFIX_L,
            64 => insn::SUFFIX_Q,
            _ => unreachable!("unexpected suffix for size {size} (value={value})"),
        };
        if self.opts_arch.suffix_always || (self.need_suffix && !self.has_gpr) || value < 0 {
            out.flags_mut()
                .field_set(insn::FIELD_SUFFIX, suffix)
                .set(insn::SUFFIX);
        };
        Ok(())
    }

    fn set_no_ptr(&mut self, _: &mut Insn, value: i32) -> Result {
        self.no_ptr = value != 0;
        Ok(())
    }

    fn set_fixed(&mut self, _: &mut Insn, value: i32) -> Result {
        self.mem_access = match value {
            0 => MemAccess::Fixed,
            1 => MemAccess::Fixed1,
            2 => MemAccess::Fixed2,
            _ => unreachable!("unexpected fixed1 {value}"),
        };
        Ok(())
    }

    fn set_tuple(&mut self, _: &mut Insn, value: i32) -> Result {
        self.mem_access = match value {
            1 => MemAccess::Tuple1,
            2 => MemAccess::Tuple2,
            4 => MemAccess::Tuple4,
            8 => MemAccess::Tuple8,
            _ => unreachable!("unexpected tuple {value}"),
        };
        Ok(())
    }

    fn set_rex_w(&mut self, out: &mut Insn, value: i32) -> Result {
        out.flags_mut().set_if(insn::REX_W, value != 0 && self.w);
        Ok(())
    }

    fn set_rep(&mut self, out: &mut Insn, value: i32) -> Result {
        if value != 0 {
            let rep = match self.repeat {
                Repeat::None => 0,
                Repeat::RepZ if value == 2 => insn::REPZ,
                Repeat::RepZ => insn::REP,
                Repeat::RepNZ => insn::REPNZ,
            };
            out.flags_mut().field_set(insn::FIELD_REP, rep);
        }
        Ok(())
    }

    fn set_indirect(&mut self, _: &mut Insn, value: i32) -> Result {
        self.indirect = value != 0;
        Ok(())
    }

    fn set_moffs_ro(&mut self, out: &mut Insn, _: i32) -> Result {
        let sz = self.operand_size_bwlq().bits() as i32;
        self.set_gpr_reg(out, 0, Access::Write, sz)?;
        self.set_moffset(out, sz, Access::Read)?;
        self.set_suffix(out, sz)
    }

    fn set_moffs_wr(&mut self, out: &mut Insn, _: i32) -> Result {
        let sz = self.operand_size_bwl().bits() as i32;
        self.set_moffset(out, sz, Access::Write)?;
        self.set_gpr_reg(out, 0, Access::Read, sz)?;
        self.set_suffix(out, sz)
    }

    fn set_in_u8(&mut self, out: &mut Insn, _: i32) -> Result {
        let sz = self.operand_size_bwl().bits() as i32;
        self.set_gpr_reg(out, 0, Access::Write, sz)?;
        self.set_uimm(out, 8)?;
        self.set_suffix(out, sz)
    }

    fn set_in_rr(&mut self, out: &mut Insn, _: i32) -> Result {
        let sz = self.operand_size_bwl().bits() as i32;
        self.set_gpr_reg(out, 0, Access::Write, sz)?;
        self.set_gpr_reg(out, 2, Access::Read, 16)?;
        self.set_suffix(out, sz)
    }

    fn set_out_u8(&mut self, out: &mut Insn, _: i32) -> Result {
        let sz = self.operand_size_bwl().bits() as i32;
        self.set_uimm(out, 8)?;
        self.set_gpr_reg(out, 0, Access::Read, sz)?;
        self.set_suffix(out, sz)
    }

    fn set_out_rr(&mut self, out: &mut Insn, _: i32) -> Result {
        let sz = self.operand_size_bwl().bits() as i32;
        self.set_gpr_reg(out, 2, Access::Read, 16)?;
        self.set_gpr_reg(out, 0, Access::Read, sz)?;
        self.set_suffix(out, sz)
    }

    fn set_args_rm_bound(&mut self, out: &mut Insn, args: &args_rm) -> Result {
        let sz = if self.prefix_66 > 0 { 16 } else { 32 };
        self.set_gpr_reg(out, args.r, Access::Read, sz)?;
        self.set_gpr_mem(out, args.b, 0, Access::Read, sz * 2)?;
        self.set_suffix(out, sz)
    }

    fn set_a_rw(&mut self, out: &mut Insn, rsz: i32) -> Result {
        self.set_gpr_reg(out, 0, Access::ReadWrite, rsz)
    }

    forward! {
        args_b {
            fn set_args_b = impl_args_b(Access::Write),
            fn set_args_b_rw = impl_args_b(Access::ReadWrite),
            fn set_args_b_ro = impl_args_b(Access::Read),
        }
    }

    forward! {
        args_r {
            fn set_args_ri_ro = impl_args_ri_bwlq(Access::Read),
            fn set_args_ri_rw = impl_args_ri_bwlq(Access::ReadWrite),
        }
        args_m {
            fn set_args_m8 = impl_args_m(Access::Write, 8),
            fn set_args_m16 = impl_args_m(Access::Write, 16),
            fn set_args_m32 = impl_args_m(Access::Write, 32),
            fn set_args_m64 = impl_args_m(Access::Write, 64),
            fn set_args_m8_ro = impl_args_m(Access::Read, 8),
            fn set_args_m16_ro = impl_args_m(Access::Read, 16),
            fn set_args_m32_ro = impl_args_m(Access::Read, 32),
            fn set_args_m64_rw = impl_args_m(Access::ReadWrite, 64),
            fn set_args_m128_rw = impl_args_m(Access::ReadWrite, 128),
        }
        args_m {
            fn set_args_m = impl_args_m_bwlq(Access::Write),
            fn set_args_m_rw = impl_args_m_bwlq(Access::ReadWrite),
            fn set_args_m_cl_rw = impl_args_m_cl(Access::ReadWrite),
        }
        args_m {
            fn set_args_mi = impl_args_mi_bwlq(Access::Write),
            fn set_args_mi_ro = impl_args_mi_bwlq(Access::Read),
            fn set_args_mi_rw = impl_args_mi_bwlq(Access::ReadWrite),
        }
        args_m {
            fn set_args_mi_u8_rw = impl_args_mi_u8(Access::ReadWrite),
        }
        args_m {
            fn set_args_mi_s8_ro = impl_args_mi_s8(Access::Read),
            fn set_args_mi_s8_rw = impl_args_mi_s8(Access::ReadWrite),
        }
        args_m {
            fn set_args_mi_one_rw = impl_args_mi_one(Access::ReadWrite),
        }
        args_rm {
            fn set_args_rm_wlq = impl_args_rm_wlq(Access::Write),
            fn set_args_rm_bwlq = impl_args_rm_bwlq(Access::Write),
            fn set_args_rm32_ro = impl_args_rm(Access::Read, 32),
            fn set_args_rm_ro = impl_args_rm_bwlq(Access::Read),
            fn set_args_rm_rw = impl_args_rm_bwlq(Access::ReadWrite),
            fn set_args_rm_cmov = impl_args_rm_wlq(Access::Write),
        }
        args_mr {
            fn set_args_mr_bwlq = impl_args_mr_bwlq(Access::Write),
            fn set_args_mr_ro = impl_args_mr_bwlq(Access::Read),
            fn set_args_mr_rw = impl_args_mr_bwlq(Access::ReadWrite),
            fn set_args_mr_cl = impl_args_mr_cl(Access::Write),
            fn set_args_mr_u8 = impl_args_mr_u8(Access::Write),
        }
    }

    forward! {
        args_rm_rr {
            fn set_args_rm_rr = impl_args_rm_rr(Access::Write),
            fn set_args_rm_rr_rw = impl_args_rm_rr(Access::ReadWrite),
            fn set_args_rm_rr_ro = impl_args_rm_rr(Access::Read),
        }
        args_mr_rr {
            fn set_args_mr_rr = impl_args_mr_rr(Access::Write),
            fn set_args_mr_rr_rw = impl_args_mr_rr(Access::ReadWrite),
        }
    }

    fn set_args_mr_xchg(&mut self, out: &mut Insn, args: &args_mr) -> Result {
        let sz = self.operand_size_bwlq().bits() as i32;
        self.impl_args_mr_base(out, args, Access::ReadWrite, Access::ReadWrite, sz)
    }

    fn set_push_seg(&mut self, out: &mut Insn, value: i32) -> Result {
        debug_assert!((0..6).contains(&value));
        let reg = Reg::new(reg_class::SEGMENT, value as u64).read();
        out.push_reg(reg);
        Ok(())
    }

    fn set_pop_seg(&mut self, out: &mut Insn, value: i32) -> Result {
        debug_assert!((0..6).contains(&value));
        let reg = Reg::new(reg_class::SEGMENT, value as u64).write();
        out.push_reg(reg);
        Ok(())
    }

    forward! {
        args_m {
            fn set_args_fld_env = impl_args_fldst_env(Access::Read),
            fn set_args_fst_env = impl_args_fldst_env(Access::Write),
            fn set_args_fldst_env = impl_args_fldst_env(Access::ReadWrite),
            fn set_args_fbld = impl_args_fbldst(Access::Read),
            fn set_args_fbst = impl_args_fbldst(Access::Write),
            fn set_args_fldt = impl_args_fldstt(Access::Read),
            fn set_args_fstt = impl_args_fldstt(Access::Write),
        }
    }

    forward! {
        args_m {
            fn set_args_flds = impl_args_fld(32, 32),
            fn set_args_fldl = impl_args_fld(64, 64),
            fn set_args_flds16 = impl_args_fld(16, 32),
            fn set_args_fldl32 = impl_args_fld(32, 64),
            fn set_args_fldll64 = impl_args_fld(64, 80),
        }
        args_m {
            fn set_args_fsts = impl_args_fst(32, 32),
            fn set_args_fstl = impl_args_fst(64, 64),
            fn set_args_fsts16 = impl_args_fst(16, 32),
            fn set_args_fstl32 = impl_args_fst(32, 64),
            fn set_args_fstll64 = impl_args_fst(64, 80),
        }
    }

    fn set_xmm(&mut self, out: &mut Insn, value: i32) -> Result {
        self.set_vec_reg(out, value, Size::Xmm, Access::Read)
    }

    fn set_args_mem(&mut self, out: &mut Insn, args: &args_mem) -> Result {
        self.set_gpr_mem(out, args.b, 0, Access::Write, args.msz)
    }

    fn set_args_mem_rw(&mut self, out: &mut Insn, args: &args_mem) -> Result {
        self.set_gpr_mem(out, args.b, 0, Access::ReadWrite, args.msz)
    }

    fn set_args_mem_ro(&mut self, out: &mut Insn, args: &args_mem) -> Result {
        self.set_gpr_mem(out, args.b, 0, Access::Read, args.msz)
    }

    fn set_args_m_m_rw(&mut self, out: &mut Insn, args: &args_m) -> Result {
        self.set_vec_mem(out, args.b, Size::Mm, Access::ReadWrite, 1)
    }

    fn set_args_m_x_ro(&mut self, out: &mut Insn, args: &args_m) -> Result {
        self.set_vec_mem(out, args.b, Size::Xmm, Access::Read, 1)
    }

    fn set_args_m_x_rw(&mut self, out: &mut Insn, args: &args_m) -> Result {
        self.set_vec_mem(out, args.b, Size::Xmm, Access::ReadWrite, 1)
    }

    fn set_args_rvm_rrr(&mut self, out: &mut Insn, args: &args_rvm_rrr) -> Result {
        self.set_gpr_reg(out, args.r, Access::Write, args.rsz)?;
        self.set_gpr_vvv(out, args.v, Access::Read, args.rsz)?;
        self.set_gpr_mem(out, args.b, 0, Access::Read, args.msz)?;
        self.set_suffix(out, 1)
    }

    fn set_args_rmv_rrr(&mut self, out: &mut Insn, args: &args_rmv_rrr) -> Result {
        self.set_gpr_reg(out, args.r, Access::Write, args.rsz)?;
        self.set_gpr_mem(out, args.b, 0, Access::Read, args.msz)?;
        self.set_gpr_vvv(out, args.v, Access::Read, args.rsz)?;
        self.set_suffix(out, 1)
    }

    fn set_args_rm_rm(&mut self, out: &mut Insn, args: &args_rm_rm) -> Result {
        self.set_gpr_reg(out, args.r, Access::Write, args.rsz)?;
        self.set_vec_mem(out, args.b, Size::Mm, Access::Read, args.msz)
    }

    fn set_args_rm_mr(&mut self, out: &mut Insn, args: &args_rm_mr) -> Result {
        self.set_vec_reg(out, args.r, Size::Mm, Access::Write)?;
        self.set_gpr_mem(out, args.b, 0, Access::Read, args.msz)
    }

    fn set_args_mr_rm(&mut self, out: &mut Insn, args: &args_mr_rm) -> Result {
        self.set_gpr_mem(out, args.b, 0, Access::Write, args.msz)?;
        self.set_vec_reg(out, args.r, Size::Mm, Access::Read)
    }

    forward! {
        args_rm_xr {
            fn set_args_rm_xr = impl_args_rm_xr(Access::Write),
            fn set_args_rm_xr_rw = impl_args_rm_xr(Access::ReadWrite),
        }
    }

    fn set_args_rm_rx(&mut self, out: &mut Insn, args: &args_rm_rx) -> Result {
        self.set_gpr_reg(out, args.r, Access::Write, args.rsz)?;
        self.set_vec_mem(out, args.b, Size::Xmm, Access::Read, args.msz)
    }

    fn set_args_rm_sr(&mut self, out: &mut Insn, args: &args_mov_seg) -> Result {
        if args.seg >= 6 {
            return Err(Error::Failed(0));
        }
        out.push_reg(Reg::new(reg_class::SEGMENT, args.seg as u64).write());
        self.set_gpr_mem(out, args.base, 1, Access::Read, 16)?;
        if self.opts_arch.suffix_always {
            out.flags_mut()
                .field_set(insn::FIELD_SUFFIX, insn::SUFFIX_W)
                .set(insn::SUFFIX);
        };
        Ok(())
    }

    fn set_args_mr_rs(&mut self, out: &mut Insn, args: &args_mov_seg) -> Result {
        if args.seg >= 6 {
            return Err(Error::Failed(0));
        }
        self.set_gpr_mem(out, args.base, 1, Access::Write, 16)?;
        out.push_reg(Reg::new(reg_class::SEGMENT, args.seg as u64).read());
        if self.opts_arch.suffix_always {
            out.flags_mut()
                .field_set(insn::FIELD_SUFFIX, insn::SUFFIX_W)
                .set(insn::SUFFIX);
        }
        Ok(())
    }

    fn set_args_evex_rm_rx(&mut self, out: &mut Insn, args: &args_evex_rm_rv) -> Result {
        self.set_evex_rm_rv(out, args, Size::Xmm)
    }

    fn set_args_evex_rm_rx_er(&mut self, out: &mut Insn, args: &args_evex_rm_rv) -> Result {
        let er = self.get_er_sae();
        self.set_args_evex_rm_rx(out, args)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn set_args_evex_rm_rx_sae(&mut self, out: &mut Insn, args: &args_evex_rm_rv) -> Result {
        let sae = self.get_sae();
        self.set_args_evex_rm_rx(out, args)?;
        out.push_operand_if_some(sae);
        Ok(())
    }

    fn set_args_evex_rm_ry(&mut self, out: &mut Insn, args: &args_evex_rm_rv) -> Result {
        self.set_evex_rm_rv(out, args, Size::Ymm)
    }

    fn set_args_evex_rvm_xxr(&mut self, out: &mut Insn, args: &args_evex_rvm_vvr) -> Result {
        self.set_evex_rvm_vvr(out, args, Size::Xmm)
    }

    fn set_args_evex_rvm_xxr_er(&mut self, out: &mut Insn, args: &args_evex_rvm_vvr) -> Result {
        let er = self.get_er_sae();
        self.set_args_evex_rvm_xxr(out, args)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn set_args_gather_xvx(&mut self, out: &mut Insn, args: &args_gather) -> Result {
        self.set_gather_vvv(out, args, Size::Xmm, Size::Xmm)
    }

    fn set_args_gather_vvv(&mut self, out: &mut Insn, args: &args_gather) -> Result {
        self.set_gather_vvv(out, args, self.vec_size, self.vec_size)
    }

    fn set_args_evex_gather_vv(&mut self, out: &mut Insn, args: &args_evex_gather) -> Result {
        self.set_evex_gather(out, args, self.vec_size, self.vec_size)
    }

    fn set_args_evex_gather_vh(&mut self, out: &mut Insn, args: &args_evex_gather) -> Result {
        let half = self.vec_half().0;
        self.set_evex_gather(out, args, self.vec_size, half)
    }

    fn set_args_evex_gather_hv(&mut self, out: &mut Insn, args: &args_evex_gather) -> Result {
        let half = self.vec_half().0;
        self.set_evex_gather(out, args, half, self.vec_size)
    }

    fn set_args_evex_scatter_vv(&mut self, out: &mut Insn, args: &args_evex_scatter) -> Result {
        self.set_evex_scatter(out, args, self.vec_size, self.vec_size)
    }

    fn set_args_evex_scatter_vh(&mut self, out: &mut Insn, args: &args_evex_scatter) -> Result {
        let half = self.vec_half().0;
        self.set_evex_scatter(out, args, self.vec_size, half)
    }

    fn set_args_evex_scatter_hv(&mut self, out: &mut Insn, args: &args_evex_scatter) -> Result {
        let half = self.vec_half().0;
        self.set_evex_scatter(out, args, half, self.vec_size)
    }

    forward! {
        args_rm_vr {
            fn set_args_rm_vr_32 = impl_args_rm_vr(Access::Write, 32),
            fn set_args_rm_vr_64 = impl_args_rm_vr(Access::Write, 64),
        }
    }

    forward! {
        args_mr_rx {
            fn set_args_mr_rx_8 = impl_args_mr_rx(8),
            fn set_args_mr_rx_16 = impl_args_mr_rx(16),
            fn set_args_mr_rx_32 = impl_args_mr_rx(32),
            fn set_args_mr_rx_64 = impl_args_mr_rx(64),
            fn set_args_mr_rx_8x1  = impl_args_mr_rx_mem(8, MemAccess::Tuple1),
            fn set_args_mr_rx_16x1 = impl_args_mr_rx_mem(16, MemAccess::Tuple1),
            fn set_args_mr_rx_32x1 = impl_args_mr_rx_mem(32, MemAccess::Tuple1),
            fn set_args_mr_rx_64x1 = impl_args_mr_rx_mem(64, MemAccess::Tuple1),
        }
    }

    forward! {
        args_rm_vv {
            fn set_args_rm_vv = impl_args_rm_vv(Access::Write, 1),
            fn set_args_rm_vv_ro = impl_args_rm_vv(Access::Read, 1),
            fn set_args_rm_vv_64 = impl_args_rm_vv(Access::Write, 64),
            fn set_args_rm_vv_x1 = impl_args_rm_vv_mem(Access::Write, 1, MemAccess::Tuple1),
            fn set_args_rm_vv_bcst16 = impl_args_rm_vv_bcst(Access::Write, 16),
            fn set_args_rm_vv_bcst32 = impl_args_rm_vv_bcst(Access::Write, 32),
            fn set_args_rm_vv_bcst64 = impl_args_rm_vv_bcst(Access::Write, 64),
            fn set_args_rm_vv_bcst16_er = impl_args_rm_vv_bcst_er(Access::Write, 16),
            fn set_args_rm_vv_bcst32_er = impl_args_rm_vv_bcst_er(Access::Write, 32),
            fn set_args_rm_vv_bcst64_er = impl_args_rm_vv_bcst_er(Access::Write, 64),
            fn set_args_rm_vv_bcst16_sae = impl_args_rm_vv_bcst_sae(Access::Write, 16),
            fn set_args_rm_vv_bcst32_sae = impl_args_rm_vv_bcst_sae(Access::Write, 32),
            fn set_args_rm_vv_bcst64_sae = impl_args_rm_vv_bcst_sae(Access::Write, 64),
        }
    }

    forward! {
        args_rm_vy {
            fn set_args_rm_vy_32x8 = impl_args_rm_vy_mem(32, MemAccess::Tuple8),
            fn set_args_rm_vy_64x4 = impl_args_rm_vy_mem(64, MemAccess::Tuple4),
        }
    }

    forward! {
        args_rm_vx {
            fn set_args_rm_vx = impl_args_rm_vx(1),
            fn set_args_rm_vx_8 = impl_args_rm_vx(8),
            fn set_args_rm_vx_16 = impl_args_rm_vx(16),
            fn set_args_rm_vx_32 = impl_args_rm_vx(32),
            fn set_args_rm_vx_64 = impl_args_rm_vx(64),
            fn set_args_rm_vx_8x1 = impl_args_rm_vx_mem(8, MemAccess::Tuple1),
            fn set_args_rm_vx_16x1 = impl_args_rm_vx_mem(16, MemAccess::Tuple1),
            fn set_args_rm_vx_32x1 = impl_args_rm_vx_mem(32, MemAccess::Tuple1),
            fn set_args_rm_vx_32x2 = impl_args_rm_vx_mem(32, MemAccess::Tuple2),
            fn set_args_rm_vx_32x4 = impl_args_rm_vx_mem(32, MemAccess::Tuple4),
            fn set_args_rm_vx_64x1 = impl_args_rm_vx_mem(64, MemAccess::Tuple1),
            fn set_args_rm_vx_64x2 = impl_args_rm_vx_mem(64, MemAccess::Tuple2),
        }
    }

    forward! {
        args_rm_xv {
            fn set_args_rm_xv = impl_args_rm_xv(1),
        }
    }

    forward! {
        args_rm_xx {
            fn set_args_rm_xx = impl_args_rm_xx(1, Access::Write),
            fn set_args_rm_xx_rw = impl_args_rm_xx(1, Access::ReadWrite),
            fn set_args_rm_xx_ro = impl_args_rm_xx(1, Access::Read),
            fn set_args_rm_xx_8 = impl_args_rm_xx(8, Access::Write),
            fn set_args_rm_xx_16 = impl_args_rm_xx(16, Access::Write),
            fn set_args_rm_xx_32 = impl_args_rm_xx(32, Access::Write),
            fn set_args_rm_xx_64 = impl_args_rm_xx(64, Access::Write),
            fn set_args_rm_xx_32_rw = impl_args_rm_xx(32, Access::ReadWrite),
            fn set_args_rm_xx_32_ro = impl_args_rm_xx(32, Access::Read),
            fn set_args_rm_xx_64_rw = impl_args_rm_xx(64, Access::ReadWrite),
            fn set_args_rm_xx_64_ro = impl_args_rm_xx(64, Access::Read),
            fn set_args_rm_xx_16x1 = impl_args_rm_xx_mem(16, MemAccess::Tuple1),
            fn set_args_rm_xx_32x1 = impl_args_rm_xx_mem(32, MemAccess::Tuple1),
            fn set_args_rm_xx_64x1 = impl_args_rm_xx_mem(64, MemAccess::Tuple1),
            fn set_args_rm_xx_16x1_sae = impl_args_rm_xx_mem_sae(16, MemAccess::Tuple1),
            fn set_args_rm_xx_32x1_sae = impl_args_rm_xx_mem_sae(32, MemAccess::Tuple1),
            fn set_args_rm_xx_64x1_sae = impl_args_rm_xx_mem_sae(64, MemAccess::Tuple1),
        }
    }

    forward! {
        args_rm_xm {
            fn set_args_rm_xm = impl_args_rm_xm(1),
        }
        args_rm_mx {
            fn set_args_rm_mx = impl_args_rm_mx(1),
            fn set_args_rm_mx_64 = impl_args_rm_mx(64),
        }
        args_rm_mm {
            fn set_args_rm_mm = impl_args_rm_mm(1, Access::Write),
            fn set_args_rm_mm_rw = impl_args_rm_mm(1, Access::ReadWrite),
            fn set_args_rm_mm_ro = impl_args_rm_mm(1, Access::Read),
            fn set_args_rm_mm_32_rw = impl_args_rm_mm(32, Access::ReadWrite),
        }
    }

    forward! {
        args_rm_hv {
            fn set_args_rm_hv_bcst32 = impl_args_rm_hv_bcst(32),
            fn set_args_rm_hv_bcst32_er = impl_args_rm_hv_bcst_er(32),
            fn set_args_rm_hv_bcst64_er = impl_args_rm_hv_bcst_er(64),
            fn set_args_rm_hv_sae = impl_args_rm_hv_sae(),
            fn set_args_rm_hv_bcst64_sae = impl_args_rm_hv_bcst_sae(64),
        }
    }

    forward! {
        args_rm_qv {
            fn set_args_rm_qv_bcst64_er = impl_args_rm_qv_bcst_er(64),
        }
    }

    forward! {
        args_rm_vh {
            fn set_args_rm_vh = impl_args_rm_vh(),
            fn set_args_rm_vh_bcst32 = impl_args_rm_vh_bcst(32),
            fn set_args_rm_vh_bcst16_er = impl_args_rm_vh_bcst_er(16),
            fn set_args_rm_vh_bcst32_er = impl_args_rm_vh_bcst_er(32),
            fn set_args_rm_vh_sae = impl_args_rm_vh_sae(),
            fn set_args_rm_vh_bcst16_sae = impl_args_rm_vh_bcst_sae(16),
            fn set_args_rm_vh_bcst32_sae = impl_args_rm_vh_bcst_sae(32),
        }
    }

    forward! {
        args_rm_vq {
            fn set_args_rm_vq = impl_args_rm_vq(),
            fn set_args_rm_vq_bcst16_er = impl_args_rm_vq_bcst_er(16),
            fn set_args_rm_vq_bcst16_sae = impl_args_rm_vq_bcst_sae(16),
        }
    }

    forward! {
        args_rm_ve {
            fn set_args_rm_ve = impl_args_rm_ve(),
        }
    }

    forward! {
        args_mr_vv {
            fn set_args_mr_vv = impl_args_mr_vv(),
            fn set_args_mr_vv_x1 = impl_args_mr_vv_mem(MemAccess::Tuple1),
        }
        args_mr_hv {
            fn set_args_mr_hv = impl_args_mr_hv(),
            fn set_args_mr_hv_sae = impl_args_mr_hv_sae(),
        }
        args_mr_qv {
            fn set_args_mr_qv = impl_args_mr_qv(),
        }
        args_mr_ev {
            fn set_args_mr_ev = impl_args_mr_ev(),
        }
    }

    forward! {
        args_mr_xx {
            fn set_args_mr_xx = impl_args_mr_xx(1),
            fn set_args_mr_xx_32 = impl_args_mr_xx(32),
            fn set_args_mr_xx_64 = impl_args_mr_xx(64),
            fn set_args_mr_xx_16x1 = impl_args_mr_xx_mem(16, MemAccess::Tuple1),
            fn set_args_mr_xx_32x1 = impl_args_mr_xx_mem(32, MemAccess::Tuple1),
            fn set_args_mr_xx_32x2 = impl_args_mr_xx_mem(32, MemAccess::Tuple2),
            fn set_args_mr_xx_64x1 = impl_args_mr_xx_mem(64, MemAccess::Tuple1),
        }
        args_mr_xv {
            fn set_args_mr_xv = impl_args_mr_xv(1),
            fn set_args_mr_xv_x2 = impl_args_mr_xv_mem(1, MemAccess::Tuple2),
            fn set_args_mr_xv_x4 = impl_args_mr_xv_mem(1, MemAccess::Tuple4),
        }
        args_mr_yv {
            fn set_args_mr_yv_x4 = impl_args_mr_yv_mem(1, MemAccess::Tuple4),
            fn set_args_mr_yv_x8 = impl_args_mr_yv_mem(1, MemAccess::Tuple8),
        }
    }

    forward! {
        args_mr_mm {
            fn set_args_mr_mm = impl_args_mr_mm(1),
        }
    }

    forward! {
        args_rvm_vvv {
            fn set_args_rvm_vvv = impl_args_rvm_vvv(Access::Write, 1),
            fn set_args_rvm_vvv_rw = impl_args_rvm_vvv(Access::ReadWrite, 1),

            fn set_args_rvm_vvv_16x1 = impl_args_rvm_vvv_mem(Access::Write, 16, MemAccess::Tuple1),
            fn set_args_rvm_vvv_32x1 = impl_args_rvm_vvv_mem(Access::Write, 32, MemAccess::Tuple1),
            fn set_args_rvm_vvv_64x1 = impl_args_rvm_vvv_mem(Access::Write, 64, MemAccess::Tuple1),
            fn set_args_rvm_vvv_32x2 = impl_args_rvm_vvv_mem(Access::Write, 32, MemAccess::Tuple2),

            // fn set_args_rvm_vvv_bcst16 = impl_args_rvm_vvv_bcst(Access::Write, 16),
            fn set_args_rvm_vvv_bcst32 = impl_args_rvm_vvv_bcst(Access::Write, 32),
            fn set_args_rvm_vvv_bcst64 = impl_args_rvm_vvv_bcst(Access::Write, 64),

            fn set_args_rvm_vvv_bcst32_rw = impl_args_rvm_vvv_bcst(Access::ReadWrite, 32),
            fn set_args_rvm_vvv_bcst64_rw = impl_args_rvm_vvv_bcst(Access::ReadWrite, 64),

            fn set_args_rvm_vvv_bcst16_er = impl_args_rvm_vvv_bcst_er(Access::Write, 16),
            fn set_args_rvm_vvv_bcst32_er = impl_args_rvm_vvv_bcst_er(Access::Write, 32),
            fn set_args_rvm_vvv_bcst64_er = impl_args_rvm_vvv_bcst_er(Access::Write, 64),

            fn set_args_rvm_vvv_bcst16_sae = impl_args_rvm_vvv_bcst_sae(Access::Write, 16),
            fn set_args_rvm_vvv_bcst32_sae = impl_args_rvm_vvv_bcst_sae(Access::Write, 32),
            fn set_args_rvm_vvv_bcst64_sae = impl_args_rvm_vvv_bcst_sae(Access::Write, 64),
        }
    }

    forward! {
        args_rvm_vvy {
            fn set_args_rvm_vvy_x4 = impl_args_rvm_vvy_mem(MemAccess::Tuple4),
            fn set_args_rvm_vvy_x8 = impl_args_rvm_vvy_mem(MemAccess::Tuple8),
        }
    }

    forward! {
        args_rvm_vvx {
            fn set_args_rvm_vvx = impl_args_rvm_vvx(),
            fn set_args_rvm_vvx_x2 = impl_args_rvm_vvx_mem(MemAccess::Tuple2),
            fn set_args_rvm_vvx_x4 = impl_args_rvm_vvx_mem(MemAccess::Tuple4),
            fn set_args_rvm_vvx_128 = impl_args_rvm_vvx_mem(MemAccess::Mem128),
        }
    }

    forward! {
        args_rvm_xxx {
            fn set_args_rvm_xxx = impl_args_rvm_xxx(Access::Write, 1),
            fn set_args_rvm_xxx_32 = impl_args_rvm_xxx(Access::Write, 32),
            fn set_args_rvm_xxx_64 = impl_args_rvm_xxx(Access::Write, 64),

            fn set_args_rvm_xxx_x1 = impl_args_rvm_xxx_mem(Access::Write, 1, MemAccess::Tuple1),
            fn set_args_rvm_xxx_16x1 = impl_args_rvm_xxx_mem(Access::Write, 16, MemAccess::Tuple1),
            fn set_args_rvm_xxx_32x1 = impl_args_rvm_xxx_mem(Access::Write, 32, MemAccess::Tuple1),
            fn set_args_rvm_xxx_64x1 = impl_args_rvm_xxx_mem(Access::Write, 64, MemAccess::Tuple1),

            fn set_args_rvm_xxx_16x1_er = impl_args_rvm_xxx_mem_er(Access::Write, 16, MemAccess::Tuple1),
            fn set_args_rvm_xxx_32x1_er = impl_args_rvm_xxx_mem_er(Access::Write, 32, MemAccess::Tuple1),
            fn set_args_rvm_xxx_64x1_er = impl_args_rvm_xxx_mem_er(Access::Write, 64, MemAccess::Tuple1),

            fn set_args_rvm_xxx_16x1_sae = impl_args_rvm_xxx_mem_sae(Access::Write, 16, MemAccess::Tuple1),
            fn set_args_rvm_xxx_32x1_sae = impl_args_rvm_xxx_mem_sae(Access::Write, 32, MemAccess::Tuple1),
            fn set_args_rvm_xxx_64x1_sae = impl_args_rvm_xxx_mem_sae(Access::Write, 64, MemAccess::Tuple1),
        }
    }

    forward! {
        args_rvm_xxr {
            fn set_args_rvm_xxr_8 = impl_args_rvm_xxr(8),
            fn set_args_rvm_xxr_16 = impl_args_rvm_xxr(16),
            fn set_args_rvm_xxr_32 = impl_args_rvm_xxr(32),
            fn set_args_rvm_xxr_64 = impl_args_rvm_xxr(64),
        }
    }

    forward! {
        args_rvm_vvv {
            fn set_args_fmaddss = impl_args_fmadds(32),
            fn set_args_fmaddsd = impl_args_fmadds(64),

            fn set_args_fmaddps = impl_args_fmaddp(),
            fn set_args_fmaddpd = impl_args_fmaddp(),
        }
    }

    forward! {
        args_rvm_vvv {
            fn set_args_fmaddsh_er = impl_args_fmadds_er(16),
            fn set_args_fmaddss_er = impl_args_fmadds_er(32),
            fn set_args_fmaddsd_er = impl_args_fmadds_er(64),
            fn set_args_fmaddcsh_er = impl_args_fmadds_er(32),

            fn set_args_pmaddp_bcst = impl_args_fmaddp_bcst(64),
            fn set_args_fmaddph_bcst_er = impl_args_fmaddp_bcst_er(16),
            fn set_args_fmaddps_bcst_er = impl_args_fmaddp_bcst_er(32),
            fn set_args_fmaddpd_bcst_er = impl_args_fmaddp_bcst_er(64),
            fn set_args_fmaddcph_bcst_er = impl_args_fmaddp_bcst_er(32),
        }
    }

    forward! {
        args_rvm_vvv {
            fn set_args_fmaddss_4a = impl_args_fmadds_4a(32),
            fn set_args_fmaddss_4b = impl_args_fmadds_4b(32),

            fn set_args_fmaddsd_4a = impl_args_fmadds_4a(64),
            fn set_args_fmaddsd_4b = impl_args_fmadds_4b(64),

            fn set_args_fmaddps_4a = impl_args_fmaddp_4a(),
            fn set_args_fmaddps_4b = impl_args_fmaddp_4b(),

            fn set_args_fmaddpd_4a = impl_args_fmaddp_4a(),
            fn set_args_fmaddpd_4b = impl_args_fmaddp_4b(),
        }
    }

    forward! {
        args_mvr_vvv {
            fn set_args_mvr_vvv = impl_args_mvr_vvv(),
        }
    }

    forward! {
        args_mvr_xxx {
            fn set_args_mvr_xxx = impl_args_mvr_xxx(),
        }
    }

    forward! {
        args_rm_kv {
            fn set_args_rm_kv = impl_args_rm_kv(),

            fn set_args_rm_kv_bcst16 = impl_args_rm_kv_bcst(-16),
            fn set_args_rm_kv_bcst32 = impl_args_rm_kv_bcst(-32),
            fn set_args_rm_kv_bcst64 = impl_args_rm_kv_bcst(-64),
        }
    }

    forward! {
        args_rm_kx {
            fn set_args_rm_kx_16x1 = impl_args_rm_kx_mem(16, MemAccess::Tuple1),
            fn set_args_rm_kx_32x1 = impl_args_rm_kx_mem(32, MemAccess::Tuple1),
            fn set_args_rm_kx_64x1 = impl_args_rm_kx_mem(64, MemAccess::Tuple1),
        }
    }

    forward! {
        args_rm_vk {
            fn set_args_rm_vk = impl_args_rm_vk(),
        }
    }

    forward! {
        args_rvm_kvv {
            fn set_args_rvm_kvv = impl_args_rvm_kvv(),

            fn set_args_rvm_kvv_bcst32 = impl_args_rvm_kvv_bcst(32),
            fn set_args_rvm_kvv_bcst64 = impl_args_rvm_kvv_bcst(64),

            fn set_args_rvm_kvv_bcst16_sae = impl_args_rvm_kvv_bcst_sae(16),
            fn set_args_rvm_kvv_bcst32_sae = impl_args_rvm_kvv_bcst_sae(32),
            fn set_args_rvm_kvv_bcst64_sae = impl_args_rvm_kvv_bcst_sae(64),
        }
    }

    forward! {
        args_rvm_kxx {
            fn set_args_rvm_kxx_16x1_sae = impl_args_rvm_kxx_mem_sae(16, MemAccess::Tuple1),
            fn set_args_rvm_kxx_32x1_sae = impl_args_rvm_kxx_mem_sae(32, MemAccess::Tuple1),
            fn set_args_rvm_kxx_64x1_sae = impl_args_rvm_kxx_mem_sae(64, MemAccess::Tuple1),
        }
    }

    fn set_args_rvm_kkk(&mut self, out: &mut Insn, args: &args_rvm_kkk) -> Result {
        self.set_k_reg(out, args.r, Access::Write)?;
        self.set_k_vvv(out, args.v, Access::Read)?;
        self.set_k_mem(out, args.b, Access::Read, 1)
    }

    forward! {
        args_rm_rk {
            fn set_args_rm_rk_32 = impl_args_rm_rk(32),
            fn set_args_rm_rk_64 = impl_args_rm_rk(64),
        }
    }

    forward! {
        args_rm_kk {
            fn set_args_rm_kk = impl_args_rm_kk(Access::Write, 1),
            fn set_args_rm_kk_ro = impl_args_rm_kk(Access::Read, 1),
            fn set_args_rm_kk_8 = impl_args_rm_kk(Access::Write, 8),
            fn set_args_rm_kk_16 = impl_args_rm_kk(Access::Write, 16),
            fn set_args_rm_kk_32 = impl_args_rm_kk(Access::Write, 32),
            fn set_args_rm_kk_64 = impl_args_rm_kk(Access::Write, 64),
        }
    }

    forward! {
        args_mr_kk {
            fn set_args_mr_kk_8 = impl_args_mr_kk(Access::Write, 8),
            fn set_args_mr_kk_16 = impl_args_mr_kk(Access::Write, 16),
            fn set_args_mr_kk_32 = impl_args_mr_kk(Access::Write, 32),
            fn set_args_mr_kk_64 = impl_args_mr_kk(Access::Write, 64),
        }
    }

    fn set_args_evex_rm_kr(&mut self, out: &mut Insn, args: &args_evex_rm_kr) -> Result {
        self.set_k_reg(out, args.r, Access::Write)?;
        self.set_gpr_mem(out, args.b, 0, Access::Read, args.msz)?;
        Ok(())
    }

    fn set_ins_size(&mut self, out: &mut Insn, size: i32) -> Result {
        self.mode = 0;
        self.set_rep(out, 1)?;
        self.segment = insn::SEGMENT_ES;
        self.set_gpr_mem(out, 7, 0, Access::Write, size)?;
        self.set_gpr_reg(out, 2, Access::Read, 16)
    }

    fn set_outs_size(&mut self, out: &mut Insn, size: i32) -> Result {
        self.mode = 0;
        self.set_rep(out, 1)?;
        self.segment = insn::SEGMENT_DS;
        self.set_gpr_reg(out, 2, Access::Read, 16)?;
        self.set_gpr_mem(out, 6, 0, Access::Read, size)
    }

    fn set_xlat(&mut self, out: &mut Insn, _: i32) -> Result {
        self.mode = 0;
        self.segment = insn::SEGMENT_DS;
        self.set_gpr_mem(out, 3, 0, Access::Read, 8)?;
        out.flags_mut().set_if(insn::REX_W, self.w);
        Ok(())
    }

    fn set_movs(&mut self, out: &mut Insn, _: i32) -> Result {
        let msz = self.operand_size_bwlq().bits() as i32;
        self.mode = 0;
        self.set_rep(out, 1)?;
        self.segment = insn::SEGMENT_ES;
        self.set_gpr_mem(out, 7, msz, Access::Write, msz)?;
        self.segment = insn::SEGMENT_DS;
        self.set_gpr_mem(out, 6, msz, Access::Read, msz)?;
        self.set_suffix(out, msz)?;
        Ok(())
    }

    fn set_cmps(&mut self, out: &mut Insn, _: i32) -> Result {
        let msz = self.operand_size_bwlq().bits() as i32;
        self.mode = 0;
        self.set_rep(out, 2)?;
        self.segment = insn::SEGMENT_DS;
        self.set_gpr_mem(out, 6, msz, Access::Read, msz)?;
        self.segment = insn::SEGMENT_ES;
        self.set_gpr_mem(out, 7, msz, Access::Read, msz)?;
        self.set_suffix(out, msz)?;
        Ok(())
    }

    fn set_stos(&mut self, out: &mut Insn, _: i32) -> Result {
        let msz = self.operand_size_bwlq().bits() as i32;
        self.mode = 0;
        self.set_rep(out, 1)?;
        self.segment = insn::SEGMENT_ES;
        self.set_gpr_mem(out, 7, msz, Access::Write, msz)?;
        self.set_gpr_reg(out, 0, Access::Read, msz)?;
        self.set_suffix(out, msz)?;
        Ok(())
    }

    fn set_lods(&mut self, out: &mut Insn, _: i32) -> Result {
        let msz = self.operand_size_bwlq().bits() as i32;
        self.mode = 0;
        self.set_rep(out, 1)?;
        self.set_gpr_reg(out, 0, Access::Write, msz)?;
        self.segment = insn::SEGMENT_DS;
        self.set_gpr_mem(out, 6, msz, Access::Read, msz)?;
        self.set_suffix(out, msz)?;
        Ok(())
    }

    fn set_scas(&mut self, out: &mut Insn, _: i32) -> Result {
        let msz = self.operand_size_bwlq().bits() as i32;
        self.mode = 0;
        self.set_rep(out, 2)?;
        self.set_gpr_reg(out, 0, Access::Read, msz)?;
        self.segment = insn::SEGMENT_ES;
        self.set_gpr_mem(out, 7, msz, Access::Read, msz)?;
        self.set_suffix(out, msz)?;
        Ok(())
    }

    fn set_args_bm(&mut self, out: &mut Insn, args: &args_r) -> Result {
        self.set_bnd_reg(out, args.r, Access::Write)
    }

    fn set_args_bm_ro(&mut self, out: &mut Insn, args: &args_r) -> Result {
        self.set_bnd_reg(out, args.r, Access::Read)
    }

    fn set_aimm(&mut self, out: &mut Insn, value: i32) -> Result {
        if value != 0 {
            if self.w {
                self.set_simm(out, 2)
            } else {
                self.set_uimm(out, 2)
            }
        } else {
            Ok(())
        }
    }

    fn set_uimm(&mut self, out: &mut Insn, value: i32) -> Result {
        let (_, imm) = self.read_uimm(value)?;
        out.push_uimm(imm);
        self.need_suffix = true;
        Ok(())
    }

    fn set_uimm2(&mut self, out: &mut Insn, value: i32) -> Result {
        self.set_uimm(out, value)
    }

    fn set_simm(&mut self, out: &mut Insn, value: i32) -> Result {
        self.set_simm_impl(out, value, self.operand_size.bits())
    }

    fn set_simm32(&mut self, out: &mut Insn, value: i32) -> Result {
        self.set_simm_impl(out, value, 32)
    }

    fn set_simm64(&mut self, out: &mut Insn, value: i32) -> Result {
        self.set_simm_impl(out, value, 64)
    }

    fn set_rel(&mut self, out: &mut Insn, value: i32) -> Result {
        debug_assert!(value == 0);
        let disp = match self.operand_size {
            Size::Long => self.bytes.read_i32()? as i64,
            Size::Word => self.bytes.read_i16()? as i64,
            Size::Quad => self.bytes.read_i64()?,
            _ => todo!(),
        };
        self.set_rel_impl(out, disp)
    }

    fn set_rel8(&mut self, out: &mut Insn, _: i32) -> Result {
        let disp = self.bytes.read_i8()?;
        self.set_rel_impl(out, disp as i64)
    }

    fn set_rel16(&mut self, out: &mut Insn, _: i32) -> Result {
        let disp = self.bytes.read_i16()?;
        self.set_rel_impl(out, disp as i64)
    }

    fn set_rel32(&mut self, out: &mut Insn, _: i32) -> Result {
        let disp = self.bytes.read_i32()?;
        self.set_rel_impl(out, disp as i64)
    }

    fn set_vi_r(&mut self, out: &mut Insn, value: i32) -> Result {
        self.set_vec_is4(out, value, self.vec_size, Access::Read)
    }

    fn set_sti_r(&mut self, out: &mut Insn, value: i32) -> Result {
        // TODO: read/write
        out.push_sti(value as u64);
        Ok(())
    }

    fn set_sti_w(&mut self, out: &mut Insn, value: i32) -> Result {
        // TODO: read/write
        out.push_sti(value as u64);
        Ok(())
    }

    fn set_sti_st_rm(&mut self, out: &mut Insn, value: i32) -> Result {
        // TODO: read/write
        out.push_sti(value as u64);
        out.push_st();
        Ok(())
    }

    fn set_sti_st_mm(&mut self, out: &mut Insn, value: i32) -> Result {
        // TODO: read/write
        out.push_sti(value as u64);
        out.push_st();
        Ok(())
    }

    fn set_st_sti_mr(&mut self, out: &mut Insn, value: i32) -> Result {
        // TODO: read/write
        out.push_st();
        out.push_sti(value as u64);
        Ok(())
    }

    fn set_st_sti_mm(&mut self, out: &mut Insn, value: i32) -> Result {
        // TODO: read/write
        out.push_st();
        out.push_sti(value as u64);
        Ok(())
    }

    fn set_br_r(&mut self, out: &mut Insn, value: i32) -> Result {
        self.set_bnd_reg(out, value, Access::Read)
    }

    fn set_br_w(&mut self, out: &mut Insn, value: i32) -> Result {
        self.set_bnd_reg(out, value, Access::Write)
    }

    fn set_opc(&mut self, out: &mut Insn, val: i32) -> Result {
        let (_, imm) = self.read_uimm(val)?;
        let opcode = out.opcode();
        match opcode {
            opcode::CMPSS => match imm {
                0 => out.set_opcode(opcode::CMPEQSS),
                1 => out.set_opcode(opcode::CMPLTSS),
                2 => out.set_opcode(opcode::CMPLESS),
                3 => out.set_opcode(opcode::CMPUNORDSS),
                4 => out.set_opcode(opcode::CMPNEQSS),
                5 => out.set_opcode(opcode::CMPNLTSS),
                6 => out.set_opcode(opcode::CMPNLESS),
                7 => out.set_opcode(opcode::CMPORDSS),
                _ => {}
            },
            opcode::VCMPSS => match imm {
                0x00 => out.set_opcode(opcode::VCMPEQSS),
                0x01 => out.set_opcode(opcode::VCMPLTSS),
                0x02 => out.set_opcode(opcode::VCMPLESS),
                0x03 => out.set_opcode(opcode::VCMPUNORDSS),
                0x04 => out.set_opcode(opcode::VCMPNEQSS),
                0x05 => out.set_opcode(opcode::VCMPNLTSS),
                0x06 => out.set_opcode(opcode::VCMPNLESS),
                0x07 => out.set_opcode(opcode::VCMPORDSS),
                0x08 => out.set_opcode(opcode::VCMPEQ_UQSS),
                0x09 => out.set_opcode(opcode::VCMPNGESS),
                0x0a => out.set_opcode(opcode::VCMPNGTSS),
                0x0b => out.set_opcode(opcode::VCMPFALSESS),
                0x0c => out.set_opcode(opcode::VCMPNEQ_OQSS),
                0x0d => out.set_opcode(opcode::VCMPGESS),
                0x0e => out.set_opcode(opcode::VCMPGTSS),
                0x0f => out.set_opcode(opcode::VCMPTRUESS),
                0x10 => out.set_opcode(opcode::VCMPEQ_OSSS),
                0x11 => out.set_opcode(opcode::VCMPLT_OQSS),
                0x12 => out.set_opcode(opcode::VCMPLE_OQSS),
                0x13 => out.set_opcode(opcode::VCMPUNORD_SSS),
                0x14 => out.set_opcode(opcode::VCMPNEQ_USSS),
                0x15 => out.set_opcode(opcode::VCMPNLT_UQSS),
                0x16 => out.set_opcode(opcode::VCMPNLE_UQSS),
                0x17 => out.set_opcode(opcode::VCMPORD_SSS),
                0x18 => out.set_opcode(opcode::VCMPEQ_USSS),
                0x19 => out.set_opcode(opcode::VCMPNGE_UQSS),
                0x1a => out.set_opcode(opcode::VCMPNGT_UQSS),
                0x1b => out.set_opcode(opcode::VCMPFALSE_OSSS),
                0x1c => out.set_opcode(opcode::VCMPNEQ_OSSS),
                0x1d => out.set_opcode(opcode::VCMPGE_OQSS),
                0x1e => out.set_opcode(opcode::VCMPGT_OQSS),
                0x1f => out.set_opcode(opcode::VCMPTRUE_USSS),
                _ => {}
            },
            opcode::CMPSD => match imm {
                0 => out.set_opcode(opcode::CMPEQSD),
                1 => out.set_opcode(opcode::CMPLTSD),
                2 => out.set_opcode(opcode::CMPLESD),
                3 => out.set_opcode(opcode::CMPUNORDSD),
                4 => out.set_opcode(opcode::CMPNEQSD),
                5 => out.set_opcode(opcode::CMPNLTSD),
                6 => out.set_opcode(opcode::CMPNLESD),
                7 => out.set_opcode(opcode::CMPORDSD),
                _ => {}
            },
            opcode::VCMPSD => match imm {
                0x00 => out.set_opcode(opcode::VCMPEQSD),
                0x01 => out.set_opcode(opcode::VCMPLTSD),
                0x02 => out.set_opcode(opcode::VCMPLESD),
                0x03 => out.set_opcode(opcode::VCMPUNORDSD),
                0x04 => out.set_opcode(opcode::VCMPNEQSD),
                0x05 => out.set_opcode(opcode::VCMPNLTSD),
                0x06 => out.set_opcode(opcode::VCMPNLESD),
                0x07 => out.set_opcode(opcode::VCMPORDSD),
                0x08 => out.set_opcode(opcode::VCMPEQ_UQSD),
                0x09 => out.set_opcode(opcode::VCMPNGESD),
                0x0a => out.set_opcode(opcode::VCMPNGTSD),
                0x0b => out.set_opcode(opcode::VCMPFALSESD),
                0x0c => out.set_opcode(opcode::VCMPNEQ_OQSD),
                0x0d => out.set_opcode(opcode::VCMPGESD),
                0x0e => out.set_opcode(opcode::VCMPGTSD),
                0x0f => out.set_opcode(opcode::VCMPTRUESD),
                0x10 => out.set_opcode(opcode::VCMPEQ_OSSD),
                0x11 => out.set_opcode(opcode::VCMPLT_OQSD),
                0x12 => out.set_opcode(opcode::VCMPLE_OQSD),
                0x13 => out.set_opcode(opcode::VCMPUNORD_SSD),
                0x14 => out.set_opcode(opcode::VCMPNEQ_USSD),
                0x15 => out.set_opcode(opcode::VCMPNLT_UQSD),
                0x16 => out.set_opcode(opcode::VCMPNLE_UQSD),
                0x17 => out.set_opcode(opcode::VCMPORD_SSD),
                0x18 => out.set_opcode(opcode::VCMPEQ_USSD),
                0x19 => out.set_opcode(opcode::VCMPNGE_UQSD),
                0x1a => out.set_opcode(opcode::VCMPNGT_UQSD),
                0x1b => out.set_opcode(opcode::VCMPFALSE_OSSD),
                0x1c => out.set_opcode(opcode::VCMPNEQ_OSSD),
                0x1d => out.set_opcode(opcode::VCMPGE_OQSD),
                0x1e => out.set_opcode(opcode::VCMPGT_OQSD),
                0x1f => out.set_opcode(opcode::VCMPTRUE_USSD),
                _ => {}
            },
            opcode::CMPPS => match imm {
                0 => out.set_opcode(opcode::CMPEQPS),
                1 => out.set_opcode(opcode::CMPLTPS),
                2 => out.set_opcode(opcode::CMPLEPS),
                3 => out.set_opcode(opcode::CMPUNORDPS),
                4 => out.set_opcode(opcode::CMPNEQPS),
                5 => out.set_opcode(opcode::CMPNLTPS),
                6 => out.set_opcode(opcode::CMPNLEPS),
                7 => out.set_opcode(opcode::CMPORDPS),
                _ => {}
            },
            opcode::VCMPPS => match imm {
                0x00 => out.set_opcode(opcode::VCMPEQPS),
                0x01 => out.set_opcode(opcode::VCMPLTPS),
                0x02 => out.set_opcode(opcode::VCMPLEPS),
                0x03 => out.set_opcode(opcode::VCMPUNORDPS),
                0x04 => out.set_opcode(opcode::VCMPNEQPS),
                0x05 => out.set_opcode(opcode::VCMPNLTPS),
                0x06 => out.set_opcode(opcode::VCMPNLEPS),
                0x07 => out.set_opcode(opcode::VCMPORDPS),
                0x08 => out.set_opcode(opcode::VCMPEQ_UQPS),
                0x09 => out.set_opcode(opcode::VCMPNGEPS),
                0x0a => out.set_opcode(opcode::VCMPNGTPS),
                0x0b => out.set_opcode(opcode::VCMPFALSEPS),
                0x0c => out.set_opcode(opcode::VCMPNEQ_OQPS),
                0x0d => out.set_opcode(opcode::VCMPGEPS),
                0x0e => out.set_opcode(opcode::VCMPGTPS),
                0x0f => out.set_opcode(opcode::VCMPTRUEPS),
                0x10 => out.set_opcode(opcode::VCMPEQ_OSPS),
                0x11 => out.set_opcode(opcode::VCMPLT_OQPS),
                0x12 => out.set_opcode(opcode::VCMPLE_OQPS),
                0x13 => out.set_opcode(opcode::VCMPUNORD_SPS),
                0x14 => out.set_opcode(opcode::VCMPNEQ_USPS),
                0x15 => out.set_opcode(opcode::VCMPNLT_UQPS),
                0x16 => out.set_opcode(opcode::VCMPNLE_UQPS),
                0x17 => out.set_opcode(opcode::VCMPORD_SPS),
                0x18 => out.set_opcode(opcode::VCMPEQ_USPS),
                0x19 => out.set_opcode(opcode::VCMPNGE_UQPS),
                0x1a => out.set_opcode(opcode::VCMPNGT_UQPS),
                0x1b => out.set_opcode(opcode::VCMPFALSE_OSPS),
                0x1c => out.set_opcode(opcode::VCMPNEQ_OSPS),
                0x1d => out.set_opcode(opcode::VCMPGE_OQPS),
                0x1e => out.set_opcode(opcode::VCMPGT_OQPS),
                0x1f => out.set_opcode(opcode::VCMPTRUE_USPS),
                _ => {}
            },
            opcode::CMPPD => match imm {
                0 => out.set_opcode(opcode::CMPEQPD),
                1 => out.set_opcode(opcode::CMPLTPD),
                2 => out.set_opcode(opcode::CMPLEPD),
                3 => out.set_opcode(opcode::CMPUNORDPD),
                4 => out.set_opcode(opcode::CMPNEQPD),
                5 => out.set_opcode(opcode::CMPNLTPD),
                6 => out.set_opcode(opcode::CMPNLEPD),
                7 => out.set_opcode(opcode::CMPORDPD),
                _ => {}
            },
            opcode::VCMPPD => match imm {
                0x00 => out.set_opcode(opcode::VCMPEQPD),
                0x01 => out.set_opcode(opcode::VCMPLTPD),
                0x02 => out.set_opcode(opcode::VCMPLEPD),
                0x03 => out.set_opcode(opcode::VCMPUNORDPD),
                0x04 => out.set_opcode(opcode::VCMPNEQPD),
                0x05 => out.set_opcode(opcode::VCMPNLTPD),
                0x06 => out.set_opcode(opcode::VCMPNLEPD),
                0x07 => out.set_opcode(opcode::VCMPORDPD),
                0x08 => out.set_opcode(opcode::VCMPEQ_UQPD),
                0x09 => out.set_opcode(opcode::VCMPNGEPD),
                0x0a => out.set_opcode(opcode::VCMPNGTPD),
                0x0b => out.set_opcode(opcode::VCMPFALSEPD),
                0x0c => out.set_opcode(opcode::VCMPNEQ_OQPD),
                0x0d => out.set_opcode(opcode::VCMPGEPD),
                0x0e => out.set_opcode(opcode::VCMPGTPD),
                0x0f => out.set_opcode(opcode::VCMPTRUEPD),
                0x10 => out.set_opcode(opcode::VCMPEQ_OSPD),
                0x11 => out.set_opcode(opcode::VCMPLT_OQPD),
                0x12 => out.set_opcode(opcode::VCMPLE_OQPD),
                0x13 => out.set_opcode(opcode::VCMPUNORD_SPD),
                0x14 => out.set_opcode(opcode::VCMPNEQ_USPD),
                0x15 => out.set_opcode(opcode::VCMPNLT_UQPD),
                0x16 => out.set_opcode(opcode::VCMPNLE_UQPD),
                0x17 => out.set_opcode(opcode::VCMPORD_SPD),
                0x18 => out.set_opcode(opcode::VCMPEQ_USPD),
                0x19 => out.set_opcode(opcode::VCMPNGE_UQPD),
                0x1a => out.set_opcode(opcode::VCMPNGT_UQPD),
                0x1b => out.set_opcode(opcode::VCMPFALSE_OSPD),
                0x1c => out.set_opcode(opcode::VCMPNEQ_OSPD),
                0x1d => out.set_opcode(opcode::VCMPGE_OQPD),
                0x1e => out.set_opcode(opcode::VCMPGT_OQPD),
                0x1f => out.set_opcode(opcode::VCMPTRUE_USPD),
                _ => {}
            },
            opcode::VPCMPUD => match imm {
                0 => out.set_opcode(opcode::VPCMPEQUD),
                1 => out.set_opcode(opcode::VPCMPLTUD),
                2 => out.set_opcode(opcode::VPCMPLEUD),
                4 => out.set_opcode(opcode::VPCMPNEQUD),
                5 => out.set_opcode(opcode::VPCMPNLTUD),
                6 => out.set_opcode(opcode::VPCMPNLEUD),
                _ => {}
            },
            opcode::VPCMPD => match imm {
                0 => out.set_opcode(opcode::VPCMPEQD),
                1 => out.set_opcode(opcode::VPCMPLTD),
                2 => out.set_opcode(opcode::VPCMPLED),
                4 => out.set_opcode(opcode::VPCMPNEQD),
                5 => out.set_opcode(opcode::VPCMPNLTD),
                6 => out.set_opcode(opcode::VPCMPNLED),
                _ => {}
            },
            opcode::VPCMPUB => match imm {
                0 => out.set_opcode(opcode::VPCMPEQUB),
                1 => out.set_opcode(opcode::VPCMPLTUB),
                2 => out.set_opcode(opcode::VPCMPLEUB),
                4 => out.set_opcode(opcode::VPCMPNEQUB),
                5 => out.set_opcode(opcode::VPCMPNLTUB),
                6 => out.set_opcode(opcode::VPCMPNLEUB),
                _ => {}
            },
            opcode::VPCMPB => match imm {
                0 => out.set_opcode(opcode::VPCMPEQB),
                1 => out.set_opcode(opcode::VPCMPLTB),
                2 => out.set_opcode(opcode::VPCMPLEB),
                4 => out.set_opcode(opcode::VPCMPNEQB),
                5 => out.set_opcode(opcode::VPCMPNLTB),
                6 => out.set_opcode(opcode::VPCMPNLEB),
                _ => {}
            },
            opcode::VPCMPUW => match imm {
                0 => out.set_opcode(opcode::VPCMPEQUW),
                1 => out.set_opcode(opcode::VPCMPLTUW),
                2 => out.set_opcode(opcode::VPCMPLEUW),
                4 => out.set_opcode(opcode::VPCMPNEQUW),
                5 => out.set_opcode(opcode::VPCMPNLTUW),
                6 => out.set_opcode(opcode::VPCMPNLEUW),
                _ => {}
            },
            opcode::VPCMPW => match imm {
                0 => out.set_opcode(opcode::VPCMPEQW),
                1 => out.set_opcode(opcode::VPCMPLTW),
                2 => out.set_opcode(opcode::VPCMPLEW),
                4 => out.set_opcode(opcode::VPCMPNEQW),
                5 => out.set_opcode(opcode::VPCMPNLTW),
                6 => out.set_opcode(opcode::VPCMPNLEW),
                _ => {}
            },
            opcode::VPCMPUQ => match imm {
                0 => out.set_opcode(opcode::VPCMPEQUQ),
                1 => out.set_opcode(opcode::VPCMPLTUQ),
                2 => out.set_opcode(opcode::VPCMPLEUQ),
                4 => out.set_opcode(opcode::VPCMPNEQUQ),
                5 => out.set_opcode(opcode::VPCMPNLTUQ),
                6 => out.set_opcode(opcode::VPCMPNLEUQ),
                _ => {}
            },
            opcode::VPCMPQ => match imm {
                0 => out.set_opcode(opcode::VPCMPEQQ),
                1 => out.set_opcode(opcode::VPCMPLTQ),
                2 => out.set_opcode(opcode::VPCMPLEQ),
                4 => out.set_opcode(opcode::VPCMPNEQQ),
                5 => out.set_opcode(opcode::VPCMPNLTQ),
                6 => out.set_opcode(opcode::VPCMPNLEQ),
                _ => {}
            },
            opcode::PCLMULQDQ => match imm {
                0x00 => out.set_opcode(opcode::PCLMULLQLQDQ),
                0x01 => out.set_opcode(opcode::PCLMULHQLQDQ),
                0x10 => out.set_opcode(opcode::PCLMULLQHQDQ),
                0x11 => out.set_opcode(opcode::PCLMULHQHQDQ),
                _ => {}
            },
            opcode::VPCLMULQDQ => match imm {
                0x00 => out.set_opcode(opcode::VPCLMULLQLQDQ),
                0x01 => out.set_opcode(opcode::VPCLMULHQLQDQ),
                0x10 => out.set_opcode(opcode::VPCLMULLQHQDQ),
                0x11 => out.set_opcode(opcode::VPCLMULHQHQDQ),
                _ => {}
            },
            opcode::VCMPPH => match imm {
                0x00 => out.set_opcode(opcode::VCMPEQPH),
                0x01 => out.set_opcode(opcode::VCMPLTPH),
                0x02 => out.set_opcode(opcode::VCMPLEPH),
                0x03 => out.set_opcode(opcode::VCMPUNORDPH),
                0x04 => out.set_opcode(opcode::VCMPNEQPH),
                0x05 => out.set_opcode(opcode::VCMPNLTPH),
                0x06 => out.set_opcode(opcode::VCMPNLEPH),
                0x07 => out.set_opcode(opcode::VCMPORDPH),
                0x08 => out.set_opcode(opcode::VCMPEQ_UQPH),
                0x09 => out.set_opcode(opcode::VCMPNGEPH),
                0x0a => out.set_opcode(opcode::VCMPNGTPH),
                0x0b => out.set_opcode(opcode::VCMPFALSEPH),
                0x0c => out.set_opcode(opcode::VCMPNEQ_OQPH),
                0x0d => out.set_opcode(opcode::VCMPGEPH),
                0x0e => out.set_opcode(opcode::VCMPGTPH),
                0x0f => out.set_opcode(opcode::VCMPTRUEPH),
                0x10 => out.set_opcode(opcode::VCMPEQ_OSPH),
                0x11 => out.set_opcode(opcode::VCMPLT_OQPH),
                0x12 => out.set_opcode(opcode::VCMPLE_OQPH),
                0x13 => out.set_opcode(opcode::VCMPUNORD_SPH),
                0x14 => out.set_opcode(opcode::VCMPNEQ_USPH),
                0x15 => out.set_opcode(opcode::VCMPNLT_UQPH),
                0x16 => out.set_opcode(opcode::VCMPNLE_UQPH),
                0x17 => out.set_opcode(opcode::VCMPORD_SPH),
                0x18 => out.set_opcode(opcode::VCMPEQ_USPH),
                0x19 => out.set_opcode(opcode::VCMPNGE_UQPH),
                0x1a => out.set_opcode(opcode::VCMPNGT_UQPH),
                0x1b => out.set_opcode(opcode::VCMPFALSE_OSPH),
                0x1c => out.set_opcode(opcode::VCMPNEQ_OSPH),
                0x1d => out.set_opcode(opcode::VCMPGE_OQPH),
                0x1e => out.set_opcode(opcode::VCMPGT_OQPH),
                0x1f => out.set_opcode(opcode::VCMPTRUE_USPH),
                _ => {}
            },
            opcode::VCMPSH => match imm {
                0x00 => out.set_opcode(opcode::VCMPEQSH),
                0x01 => out.set_opcode(opcode::VCMPLTSH),
                0x02 => out.set_opcode(opcode::VCMPLESH),
                0x03 => out.set_opcode(opcode::VCMPUNORDSH),
                0x04 => out.set_opcode(opcode::VCMPNEQSH),
                0x05 => out.set_opcode(opcode::VCMPNLTSH),
                0x06 => out.set_opcode(opcode::VCMPNLESH),
                0x07 => out.set_opcode(opcode::VCMPORDSH),
                0x08 => out.set_opcode(opcode::VCMPEQ_UQSH),
                0x09 => out.set_opcode(opcode::VCMPNGESH),
                0x0a => out.set_opcode(opcode::VCMPNGTSH),
                0x0b => out.set_opcode(opcode::VCMPFALSESH),
                0x0c => out.set_opcode(opcode::VCMPNEQ_OQSH),
                0x0d => out.set_opcode(opcode::VCMPGESH),
                0x0e => out.set_opcode(opcode::VCMPGTSH),
                0x0f => out.set_opcode(opcode::VCMPTRUESH),
                0x10 => out.set_opcode(opcode::VCMPEQ_OSSH),
                0x11 => out.set_opcode(opcode::VCMPLT_OQSH),
                0x12 => out.set_opcode(opcode::VCMPLE_OQSH),
                0x13 => out.set_opcode(opcode::VCMPUNORD_SSH),
                0x14 => out.set_opcode(opcode::VCMPNEQ_USSH),
                0x15 => out.set_opcode(opcode::VCMPNLT_UQSH),
                0x16 => out.set_opcode(opcode::VCMPNLE_UQSH),
                0x17 => out.set_opcode(opcode::VCMPORD_SSH),
                0x18 => out.set_opcode(opcode::VCMPEQ_USSH),
                0x19 => out.set_opcode(opcode::VCMPNGE_UQSH),
                0x1a => out.set_opcode(opcode::VCMPNGT_UQSH),
                0x1b => out.set_opcode(opcode::VCMPFALSE_OSSH),
                0x1c => out.set_opcode(opcode::VCMPNEQ_OSSH),
                0x1d => out.set_opcode(opcode::VCMPGE_OQSH),
                0x1e => out.set_opcode(opcode::VCMPGT_OQSH),
                0x1f => out.set_opcode(opcode::VCMPTRUE_USSH),
                _ => {}
            },
            _ => {}
        }
        if opcode == out.opcode() {
            out.push_uimm(imm);
        }
        Ok(())
    }
}

macro_rules! impl_cond_ext {
    ($($func:ident = $name:ident),* $(,)?) => {
        $(fn $func(&self) -> bool {
            self.opts_arch.ext.$name
        })*
    }
}

impl X86Decode for Inner<'_> {
    fn need_more(&self, size: usize) -> Self::Error {
        Error::More(size - INSN_FIXED_SIZE)
    }

    fn fail(&self) -> Self::Error {
        Error::Failed(0)
    }

    fn advance(&mut self, count: usize) {
        self.bytes.advance((count - INSN_FIXED_SIZE) / 8)
    }

    fn cond_att(&self) -> bool {
        self.opts_arch.att
    }

    fn cond_alias(&self) -> bool {
        self.opts.alias
    }

    fn cond_prefix_67(&self) -> bool {
        self.prefix_67 != 0
    }

    impl_cond_ext! {
        cond_x87 = x87,
        cond_rtm = rtm,

        cond_i386 = i386,
        cond_amd64 = amd64,
    }
}

impl X86Decode0f for Inner<'_> {
    fn need_more(&self, size: usize) -> Self::Error {
        Error::More(size - INSN_FIXED_SIZE)
    }

    fn fail(&self) -> Self::Error {
        Error::Failed(0)
    }

    fn advance(&mut self, count: usize) {
        self.bytes.advance((count - INSN_FIXED_SIZE) / 8)
    }

    fn cond_att(&self) -> bool {
        self.opts_arch.att
    }

    impl_cond_ext! {
        cond_bmi = bmi,
        cond_cet_ibt = cet_ibt,
        cond_cet_ss = cet_ss,
        cond_cmov = cmov,
        cond_cmpxchg16b = cmpxchg16b,
        cond_cmpxchg8b = cmpxchg8b,
        cond_cpuid = cpuid,
        cond_fsgsbase = fsgsbase,
        cond_lzcnt = lzcnt,
        cond_mcommit = mcommit,
        cond_mmx = mmx,
        cond_monitorx = monitorx,
        cond_mpx = mpx,
        cond_popcnt = popcnt,
        cond_rdpid = rdpid,
        cond_rdrand = rdrand,
        cond_rdseed = rdseed,
        cond_rdtscp = rdtscp,
        cond_rtm = rtm,
        cond_serialize = serialize,
        cond_smap = smap,
        cond_sse = sse,
        cond_sse2 = sse2,
        cond_sse3 = sse3,
        cond_tsc = tsc,
        cond_uintr = uintr,
        cond_waitpkg = waitpkg,
        cond_wbnoinvd = wbnoinvd,
        cond_x87 = x87,

        cond_amd64 = amd64,
    }

    fn cond_rtm_or_hle(&self) -> bool {
        X86Decode0f::cond_rtm(self) || self.opts_arch.ext.hle
    }

    fn cond_ospke(&self) -> bool {
        true
    }
}

impl X86Decode0f38 for Inner<'_> {
    fn fail(&self) -> Self::Error {
        Error::Failed(0)
    }

    impl_cond_ext! {
        cond_ssse3 = ssse3,
        cond_sse4_1 = sse4_1,
        cond_sse4_2 = sse4_2,
        cond_aes = aes,
        cond_aeskle = aeskle,
        cond_adx = adx,
        cond_movbe = movbe,
        cond_cet_ss = cet_ss,
        cond_sha = sha,
        cond_gfni = gfni,
    }
}

impl X86Decode0f3a for Inner<'_> {
    fn fail(&self) -> Self::Error {
        Error::Failed(0)
    }

    impl_cond_ext! {
        cond_sse3 = sse3,
        cond_sse4_1 = sse4_1,
        cond_sse4_2 = sse4_2,
        cond_aes = aes,
        cond_pclmulqdq = pclmulqdq,
        cond_sha = sha,
        cond_gfni = gfni,
    }
}

impl X86DecodeVex for Inner<'_> {
    fn fail(&self) -> Self::Error {
        Error::Failed(0)
    }

    impl_cond_ext! {
        cond_avx = avx,
        cond_avx2 = avx2,
        cond_avx_vnni = avx_vnni,
        cond_avx512f = avx512f,
        cond_avx512bw = avx512bw,
        cond_avx512dq = avx512dq,
        cond_fma = fma,
        cond_fma4 = fma4,
        cond_bmi = bmi,
        cond_bmi2 = bmi2,
        cond_aes = aes,
        cond_vaes = vaes,
        cond_vpclmulqdq = vpclmulqdq,
        cond_f16c = f16c,
        cond_gfni = gfni,
    }

    fn cond_aes_or_vaes(&self) -> bool {
        self.opts_arch.ext.aes || self.opts_arch.ext.vaes
    }

    fn ex_reg(&self, value: i32) -> i32 {
        value ^ 0x08
    }

    fn ex_base(&self, value: i32) -> i32 {
        value ^ 0x18
    }

    fn ex_mm_v(&self, value: i32) -> i32 {
        value ^ 0x0f
    }

    fn ex_k_v(&self, value: i32) -> i32 {
        value ^ 0x07
    }
}

impl X86DecodeEvex for Inner<'_> {
    fn fail(&self) -> Self::Error {
        Error::Failed(0)
    }

    #[inline(always)]
    fn cond_mask(&self) -> bool {
        self.operand_mask.is_some()
    }

    impl_cond_ext! {
        cond_avx512f = avx512f,
        cond_avx512bw = avx512bw,
        cond_avx512dq = avx512dq,
        cond_avx512cd = avx512cd,
        cond_avx512fp16 = avx512fp16,
        cond_avx512bf16 = avx512bf16,
        cond_avx512_vbmi = avx512_vbmi,
        cond_avx512_vbmi2 = avx512_vbmi2,
        cond_avx512_vnni = avx512_vnni,
        cond_avx512_ifma = avx512_ifma,
        cond_avx512_bitalg = avx512_bitalg,
        cond_avx512_vpopcntdq = avx512_vpopcntdq,
        cond_vaes = vaes,
        cond_vpclmulqdq = vpclmulqdq,
        cond_gfni = gfni,
    }

    fn cond_avx512vl(&self) -> bool {
        // TODO: only for xmm and ymm, but with respect to {er}
        // maybe need to separate conditions
        self.opts_arch.ext.avx512vl
    }

    fn ex_reg(&self, value: i32) -> i32 {
        value ^ 0x08
    }

    fn ex_base(&self, value: i32) -> i32 {
        value ^ 0x18
    }

    fn ex_mm_v(&self, value: i32) -> i32 {
        value ^ 0x1f
    }
}

pub struct Decoder {
    opts: disasm_core::Options,
    opts_arch: Options,
}

impl Decoder {
    pub fn new(opts: &disasm_core::Options, opts_arch: &Options) -> Self {
        Self {
            opts: *opts,
            opts_arch: *opts_arch,
        }
    }
}

impl ArchDecoder for Decoder {
    fn decode(&mut self, address: u64, bytes: &[u8], out: &mut Bundle) -> Result<usize, Error> {
        Inner {
            opts: &self.opts,
            opts_arch: &self.opts_arch,
            bytes: Bytes::new(bytes),
            address,
            state: State::default(),
        }
        .decode(out)
    }
}

fn sign_extend(value: u64, from: usize, to: usize) -> u64 {
    let shift = 64 - from;
    ((((value << shift) as i64) >> shift) as u64) & (!0 >> (64 - to))
}

#[cfg(feature = "mnemonic")]
fn mnemonic(insn: &Insn, amd64: bool, att: bool) -> Option<(&'static str, &'static str)> {
    let opcode = insn.opcode();
    let s = if att {
        match opcode {
            opcode::CBW => "cbtw",
            opcode::CWDE => "cwtl",
            opcode::CDQE => "cltq",
            opcode::CWD => "cwtd",
            opcode::CDQ => "cltd",
            opcode::CQO => "cqto",
            opcode::MOVSXD => "movslq",
            opcode::PUSHF if amd64 => "pushfq",
            opcode::POPF if amd64 => "popfq",
            opcode::PUSHA => "pushad",
            opcode::POPA => "popad",
            opcode::RETF => "lretl",
            _ => self::opcode::mnemonic(opcode)?,
        }
    } else {
        self::opcode::mnemonic(opcode)?
    };
    Some((s, ""))
}
