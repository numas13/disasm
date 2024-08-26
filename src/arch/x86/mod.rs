mod generated;

#[cfg(feature = "print")]
mod printer;

use core::ops::{Deref, DerefMut};

use crate::{
    bytes::Bytes, flags::Field, utils::zextract, Access, Bundle, Error, Insn, Operand, OperandKind,
    Reg, RegClass,
};

use self::generated::*;

pub use self::generated::opcode;

const GPR_MASK: u64 = 15;

const INSN_MIN: usize = 1;
const INSN_MAX: usize = 15;

#[cfg(feature = "print")]
pub(crate) use self::printer::printer;

type Result<T = (), E = Error> = core::result::Result<T, E>;

const INSN_FIELD_SUFFIX: Field = Field::new(16, 3);
const INSN_FIELD_REP: Field = Field::new(19, 2);
const INSN_FIELD_SEGMENT: Field = Field::new(21, 3);
const INSN_REX_W: u32 = 1 << 27;
const INSN_ADDR32: u32 = 1 << 28;
const INSN_DATA16: u32 = 1 << 29;
const INSN_LOCK: u32 = 1 << 30;
const INSN_SUFFIX: u32 = 1 << 31;

const INSN_REP_NONE: u32 = 0;
const INSN_REP: u32 = 1;
const INSN_REPZ: u32 = 2;
const INSN_REPNZ: u32 = 3;

const SEGMENT_NONE: u32 = 0;
const SEGMENT_CS: u32 = 1;
const SEGMENT_DS: u32 = 2;
const SEGMENT_SS: u32 = 3;
const SEGMENT_ES: u32 = 4;
const SEGMENT_FS: u32 = 5;
const SEGMENT_GS: u32 = 6;

const OP_INDIRECT: u32 = 8;

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

const NONE: Reg = Reg::new(RegClass::INT, 0x1000);
const RIP: Reg = Reg::new(RegClass::INT, 0x1001);

const OP_ST: u64 = 0;
const OP_STI: u64 = 1;
const OP_SAE: u64 = 2;
const OP_ER_SAE: u64 = 3;

const OP_FIELD_MEM: Field = Field::new(16, 4);
const OP_FIELD_BCST: Field = Field::new(20, 3);
const OP_FIELD_SEGMENT: Field = Field::new(23, 3);

const SIZE_NONE: u8 = 0;
const SIZE_BYTE: u8 = 1;
const SIZE_WORD: u8 = 2;
const SIZE_DWORD: u8 = 3;
const SIZE_QWORD: u8 = 4;
const SIZE_OWORD: u8 = 5;
const SIZE_XMMWORD: u8 = 6;
const SIZE_YMMWORD: u8 = 7;
const SIZE_ZMMWORD: u8 = 8;
const SIZE_TBYTE: u8 = 9;
const SIZE_FWORD_48: u8 = 10;
const SIZE_FWORD_80: u8 = 11;

const BROADCAST_NONE: u8 = 0;
const BROADCAST_1TO2: u8 = 1;
const BROADCAST_1TO4: u8 = 2;
const BROADCAST_1TO8: u8 = 3;
const BROADCAST_1TO16: u8 = 4;
const BROADCAST_1TO32: u8 = 5;

const OP_BCST_FORCE: u32 = 1 << 30;
const OP_NO_PTR: u32 = 1 << 31;

const OPCODE_MAP_0F: u8 = 0x01;
const OPCODE_MAP_0F_38: u8 = 0x02;
const OPCODE_MAP_0F_3A: u8 = 0x03;

const SUFFIX_B: u32 = 0;
const SUFFIX_W: u32 = 1;
const SUFFIX_L: u32 = 2;
const SUFFIX_Q: u32 = 3;

const FIXED_PREFIX: usize = 2;

const REG_CLASS_K: RegClass = RegClass::arch(0);
const REG_CLASS_K_MASK: RegClass = RegClass::arch(1);
const REG_CLASS_BND: RegClass = RegClass::arch(2);
const REG_CLASS_SEGMENT: RegClass = RegClass::arch(3);

const PP_NONE: u8 = 0b00;
const PP_66: u8 = 0b01;
const PP_F3: u8 = 0b10;
const PP_F2: u8 = 0b11;

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
            Self::None => SIZE_NONE,
            Self::Byte => SIZE_BYTE,
            Self::Word => SIZE_WORD,
            Self::Long => SIZE_DWORD,
            Self::Quad => SIZE_QWORD,
            Self::Octo => SIZE_OWORD,
            Self::Mm => SIZE_QWORD,
            Self::Xmm => SIZE_XMMWORD,
            Self::Ymm => SIZE_YMMWORD,
            Self::Zmm => SIZE_ZMMWORD,
            Self::Tbyte => SIZE_TBYTE,
            Self::Far48 => SIZE_FWORD_48,
            Self::Far80 => SIZE_FWORD_80,
        }
    }

    fn op_size_vec(&self, access: MemAccess) -> u8 {
        match (self, access) {
            (Self::Byte, MemAccess::Tuple2) => SIZE_WORD,
            (Self::Byte, MemAccess::Tuple4) => SIZE_DWORD,
            (Self::Byte, MemAccess::Tuple8) => SIZE_QWORD,
            (Self::Word, MemAccess::Tuple2) => SIZE_DWORD,
            (Self::Word, MemAccess::Tuple4) => SIZE_QWORD,
            (Self::Word, MemAccess::Tuple8) => SIZE_XMMWORD,
            (Self::Long, MemAccess::Tuple2) => SIZE_QWORD,
            (Self::Long, MemAccess::Tuple4) => SIZE_XMMWORD,
            (Self::Long, MemAccess::Tuple8) => SIZE_YMMWORD,
            (Self::Quad, MemAccess::Tuple2) => SIZE_XMMWORD,
            (Self::Quad, MemAccess::Tuple4) => SIZE_YMMWORD,
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
        debug_assert!(index < 16);
        let class = match self {
            Self::Byte if rex => 1,
            Self::Byte => 0,
            Self::Word => 2,
            Self::Long => 3,
            Self::Quad => 4,
            _ => unreachable!(),
        };
        ((class as u64) << 4) | (index as u64)
    }

    fn decode_gpr(reg: u64) -> (Size, bool, usize) {
        let (size, rex) = match reg >> 4 {
            0 => (Self::Byte, false),
            1 => (Self::Byte, true),
            2 => (Self::Word, false),
            3 => (Self::Long, false),
            4 => (Self::Quad, false),
            _ => unreachable!(),
        };
        (size, rex, reg as usize & 15)
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
        self.push_arch_spec(OP_ST, 0, 0);
    }

    fn push_sti(&mut self, value: u64) {
        self.push_arch_spec(OP_STI, value, 0);
    }
}

#[derive(Copy, Clone, Default)]
struct RawInsn {
    raw: [u8; 8],
}

impl RawInsn {
    fn set_opcode_map(&mut self, map: u8) {
        self.raw[0] |= map;
    }

    fn set_66(&mut self) {
        self.raw[1] |= 0x10;
    }

    fn set_f2(&mut self) {
        self.raw[1] |= 0x20;
    }

    fn set_f3(&mut self) {
        self.raw[1] |= 0x40;
    }

    fn set_pp(&mut self, pp: u8) {
        self.raw[1] &= 0x8c;
        self.raw[1] |= pp;
        self.raw[1] |= match pp & 3 {
            PP_NONE => 0x00,
            PP_66 => 0x10, // prefix 66
            PP_F2 => 0x20, // prefix f2
            PP_F3 => 0x40, // prefix f3
            _ => unreachable!(),
        };
    }

    fn set_w(&mut self, cond: bool) {
        if cond {
            self.raw[1] |= 0x80;
        }
    }

    fn append<const N: usize, const S: usize>(&mut self, slice: [u8; N]) {
        self.raw[S..S + N].copy_from_slice(&slice);
    }

    fn as_u64(&self) -> u64 {
        u64::from_le_bytes(self.raw)
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
}

#[derive(Default)]
struct State {
    // internal instruction format
    raw: RawInsn,

    no_ptr: bool,
    has_gpr: bool,
    need_suffix: bool,

    // prefix counters
    prefix_66: u8,
    prefix_67: u8,

    // lock prefix
    lock: bool,

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

    addr_size: Size,
    mem_size: Size,
    reg_size: Size,
    vl: u8,
    vec_size: Size,
    mem_size_override: bool,
    mem_access: MemAccess,

    operand_mask: Option<Operand>,

    segment: u32,
    indirect: bool,
}

struct Inner<'a> {
    opts: &'a crate::Options,
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
    fn is_att(&self) -> bool {
        self.opts_arch.att
    }

    fn operand_size(&self, value: i32) -> usize {
        match value.abs() {
            1 => core::cmp::max(self.mem_size.bits(), self.reg_size.bits()),
            2 => self.addr_size.bits(),
            3 if self.w => 64,
            3 => 32,
            4 if self.cond_amd64() && self.prefix_66 > 0 => 32,
            4 if self.cond_amd64() => 64,
            4 if self.prefix_66 > 0 => 16,
            4 => 32,
            s => s as usize,
        }
    }

    fn set_gpr_size(&mut self, size: Size) {
        self.mem_size = size;
        self.reg_size = size;
    }

    fn set_w(&mut self) {
        self.w = true;
        self.set_gpr_size(Size::Quad);
    }

    fn set_rex(&mut self, rex: u8) {
        self.rex = true;
        if rex & 8 != 0 {
            self.set_w();
            self.raw.set_w(true);
        }
        self.raw.raw[0] |= (rex & 7) << 5;
    }

    fn set_vl(&mut self, vl: u8) -> Result<()> {
        self.vl = vl;
        self.vec_size = match vl {
            0 => Size::Xmm,
            1 => Size::Ymm,
            _ => Size::Zmm,
        };
        Ok(())
    }

    fn set_vex(&mut self, vex: [u8; 4]) -> Result<()> {
        if vex[2] & 0x80 != 0 {
            self.set_w();
        }
        self.set_vl(zextract(vex[2], 2, 1))?;

        self.raw.raw[0] = vex[1];
        self.raw.raw[1] = vex[2];
        self.raw.raw[2] = vex[3];

        Ok(())
    }

    fn set_evex(&mut self, evex: [u8; 6]) -> Result<()> {
        self.evex = true;
        if evex[2] & 0x80 != 0 {
            self.set_w();
        }
        self.set_vl(zextract(evex[3], 5, 2))?;

        self.broadcast = evex[3] & 0x10 != 0;

        let mask = (zextract(evex[3], 7, 1) << 3) | zextract(evex[3], 0, 3);
        if mask & 7 != 0 {
            let mask = Reg::new(REG_CLASS_K_MASK, mask.into()).read();
            self.operand_mask = Some(Operand::reg(mask));
        }

        self.raw.raw[0] = evex[1];
        self.raw.raw[1] = evex[2];
        self.raw.raw[2] = evex[3];
        self.raw.raw[3] = evex[4];
        self.raw.raw[4] = evex[5];

        Ok(())
    }

    fn imm_size(&self, value: i32) -> usize {
        match value {
            0 => unreachable!("size must not be zero"),
            1 => 8 << self.mem_size.suffix(),
            2 if self.w => 32,
            2 => 8 << self.mem_size.suffix(),
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
            MemAccess::Fixed1 => match self.mem_size {
                Size::Long => offset *= 4,
                Size::Quad => offset *= 8,
                _ => unreachable!(),
            },
            MemAccess::Fixed2 => offset *= 2,
            MemAccess::Tuple1 => match self.mem_size {
                Size::Word => offset *= 2,
                _ if self.w => offset *= 8,
                _ => offset *= 4,
            },
            MemAccess::Tuple2 => match self.mem_size {
                Size::Long if !self.w => offset *= 8,
                Size::Quad if self.w => offset *= 16,
                Size::Xmm => offset *= 16,
                _ => unreachable!("{:?}", self.mem_size),
            },
            MemAccess::Tuple4 => match self.mem_size {
                Size::Long if !self.w => offset *= 16,
                Size::Quad if self.w => offset *= 32,
                Size::Xmm => offset *= 16,
                Size::Ymm => offset *= 32,
                _ => unreachable!("{:?}", self.mem_size),
            },
            MemAccess::Tuple8 => match self.mem_size {
                Size::Long if !self.w => offset *= 32,
                Size::Ymm => offset *= 32,
                _ => unreachable!("{:?}", self.mem_size),
            },
        }
        offset
    }

    fn decode_mem(
        &mut self,
        out: &mut Insn,
        base: u8,
        size: u8,
        vector: bool,
    ) -> Result<Option<Operand>, Error> {
        if self.mode == MODE_REGISTER_DIRECT {
            return Ok(None);
        }
        let rm = base & 7;
        let kind = if self.mode == 0 && rm == 5 {
            if self.cond_amd64() {
                OperandKind::Relative(RIP, self.bytes.read_i32()? as i64)
            } else {
                OperandKind::Absolute(self.bytes.read_u32()? as u64)
            }
        } else {
            let sib = if rm == 4 {
                Some(self.bytes.read_u8()?)
            } else {
                None
            };
            let mut offset = match self.mode {
                1 if vector || self.mem_access != MemAccess::Full => {
                    let offset = self.bytes.read_i8()? as i32;
                    Some(self.evex_disp8(out, offset))
                }
                1 => Some(self.bytes.read_i8()? as i32),
                2 => Some(self.bytes.read_i32()?),
                _ => None,
            };
            if let Some(sib) = sib {
                let index = ((base >> 1) & 8) | zextract(sib, 3, 3);
                let index = Reg::new(RegClass::INT, self.addr_size.encode_gpr(index, self.rex));
                let base = (base & 8) | zextract(sib, 0, 3);
                let mut base = Reg::new(RegClass::INT, self.addr_size.encode_gpr(base, self.rex));
                if self.mode == 0 && (base.index() & GPR_MASK) == 5 {
                    offset = Some(self.bytes.read_i32()?);
                    base = NONE;
                }
                if (index.index() & GPR_MASK) == 4 {
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
                    self.addr_size.encode_gpr(base & 15, self.rex),
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
        if self.segment != SEGMENT_NONE && self.segment != SEGMENT_CS {
            flags.field_set(OP_FIELD_SEGMENT, self.segment);
            self.segment = 0;
        }
        flags
            .set_if(OP_NO_PTR, self.no_ptr)
            .field_set(OP_FIELD_MEM, size as u32);
        self.need_suffix = true;
        Ok(Some(op))
    }

    fn decode(&mut self, out: &mut Bundle) -> Result<usize> {
        self.mode = MODE_REGISTER_DIRECT;
        self.addr_size = if self.cond_amd64() {
            Size::Quad
        } else {
            Size::Long
        };
        self.mem_size = Size::Long;
        self.reg_size = Size::Long;

        let mut pp = PP_NONE;

        // collect legacy prefixes
        while let Some(byte) = self.bytes.peek_u8() {
            match byte {
                PREFIX_OPERAND_SIZE => {
                    self.mem_size = Size::Word;
                    self.reg_size = Size::Word;
                    self.prefix_66 += 1;
                    self.raw.set_66();
                    pp = PP_66;
                }
                PREFIX_ADDRESS_SIZE => {
                    self.addr_size = if self.cond_amd64() {
                        Size::Long
                    } else {
                        Size::Word
                    };
                    self.prefix_67 += 1;
                }
                PREFIX_LOCK => {
                    self.lock = true;
                }
                PREFIX_REPZ => {
                    self.repeat = Repeat::RepZ;
                    self.raw.set_f3();
                    pp = PP_F3;
                }
                PREFIX_REPNZ => {
                    self.repeat = Repeat::RepNZ;
                    self.raw.set_f2();
                    pp = PP_F2;
                }
                PREFIX_CS => self.segment = SEGMENT_CS,
                PREFIX_ES => self.segment = SEGMENT_ES,
                PREFIX_SS => self.segment = SEGMENT_SS,
                PREFIX_DS => self.segment = SEGMENT_DS,
                PREFIX_FS => self.segment = SEGMENT_FS,
                PREFIX_GS => self.segment = SEGMENT_GS,
                _ => break,
            }

            self.bytes.advance(1);

            if self.bytes.offset() >= INSN_MAX {
                return Err(Error::Failed(INSN_MAX * 8));
            }
        }

        out.clear();
        let insn = out.peek();

        self.bytes
            .peek_u8()
            .ok_or(Error::More(8))
            .and_then(|byte| match byte {
                0x62 if self.cond_amd64() => {
                    let evex = self.bytes.read_array::<6>()?;
                    self.set_evex(evex)?;
                    X86DecodeEvex::decode(self, self.raw.as_u64(), insn)
                }
                0xc4 | 0xc5 => {
                    let vex = if byte == 0xc4 {
                        self.bytes.read_array::<4>()?
                    } else {
                        let vex = self.bytes.read_array::<3>()?;
                        [0xc4, (vex[1] & 0x80) | 0x61, vex[1] & 0x7f, vex[2]]
                    };
                    self.set_vex(vex)?;
                    // vzeroupper and vzeroall do not use modrm
                    if vex[3] != 0b01110111 {
                        self.raw.raw[3] = self.bytes.read_u8()?;
                    }
                    X86DecodeVex::decode(self, self.raw.as_u64(), insn)
                }
                _ => {
                    if byte & PREFIX_REX_MASK == PREFIX_REX && self.cond_amd64() {
                        self.bytes.advance(1);
                        self.set_rex(byte);
                    }

                    if let (_, [0x0f, byte]) = self.bytes.peek_array::<2>() {
                        let (count, opcode) = match byte {
                            0x38 => (2, OPCODE_MAP_0F_38),
                            0x3a => (2, OPCODE_MAP_0F_3A),
                            _ => (1, OPCODE_MAP_0F),
                        };
                        self.bytes.advance(count);
                        self.raw.set_pp(pp);
                        self.raw.set_opcode_map(opcode);
                    }

                    let (len, arr) = self.bytes.peek_array();
                    self.raw.append::<FIXED_PREFIX, 2>(arr);
                    let raw = self.raw.as_u64();
                    X86Decode::decode(self, raw, (FIXED_PREFIX + len) * 8, insn)
                }
            })
            .map_err(|err| match err {
                Error::Failed(_) => Error::Failed((self.bytes.offset() + 1) * 8),
                Error::More(bits) => Error::More(self.bytes.offset() * 8 + bits),
            })?;

        // TODO: HLE
        insn.flags_mut()
            .set_if(INSN_LOCK, self.lock)
            .set_if(INSN_DATA16, self.prefix_66 > 1)
            .set_if(
                INSN_ADDR32,
                self.prefix_67 > 0 && self.mode == MODE_REGISTER_DIRECT,
            )
            .field_set_if(INSN_FIELD_SEGMENT, self.segment, self.segment != 0);

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

            2 => self.addr_size,

            3 if self.w => Size::Quad,
            3 => Size::Long,

            4 if self.cond_amd64() => Size::Quad,
            4 if self.prefix_66 > 0 => Size::Word,
            4 => Size::Long,

            5 if self.cond_amd64() => Size::Quad,
            5 => Size::Long,

            6 if self.cond_amd64() => {
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

    fn vec_size(&self, value: i32) -> Result<Size> {
        Ok(match value {
            64 => Size::Mm,
            128 => Size::Xmm,
            256 => Size::Ymm,
            512 => Size::Zmm,
            _ => return Err(Error::Failed(0)),
        })
    }

    fn set_gpr_reg(&mut self, out: &mut Insn, index: i32, access: Access, rsz: i32) -> Result {
        self.reg_size = self.gpr_size(rsz);
        let reg = Reg::new(
            RegClass::INT,
            self.reg_size.encode_gpr(index as u8, self.rex),
        )
        .access(access);
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
        mode: i32,
        msz: i32,
    ) -> Result {
        self.mode = mode as u8;
        self.set_mem_size(msz);
        let index = index as u8;
        let mut op = self
            .decode_mem(out, index, self.mem_size.op_size(), false)?
            .unwrap_or_else(|| {
                let size = if bsz != 0 {
                    self.gpr_size(bsz)
                } else {
                    self.mem_size
                };
                let reg = Reg::new(RegClass::INT, size.encode_gpr(index & 15, self.rex));
                self.has_gpr = true;
                Operand::reg(reg.access(access))
            });
        op.flags_mut().set_if(OP_INDIRECT, self.indirect);
        out.push_operand(op);
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
        mode: i32,
        mem_size: i32,
    ) -> Result<Operand> {
        self.mode = mode as u8;
        match mem_size {
            0 => {}
            1 => self.mem_size = size,
            _ => {
                self.mem_size = self.gpr_size(mem_size);
                self.mem_size_override = true;
            }
        }
        let mem_size = if self.broadcast && self.broadcast_size != 0 {
            match self.broadcast_size {
                4 => SIZE_WORD,
                5 => SIZE_DWORD,
                6 => SIZE_QWORD,
                _ => unreachable!(),
            }
        } else if self.mem_size_override {
            self.mem_size.op_size_vec(self.mem_access)
        } else {
            size.op_size_vec(self.mem_access)
        };
        let mut index = value as u8;
        let mut operand = self
            .decode_mem(out, index, mem_size, true)?
            .map(|mut operand| {
                if self.broadcast && self.broadcast_size != 0 {
                    let bcst = match size.bits() >> self.broadcast_size as usize {
                        2 => BROADCAST_1TO2,
                        4 => BROADCAST_1TO4,
                        8 => BROADCAST_1TO8,
                        16 => BROADCAST_1TO16,
                        32 => BROADCAST_1TO32,
                        _ => unreachable!(),
                    };
                    operand
                        .flags_mut()
                        .field_set(OP_FIELD_BCST, bcst as u32)
                        .set_if(OP_BCST_FORCE, self.broadcast_force);
                }
                operand
            })
            .unwrap_or_else(|| {
                if !self.evex {
                    // NOTE: index[5] is X (raw[0][6]), but it is used only in EVEX
                    index &= 15;
                }
                let reg = Reg::new(RegClass::VECTOR, size.encode_vec(index));
                Operand::reg(reg.access(access))
            });
        operand.flags_mut().set_if(OP_INDIRECT, self.indirect);
        Ok(operand)
    }

    fn set_vec_mem(
        &mut self,
        out: &mut Insn,
        value: i32,
        size: Size,
        access: Access,
        mode: i32,
        mem_size: i32,
    ) -> Result {
        let operand = self.set_vec_mem_impl(out, value, size, access, mode, mem_size)?;
        self.push_operand_with_mask(out, operand);
        Ok(())
    }

    fn get_sae(&self, mode: i32) -> Option<Operand> {
        if self.broadcast && mode == MODE_REGISTER_DIRECT as i32 {
            Some(Operand::arch(OP_SAE, self.vl as u64, 0))
        } else {
            None
        }
    }

    fn get_er_sae(&self, mode: i32) -> Option<Operand> {
        if self.broadcast && mode == MODE_REGISTER_DIRECT as i32 {
            Some(Operand::arch(OP_ER_SAE, self.vl as u64, 0))
        } else {
            None
        }
    }

    fn get_sae_zmm(&mut self, mode: i32) -> Option<Operand> {
        self.get_sae(mode).map(|i| {
            self.vec_size = Size::Zmm;
            i
        })
    }

    fn get_er_sae_zmm(&mut self, mode: i32) -> Option<Operand> {
        self.get_er_sae(mode).map(|i| {
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

    fn set_evex_rm_vv(
        &mut self,
        out: &mut Insn,
        args: args_evex_rm_vv,
        rsz: Size,
        bsz: Size,
    ) -> Result {
        let rw = access_from_mask(args.rw);
        self.set_bcst(args.bcst);
        self.set_vec_reg(out, args.r, rsz, rw)?;
        self.set_vec_mem(out, args.b, bsz, Access::Read, args.mode, args.msz)?;
        Ok(())
    }

    fn set_evex_rm_rv(&mut self, out: &mut Insn, args: args_evex_rm_rv, size: Size) -> Result {
        let rw = access_from_mask(args.rw);
        self.set_gpr_reg(out, args.r, rw, args.rsz)?;
        self.set_vec_mem(out, args.b, size, Access::Read, args.mode, args.msz)?;
        Ok(())
    }

    fn set_evex_rm_vr(&mut self, out: &mut Insn, args: args_evex_rm_vr, size: Size) -> Result {
        let rw = access_from_mask(args.rw);
        self.set_vec_reg(out, args.r, size, rw)?;
        self.set_gpr_mem(out, args.b, args.bsz, Access::Read, args.mode, args.msz)?;
        Ok(())
    }

    fn set_evex_mr_vv(
        &mut self,
        out: &mut Insn,
        args: args_evex_rm_vv,
        bsz: Size,
        rsz: Size,
    ) -> Result {
        let rw = access_from_mask(args.rw);
        self.set_bcst(args.bcst);
        self.set_vec_mem(out, args.b, bsz, rw, args.mode, args.msz)?;
        self.set_vec_reg(out, args.r, rsz, Access::Read)?;
        Ok(())
    }

    fn set_evex_mr_rv(&mut self, out: &mut Insn, args: args_evex_mr_rv, size: Size) -> Result {
        let rw = access_from_mask(args.rw);
        self.set_gpr_mem(out, args.b, args.bsz, rw, args.mode, args.msz)?;
        self.set_vec_reg(out, args.r, size, Access::Read)?;
        Ok(())
    }

    fn set_evex_rvm_vvv(
        &mut self,
        out: &mut Insn,
        args: args_evex_rvm_vvv,
        rsz: Size,
        vsz: Size,
        bsz: Size,
    ) -> Result {
        let rw = access_from_mask(args.rw);
        self.set_bcst(args.bcst);
        self.set_vec_reg(out, args.r, rsz, rw)?;
        self.set_vec_reg(out, args.v, vsz, Access::Read)?;
        self.set_vec_mem(out, args.b, bsz, Access::Read, args.mode, args.msz)?;
        Ok(())
    }

    fn set_evex_fma_vvv(&mut self, out: &mut Insn, args: args_evex_rvm_vvv, size: Size) -> Result {
        let rw = access_from_mask(args.rw);
        self.set_bcst(args.bcst);
        self.set_vec_reg(out, args.r, size, rw)?;
        self.set_vec_reg(out, args.v, size, Access::Read)?;
        self.set_vec_mem(out, args.b, size, Access::Read, args.mode, args.msz)?;
        Ok(())
    }

    fn set_fma4_vvv(&mut self, out: &mut Insn, args: args_evex_rvm_vvv, size: Size) -> Result {
        let rw = access_from_mask(args.rw);
        self.set_vec_reg(out, args.r, size, rw)?;
        self.set_vec_reg(out, args.v, size, Access::Read)?;
        self.set_vec_mem(out, args.b, size, Access::Read, args.mode, args.msz)?;
        self.set_vec_is4(out, 1, size, Access::Read)?;
        Ok(())
    }

    fn set_fma4a_vvv(&mut self, out: &mut Insn, args: args_evex_rvm_vvv, size: Size) -> Result {
        let rw = access_from_mask(args.rw);
        self.set_vec_reg(out, args.r, size, rw)?;
        self.set_vec_reg(out, args.v, size, Access::Read)?;
        let mem = self.set_vec_mem_impl(out, args.b, size, Access::Read, args.mode, args.msz)?;
        self.set_vec_is4(out, 1, size, Access::Read)?;
        self.push_operand_with_mask(out, mem);
        Ok(())
    }

    fn set_evex_rvm_vvr(&mut self, out: &mut Insn, args: args_evex_rvm_vvr, size: Size) -> Result {
        let rw = access_from_mask(args.rw);
        self.set_vec_reg(out, args.r, size, rw)?;
        self.set_vec_reg(out, args.v, size, Access::Read)?;
        self.set_gpr_mem(out, args.b, args.bsz, Access::Read, args.mode, args.msz)?;
        Ok(())
    }

    fn set_evex_mvr_vvv(
        &mut self,
        out: &mut Insn,
        args: args_evex_rvm_vvv,
        rsz: Size,
        vsz: Size,
        bsz: Size,
    ) -> Result {
        let rw = access_from_mask(args.rw);
        self.set_bcst(args.bcst);
        self.set_vec_mem(out, args.b, bsz, rw, args.mode, args.msz)?;
        self.set_vec_reg(out, args.v, vsz, Access::Read)?;
        self.set_vec_reg(out, args.r, rsz, Access::Read)?;
        Ok(())
    }

    fn set_evex_rm_kv(&mut self, out: &mut Insn, args: args_evex_rm_vv, size: Size) -> Result {
        let rw = access_from_mask(args.rw);
        self.set_bcst(args.bcst);
        self.set_k_reg(out, args.r, rw)?;
        self.set_vec_mem(out, args.b, size, Access::Read, args.mode, args.msz)?;
        Ok(())
    }

    fn set_evex_rm_vk(&mut self, out: &mut Insn, args: args_evex_rm_vv, size: Size) -> Result {
        let rw = access_from_mask(args.rw);
        self.set_vec_reg(out, args.r, size, rw)?;
        self.set_k_mem(out, args.b, Access::Read, args.mode, args.msz)?;
        Ok(())
    }

    fn set_evex_rvm_kvv(&mut self, out: &mut Insn, args: args_evex_rvm_vvv, size: Size) -> Result {
        let rw = access_from_mask(args.rw);
        self.set_bcst(args.bcst);
        self.set_k_reg(out, args.r, rw)?;
        self.set_vec_reg(out, args.v, size, Access::Read)?;
        self.set_vec_mem(out, args.b, size, Access::Read, args.mode, args.msz)?;
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
        let reg = Reg::new(REG_CLASS_K, value as u64);
        out.push_reg(reg.access(access));
        Ok(())
    }

    fn set_k_reg(&mut self, out: &mut Insn, value: i32, access: Access) -> Result {
        let reg = Reg::new(REG_CLASS_K, value as u64);
        let operand = Operand::reg(reg.access(access));
        self.push_operand_with_mask(out, operand);
        Ok(())
    }

    fn set_k_mem(
        &mut self,
        out: &mut Insn,
        value: i32,
        access: Access,
        mode: i32,
        msz: i32,
    ) -> Result {
        self.mode = mode as u8;
        self.set_mem_size(msz);
        let index = value as u8;
        let mut operand = self
            .decode_mem(out, index, SIZE_DWORD, false)?
            .unwrap_or_else(|| Operand::reg(Reg::new(REG_CLASS_K, value as u64).access(access)));
        operand
            .flags_mut()
            .field_set(OP_FIELD_MEM, self.mem_size.op_size() as u32);
        out.push_operand(operand);
        Ok(())
    }

    fn set_bnd_reg(&mut self, out: &mut Insn, value: i32, access: Access) -> Result {
        out.push_reg(Reg::new(REG_CLASS_BND, value as u64).access(access));
        Ok(())
    }

    fn set_mem_size(&mut self, msz: i32) {
        self.mem_size = self.gpr_size(msz);
        if msz != 1 {
            self.mem_size_override = true;
        }
    }

    fn set_evex_rm_qv(&mut self, out: &mut Insn, mut args: args_evex_rm_vv) -> Result {
        self.set_bcst(args.bcst);
        args.bcst = 0;
        self.broadcast_force = true;
        self.set_evex_rm_vv(out, args, Size::Xmm, self.vec_size)
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
            8 => SUFFIX_B,
            16 => SUFFIX_W,
            32 => SUFFIX_L,
            64 => SUFFIX_Q,
            _ => unreachable!("unexpected suffix for size {size} (value={value})"),
        };
        if self.opts_arch.suffix_always || (self.need_suffix && !self.has_gpr) || value < 0 {
            out.flags_mut()
                .field_set(INSN_FIELD_SUFFIX, suffix)
                .set(INSN_SUFFIX);
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
        out.flags_mut().set_if(INSN_REX_W, value != 0 && self.w);
        Ok(())
    }

    fn set_rep(&mut self, out: &mut Insn, value: i32) -> Result {
        if value != 0 {
            let rep = match self.repeat {
                Repeat::None => 0,
                Repeat::RepZ if value == 2 => INSN_REPZ,
                Repeat::RepZ => INSN_REP,
                Repeat::RepNZ => INSN_REPNZ,
            };
            out.flags_mut().field_set(INSN_FIELD_REP, rep);
        }
        Ok(())
    }

    fn set_indirect(&mut self, _: &mut Insn, value: i32) -> Result {
        self.indirect = value != 0;
        Ok(())
    }

    fn set_args_segment(&mut self, out: &mut Insn, args: args_segment) -> Result {
        assert!((0..6).contains(&args.seg));
        let reg = Reg::new(REG_CLASS_SEGMENT, args.seg as u64);
        out.push_reg(reg.access(access_from_mask(args.rw)));
        Ok(())
    }

    fn set_args_reg(&mut self, out: &mut Insn, args: args_reg) -> Result {
        let access = access_from_mask(args.rw);
        self.set_gpr_reg(out, args.reg, access, args.rsz)
    }

    fn set_args_reg_vec(&mut self, out: &mut Insn, args: args_reg_vec) -> Result {
        let size = self.vec_size(args.rsz)?;
        let access = access_from_mask(args.rw);
        self.set_vec_reg(out, args.reg, size, access)
    }

    fn set_args_xmm(&mut self, out: &mut Insn, args: args_reg_vec) -> Result {
        self.set_args_reg_vec(out, args)
    }

    fn set_args_mem(&mut self, out: &mut Insn, args: args_mem) -> Result {
        let access = access_from_mask(args.rw);
        self.set_gpr_mem(out, args.b, args.bsz, access, args.mode, args.msz)
    }

    fn set_args_m_m(&mut self, out: &mut Insn, args: args_mem_vec) -> Result {
        let access = access_from_mask(args.rw);
        self.set_vec_mem(out, args.b, Size::Mm, access, args.mode, args.msz)
    }

    fn set_args_m_x(&mut self, out: &mut Insn, args: args_mem_vec) -> Result {
        let access = access_from_mask(args.rw);
        self.set_vec_mem(out, args.b, Size::Xmm, access, args.mode, args.msz)
    }

    fn set_args_rvm_rrr(&mut self, out: &mut Insn, args: args_rvm_rrr) -> Result {
        self.set_gpr_reg(out, args.r, Access::Write, args.rsz)?;
        self.set_gpr_vvv(out, args.v, Access::Read, args.vsz)?;
        self.set_gpr_mem(out, args.b, args.bsz, Access::Read, args.mode, args.msz)?;
        Ok(())
    }

    fn set_args_rmv_rrr(&mut self, out: &mut Insn, args: args_rmv_rrr) -> Result {
        self.set_gpr_reg(out, args.r, Access::Write, args.rsz)?;
        self.set_gpr_mem(out, args.b, args.bsz, Access::Read, args.mode, args.msz)?;
        self.set_gpr_vvv(out, args.v, Access::Read, args.vsz)?;
        Ok(())
    }

    fn set_args_rm_mm(&mut self, out: &mut Insn, args: args_rm_mm) -> Result {
        let access = access_from_mask(args.rw);
        self.set_vec_reg(out, args.r, Size::Mm, access)?;
        self.set_vec_mem(out, args.b, Size::Mm, Access::Read, args.mode, args.msz)?;
        Ok(())
    }

    fn set_args_mr_mm(&mut self, out: &mut Insn, args: args_mr_mm) -> Result {
        let access = access_from_mask(args.rw);
        self.set_vec_mem(out, args.b, Size::Mm, access, args.mode, args.msz)?;
        self.set_vec_reg(out, args.r, Size::Mm, Access::Read)?;
        Ok(())
    }

    fn set_args_rm_rm(&mut self, out: &mut Insn, args: args_rm_rm) -> Result {
        let access = access_from_mask(args.rw);
        self.set_gpr_reg(out, args.r, access, args.rsz)?;
        self.set_vec_mem(out, args.b, Size::Mm, Access::Read, args.mode, args.msz)?;
        Ok(())
    }

    fn set_args_rm_mr(&mut self, out: &mut Insn, args: args_rm_mr) -> Result {
        let access = access_from_mask(args.rw);
        self.set_vec_reg(out, args.r, Size::Mm, access)?;
        self.set_gpr_mem(out, args.b, args.bsz, Access::Read, args.mode, args.msz)?;
        Ok(())
    }

    fn set_args_mr_rm(&mut self, out: &mut Insn, args: args_mr_rm) -> Result {
        let access = access_from_mask(args.rw);
        self.set_gpr_mem(out, args.b, args.bsz, access, args.mode, args.msz)?;
        self.set_vec_reg(out, args.r, Size::Mm, Access::Read)?;
        Ok(())
    }

    fn set_args_rm_xx(&mut self, out: &mut Insn, args: args_rm_xx) -> Result {
        let access = access_from_mask(args.rw);
        self.set_vec_reg(out, args.r, Size::Xmm, access)?;
        self.set_vec_mem(out, args.b, Size::Xmm, Access::Read, args.mode, args.msz)?;
        Ok(())
    }

    fn set_args_rm_xm(&mut self, out: &mut Insn, args: args_rm_xm) -> Result {
        let access = access_from_mask(args.rw);
        self.set_vec_reg(out, args.r, Size::Xmm, access)?;
        self.set_vec_mem(out, args.b, Size::Mm, Access::Read, args.mode, args.msz)?;
        Ok(())
    }

    fn set_args_rm_mx(&mut self, out: &mut Insn, args: args_rm_mx) -> Result {
        let access = access_from_mask(args.rw);
        self.set_vec_reg(out, args.r, Size::Mm, access)?;
        self.set_vec_mem(out, args.b, Size::Xmm, Access::Read, args.mode, args.msz)?;
        Ok(())
    }

    fn set_args_rm_xr(&mut self, out: &mut Insn, args: args_rm_xr) -> Result {
        let access = access_from_mask(args.rw);
        self.set_vec_reg(out, args.r, Size::Xmm, access)?;
        self.set_gpr_mem(out, args.b, args.bsz, Access::Read, args.mode, args.msz)?;
        Ok(())
    }

    fn set_args_mr_xx(&mut self, out: &mut Insn, args: args_mr_xx) -> Result {
        let access = access_from_mask(args.rw);
        self.set_vec_mem(out, args.b, Size::Xmm, access, args.mode, args.msz)?;
        self.set_vec_reg(out, args.r, Size::Xmm, Access::Read)?;
        Ok(())
    }

    fn set_args_rm_rx(&mut self, out: &mut Insn, args: args_rm_rx) -> Result {
        let access = access_from_mask(args.rw);
        self.set_gpr_reg(out, args.r, access, args.rsz)?;
        self.set_vec_mem(out, args.b, Size::Xmm, Access::Read, args.mode, args.msz)?;
        Ok(())
    }

    fn set_args_mr_rx(&mut self, out: &mut Insn, args: args_mr_rx) -> Result {
        let access = access_from_mask(args.rw);
        self.set_gpr_mem(out, args.b, args.bsz, access, args.mode, args.msz)?;
        self.set_vec_reg(out, args.r, Size::Xmm, Access::Read)?;
        Ok(())
    }

    fn set_args_evex_rm_vx(&mut self, out: &mut Insn, args: args_evex_rm_vv) -> Result {
        self.set_evex_rm_vv(out, args, self.vec_size, Size::Xmm)
    }

    fn set_args_evex_rm_vy(&mut self, out: &mut Insn, args: args_evex_rm_vv) -> Result {
        self.set_evex_rm_vv(out, args, self.vec_size, Size::Ymm)
    }

    fn set_args_rm_rr(&mut self, out: &mut Insn, args: args_rm_rr) -> Result {
        let access = access_from_mask(args.rw);
        self.set_gpr_reg(out, args.r, access, args.rsz)?;
        self.set_gpr_mem(out, args.b, args.bsz, Access::Read, args.mode, args.msz)
    }

    fn set_args_mr_rr(&mut self, out: &mut Insn, args: args_mr_rr) -> Result {
        let access = access_from_mask(args.rw);
        self.set_gpr_mem(out, args.b, args.bsz, access, args.mode, args.msz)?;
        self.set_gpr_reg(out, args.r, Access::Read, args.rsz)
    }

    fn set_args_evex_rm_hv(&mut self, out: &mut Insn, mut args: args_evex_rm_vv) -> Result {
        self.set_bcst(args.bcst);
        args.bcst = 0;
        let size = self.vec_reg_half();
        self.set_evex_rm_vv(out, args, size, self.vec_size)
    }

    fn set_args_evex_rm_hv_er(&mut self, out: &mut Insn, mut args: args_evex_rm_vv) -> Result {
        let er = self.get_er_sae_zmm(args.mode);
        self.set_bcst(args.bcst);
        args.bcst = 0;
        self.set_args_evex_rm_hv(out, args)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn set_args_evex_rm_qv_er(&mut self, out: &mut Insn, mut args: args_evex_rm_vv) -> Result {
        let er = self.get_er_sae_zmm(args.mode);
        self.set_bcst(args.bcst);
        args.bcst = 0;
        self.set_evex_rm_qv(out, args)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn set_args_evex_rm_vh_er(&mut self, out: &mut Insn, mut args: args_evex_rm_vv) -> Result {
        let er = self.get_er_sae_zmm(args.mode);
        self.set_bcst(args.bcst);
        args.bcst = 0;
        self.set_args_evex_rm_vh(out, args)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn set_args_evex_rm_vq_er(&mut self, out: &mut Insn, mut args: args_evex_rm_vv) -> Result {
        let er = self.get_er_sae_zmm(args.mode);
        self.set_bcst(args.bcst);
        args.bcst = 0;
        self.set_args_evex_rm_vq(out, args)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn set_args_evex_rm_hv_sae(&mut self, out: &mut Insn, mut args: args_evex_rm_vv) -> Result {
        let er = self.get_sae_zmm(args.mode);
        self.set_bcst(args.bcst);
        args.bcst = 0;
        self.set_args_evex_rm_hv(out, args)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn set_args_evex_rm_vq_sae(&mut self, out: &mut Insn, mut args: args_evex_rm_vv) -> Result {
        let er = self.get_sae_zmm(args.mode);
        self.set_bcst(args.bcst);
        args.bcst = 0;
        self.set_args_evex_rm_vq(out, args)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn set_args_evex_rm_vh(&mut self, out: &mut Insn, mut args: args_evex_rm_vv) -> Result {
        let (size, msz) = self.vec_mem_half();
        args.msz = msz;
        self.set_evex_rm_vv(out, args, self.vec_size, size)
    }

    fn set_args_evex_rm_vq(&mut self, out: &mut Insn, mut args: args_evex_rm_vv) -> Result {
        let (size, msz) = self.vec_mem_quarter();
        args.msz = msz;
        self.set_evex_rm_vv(out, args, self.vec_size, size)
    }

    fn set_args_evex_rm_ve(&mut self, out: &mut Insn, mut args: args_evex_rm_vv) -> Result {
        let (size, msz) = self.vec_mem_eighth();
        args.msz = msz;
        self.set_evex_rm_vv(out, args, self.vec_size, size)
    }

    fn set_args_evex_rm_vh_sae(&mut self, out: &mut Insn, mut args: args_evex_rm_vv) -> Result {
        let sae = self.get_sae_zmm(args.mode);
        self.set_bcst(args.bcst);
        args.bcst = 0;
        self.set_args_evex_rm_vh(out, args)?;
        out.push_operand_if_some(sae);
        Ok(())
    }

    fn set_args_evex_mr_hv(&mut self, out: &mut Insn, mut args: args_evex_rm_vv) -> Result {
        let (size, msz) = self.vec_mem_half();
        args.msz = msz;
        self.set_evex_mr_vv(out, args, size, self.vec_size)
    }

    fn set_args_evex_mr_hv_sae(&mut self, out: &mut Insn, mut args: args_evex_rm_vv) -> Result {
        let sae = self.get_sae_zmm(args.mode);
        let (size, msz) = self.vec_mem_half();
        args.msz = msz;
        self.set_evex_mr_vv(out, args, size, self.vec_size)?;
        out.push_operand_if_some(sae);
        Ok(())
    }

    fn set_args_evex_mr_qv(&mut self, out: &mut Insn, mut args: args_evex_rm_vv) -> Result {
        let (size, msz) = self.vec_mem_quarter();
        args.msz = msz;
        self.set_evex_mr_vv(out, args, size, self.vec_size)
    }

    fn set_args_evex_mr_ev(&mut self, out: &mut Insn, mut args: args_evex_rm_vv) -> Result {
        let (size, msz) = self.vec_mem_eighth();
        args.msz = msz;
        self.set_evex_mr_vv(out, args, size, self.vec_size)
    }

    fn set_args_evex_rm_xx(&mut self, out: &mut Insn, args: args_evex_rm_vv) -> Result {
        self.set_evex_rm_vv(out, args, Size::Xmm, Size::Xmm)
    }

    fn set_args_evex_rm_xy(&mut self, out: &mut Insn, args: args_evex_rm_vv) -> Result {
        self.set_evex_rm_vv(out, args, Size::Xmm, Size::Ymm)
    }

    fn set_args_evex_rm_yx(&mut self, out: &mut Insn, args: args_evex_rm_vv) -> Result {
        self.set_evex_rm_vv(out, args, Size::Ymm, Size::Xmm)
    }

    fn set_args_evex_rm_yy(&mut self, out: &mut Insn, args: args_evex_rm_vv) -> Result {
        self.set_evex_rm_vv(out, args, Size::Ymm, Size::Ymm)
    }

    fn set_args_evex_rm_zx(&mut self, out: &mut Insn, args: args_evex_rm_vv) -> Result {
        self.set_evex_rm_vv(out, args, Size::Zmm, Size::Xmm)
    }

    fn set_args_evex_rm_zy(&mut self, out: &mut Insn, args: args_evex_rm_vv) -> Result {
        self.set_evex_rm_vv(out, args, Size::Zmm, Size::Ymm)
    }

    fn set_args_evex_rm_xx_sae(&mut self, out: &mut Insn, args: args_evex_rm_vv) -> Result {
        let sae = self.get_sae(args.mode);
        self.set_evex_rm_vv(out, args, Size::Xmm, Size::Xmm)?;
        out.push_operand_if_some(sae);
        Ok(())
    }

    fn set_args_evex_rm_rx(&mut self, out: &mut Insn, args: args_evex_rm_rv) -> Result {
        self.set_evex_rm_rv(out, args, Size::Xmm)
    }

    fn set_args_evex_rm_rx_er(&mut self, out: &mut Insn, args: args_evex_rm_rv) -> Result {
        let er = self.get_er_sae(args.mode);
        self.set_args_evex_rm_rx(out, args)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn set_args_evex_rm_rx_sae(&mut self, out: &mut Insn, args: args_evex_rm_rv) -> Result {
        let sae = self.get_sae(args.mode);
        self.set_args_evex_rm_rx(out, args)?;
        out.push_operand_if_some(sae);
        Ok(())
    }

    fn set_args_evex_rm_ry(&mut self, out: &mut Insn, args: args_evex_rm_rv) -> Result {
        self.set_evex_rm_rv(out, args, Size::Ymm)
    }

    fn set_args_evex_rm_vr(&mut self, out: &mut Insn, args: args_evex_rm_vr) -> Result {
        self.set_evex_rm_vr(out, args, self.vec_size)
    }

    fn set_args_evex_rm_xr(&mut self, out: &mut Insn, args: args_evex_rm_vr) -> Result {
        self.set_evex_rm_vr(out, args, Size::Xmm)
    }

    fn set_args_evex_mr_xx(&mut self, out: &mut Insn, args: args_evex_rm_vv) -> Result {
        self.set_evex_mr_vv(out, args, Size::Xmm, Size::Xmm)
    }

    fn set_args_evex_mr_xy(&mut self, out: &mut Insn, args: args_evex_rm_vv) -> Result {
        self.set_evex_mr_vv(out, args, Size::Xmm, Size::Ymm)
    }

    fn set_args_evex_mr_xz(&mut self, out: &mut Insn, args: args_evex_rm_vv) -> Result {
        self.set_evex_mr_vv(out, args, Size::Xmm, Size::Zmm)
    }

    fn set_args_evex_mr_yy(&mut self, out: &mut Insn, args: args_evex_rm_vv) -> Result {
        self.set_evex_mr_vv(out, args, Size::Ymm, Size::Ymm)
    }

    fn set_args_evex_mr_yz(&mut self, out: &mut Insn, args: args_evex_rm_vv) -> Result {
        self.set_evex_mr_vv(out, args, Size::Ymm, Size::Zmm)
    }

    fn set_args_evex_mr_rx(&mut self, out: &mut Insn, args: args_evex_mr_rv) -> Result {
        self.set_evex_mr_rv(out, args, Size::Xmm)
    }

    fn set_args_evex_rvm_xxx(&mut self, out: &mut Insn, args: args_evex_rvm_vvv) -> Result {
        self.vec_size = Size::Xmm;
        self.set_args_evex_rvm_vvv(out, args)
    }

    fn set_args_evex_rvm_yyx(&mut self, out: &mut Insn, args: args_evex_rvm_vvv) -> Result {
        self.set_evex_rvm_vvv(out, args, Size::Ymm, Size::Ymm, Size::Xmm)
    }

    fn set_args_evex_rvm_yyy(&mut self, out: &mut Insn, args: args_evex_rvm_vvv) -> Result {
        self.set_evex_rvm_vvv(out, args, Size::Ymm, Size::Ymm, Size::Ymm)
    }

    fn set_args_evex_rvm_zzx(&mut self, out: &mut Insn, args: args_evex_rvm_vvv) -> Result {
        self.set_evex_rvm_vvv(out, args, Size::Zmm, Size::Zmm, Size::Xmm)
    }

    fn set_args_evex_rvm_zzy(&mut self, out: &mut Insn, args: args_evex_rvm_vvv) -> Result {
        self.set_evex_rvm_vvv(out, args, Size::Zmm, Size::Zmm, Size::Ymm)
    }

    fn set_args_evex_mvr_xxx(&mut self, out: &mut Insn, args: args_evex_rvm_vvv) -> Result {
        self.set_evex_mvr_vvv(out, args, Size::Xmm, Size::Xmm, Size::Xmm)
    }

    fn set_args_evex_mvr_yyy(&mut self, out: &mut Insn, args: args_evex_rvm_vvv) -> Result {
        self.set_evex_mvr_vvv(out, args, Size::Ymm, Size::Ymm, Size::Ymm)
    }

    fn set_args_evex_rvm_xxr(&mut self, out: &mut Insn, args: args_evex_rvm_vvr) -> Result {
        self.set_evex_rvm_vvr(out, args, Size::Xmm)
    }

    fn set_args_evex_rvm_xxr_er(&mut self, out: &mut Insn, args: args_evex_rvm_vvr) -> Result {
        let er = self.get_er_sae(args.mode);
        self.set_args_evex_rvm_xxr(out, args)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn set_args_evex_rm_kv(&mut self, out: &mut Insn, args: args_evex_rm_vv) -> Result {
        self.set_evex_rm_kv(out, args, self.vec_size)
    }

    fn set_args_evex_rm_kx(&mut self, out: &mut Insn, args: args_evex_rm_vv) -> Result {
        self.set_evex_rm_kv(out, args, Size::Xmm)
    }

    fn set_args_evex_rm_vk(&mut self, out: &mut Insn, args: args_evex_rm_vv) -> Result {
        self.set_evex_rm_vk(out, args, self.vec_size)
    }

    fn set_args_evex_rvm_kxx_sae(&mut self, out: &mut Insn, args: args_evex_rvm_vvv) -> Result {
        let er = self.get_sae(args.mode);
        self.set_evex_rvm_kvv(out, args, Size::Xmm)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn set_args_evex_rm_vv(&mut self, out: &mut Insn, args: args_evex_rm_vv) -> Result {
        self.set_evex_rm_vv(out, args, self.vec_size, self.vec_size)
    }

    fn set_args_evex_rm_vv_er(&mut self, out: &mut Insn, args: args_evex_rm_vv) -> Result {
        let er = self.get_er_sae_zmm(args.mode);
        self.set_bcst(args.bcst);
        self.set_evex_rm_vv(out, args, self.vec_size, self.vec_size)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn set_args_evex_rm_vv_sae(&mut self, out: &mut Insn, args: args_evex_rm_vv) -> Result {
        let er = self.get_sae_zmm(args.mode);
        self.set_bcst(args.bcst);
        self.set_evex_rm_vv(out, args, self.vec_size, self.vec_size)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn set_args_evex_mr_vv(&mut self, out: &mut Insn, args: args_evex_rm_vv) -> Result {
        self.set_evex_mr_vv(out, args, self.vec_size, self.vec_size)
    }

    fn set_args_evex_rvm_vvv(&mut self, out: &mut Insn, args: args_evex_rvm_vvv) -> Result {
        self.set_evex_rvm_vvv(out, args, self.vec_size, self.vec_size, self.vec_size)
    }

    fn set_args_evex_rvm_vvx_128(&mut self, out: &mut Insn, args: args_evex_rvm_vvv) -> Result {
        self.mem_access = MemAccess::Mem128;
        self.set_evex_rvm_vvv(out, args, self.vec_size, self.vec_size, Size::Xmm)
    }

    fn set_args_evex_rvm_vvv_er(&mut self, out: &mut Insn, args: args_evex_rvm_vvv) -> Result {
        let er = self.get_er_sae_zmm(args.mode);
        self.set_evex_rvm_vvv(out, args, self.vec_size, self.vec_size, self.vec_size)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn set_args_evex_rvm_vvv_sae(&mut self, out: &mut Insn, args: args_evex_rvm_vvv) -> Result {
        let er = self.get_sae_zmm(args.mode);
        self.set_evex_rvm_vvv(out, args, self.vec_size, self.vec_size, self.vec_size)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn set_args_evex_rvm_xxx_er(&mut self, out: &mut Insn, args: args_evex_rvm_vvv) -> Result {
        let er = self.get_er_sae(args.mode);
        self.set_evex_rvm_vvv(out, args, Size::Xmm, Size::Xmm, Size::Xmm)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn set_args_evex_rvm_xxx_sae(&mut self, out: &mut Insn, args: args_evex_rvm_vvv) -> Result {
        let sae = self.get_sae(args.mode);
        self.set_evex_rvm_vvv(out, args, Size::Xmm, Size::Xmm, Size::Xmm)?;
        out.push_operand_if_some(sae);
        Ok(())
    }

    fn set_args_evex_rvm_kvv(&mut self, out: &mut Insn, args: args_evex_rvm_vvv) -> Result {
        self.set_evex_rvm_kvv(out, args, self.vec_size)
    }

    fn set_args_evex_rvm_kvv_sae(&mut self, out: &mut Insn, args: args_evex_rvm_vvv) -> Result {
        let sae = self.get_sae_zmm(args.mode);
        self.set_evex_rvm_kvv(out, args, self.vec_size)?;
        out.push_operand_if_some(sae);
        Ok(())
    }

    fn set_args_fmadds_er(&mut self, out: &mut Insn, args: args_evex_rvm_vvv) -> Result {
        let er = self.get_er_sae(args.mode);
        self.set_vec_reg(out, args.r, Size::Xmm, Access::ReadWrite)?;
        self.set_vec_reg(out, args.v, Size::Xmm, Access::Read)?;
        self.set_vec_mem(out, args.b, Size::Xmm, Access::Read, args.mode, args.msz)?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn set_args_fmaddp(&mut self, out: &mut Insn, args: args_evex_rvm_vvv) -> Result {
        self.set_bcst(args.bcst);
        self.set_vec_reg(out, args.r, self.vec_size, Access::ReadWrite)?;
        self.set_vec_reg(out, args.v, self.vec_size, Access::Read)?;
        self.set_vec_mem(
            out,
            args.b,
            self.vec_size,
            Access::Read,
            args.mode,
            args.msz,
        )?;
        Ok(())
    }

    fn set_args_fmaddp_er(&mut self, out: &mut Insn, args: args_evex_rvm_vvv) -> Result {
        let er = self.get_er_sae_zmm(args.mode);
        self.set_bcst(args.bcst);
        self.set_vec_reg(out, args.r, self.vec_size, Access::ReadWrite)?;
        self.set_vec_reg(out, args.v, self.vec_size, Access::Read)?;
        self.set_vec_mem(
            out,
            args.b,
            self.vec_size,
            Access::Read,
            args.mode,
            args.msz,
        )?;
        out.push_operand_if_some(er);
        Ok(())
    }

    fn set_args_evex_fmax(&mut self, out: &mut Insn, args: args_evex_rvm_vvv) -> Result {
        self.set_evex_fma_vvv(out, args, Size::Xmm)
    }

    fn set_args_evex_fmay(&mut self, out: &mut Insn, args: args_evex_rvm_vvv) -> Result {
        self.set_evex_fma_vvv(out, args, Size::Ymm)
    }

    fn set_args_evex_fma4x(&mut self, out: &mut Insn, args: args_evex_rvm_vvv) -> Result {
        self.set_fma4_vvv(out, args, Size::Xmm)
    }

    fn set_args_evex_fma4y(&mut self, out: &mut Insn, args: args_evex_rvm_vvv) -> Result {
        self.set_fma4_vvv(out, args, Size::Ymm)
    }

    fn set_args_evex_fma4x2(&mut self, out: &mut Insn, args: args_evex_rvm_vvv) -> Result {
        self.set_fma4a_vvv(out, args, Size::Xmm)
    }

    fn set_args_evex_fma4y2(&mut self, out: &mut Insn, args: args_evex_rvm_vvv) -> Result {
        self.set_fma4a_vvv(out, args, Size::Ymm)
    }

    fn set_args_evex_rvm_kkk(&mut self, out: &mut Insn, args: args_evex_rvm_kkk) -> Result {
        let rw = access_from_mask(args.rw);
        self.set_k_reg(out, args.r, rw)?;
        self.set_k_vvv(out, args.v, Access::Read)?;
        self.set_k_mem(out, args.b, Access::Read, args.mode, args.msz)?;
        Ok(())
    }

    fn set_args_evex_mr_kk(&mut self, out: &mut Insn, args: args_evex_mr_kk) -> Result {
        let rw = access_from_mask(args.rw);
        self.set_k_mem(out, args.b, rw, args.mode, args.msz)?;
        self.set_k_reg(out, args.r, Access::Read)?;
        Ok(())
    }

    fn set_args_evex_rm_kk(&mut self, out: &mut Insn, args: args_evex_rm_kk) -> Result {
        let rw = access_from_mask(args.rw);
        self.set_k_reg(out, args.r, rw)?;
        self.set_k_mem(out, args.b, Access::Read, args.mode, args.msz)?;
        Ok(())
    }

    fn set_args_evex_rm_kr(&mut self, out: &mut Insn, args: args_evex_rm_kr) -> Result {
        let rw = access_from_mask(args.rw);
        self.set_k_reg(out, args.r, rw)?;
        self.set_gpr_mem(out, args.b, args.bsz, Access::Read, args.mode, args.msz)?;
        Ok(())
    }

    fn set_args_evex_rm_rk(&mut self, out: &mut Insn, args: args_evex_rm_rk) -> Result {
        let rw = access_from_mask(args.rw);
        self.set_gpr_reg(out, args.r, rw, args.rsz)?;
        self.set_k_mem(out, args.b, Access::Read, args.mode, args.msz)?;
        Ok(())
    }

    fn set_movs(&mut self, out: &mut Insn, msz: i32) -> Result {
        self.segment = SEGMENT_ES;
        self.set_gpr_mem(out, 7, msz, Access::Write, 0, msz)?;
        self.segment = SEGMENT_DS;
        self.set_gpr_mem(out, 6, msz, Access::Read, 0, msz)?;
        self.set_suffix(out, msz)?;
        Ok(())
    }

    fn set_cmps(&mut self, out: &mut Insn, msz: i32) -> Result {
        self.segment = SEGMENT_DS;
        self.set_gpr_mem(out, 6, msz, Access::Read, 0, msz)?;
        self.segment = SEGMENT_ES;
        self.set_gpr_mem(out, 7, msz, Access::Read, 0, msz)?;
        self.set_suffix(out, msz)?;
        Ok(())
    }

    fn set_stos(&mut self, out: &mut Insn, msz: i32) -> Result {
        self.segment = SEGMENT_ES;
        self.set_gpr_mem(out, 7, msz, Access::Write, 0, msz)?;
        self.set_gpr_reg(out, 0, Access::Read, msz)?;
        self.set_suffix(out, msz)?;
        Ok(())
    }

    fn set_lods(&mut self, out: &mut Insn, msz: i32) -> Result {
        self.set_gpr_reg(out, 0, Access::Write, msz)?;
        self.segment = SEGMENT_DS;
        self.set_gpr_mem(out, 6, msz, Access::Read, 0, msz)?;
        self.set_suffix(out, msz)?;
        Ok(())
    }

    fn set_scas(&mut self, out: &mut Insn, msz: i32) -> Result {
        self.set_gpr_reg(out, 0, Access::Read, msz)?;
        self.segment = SEGMENT_ES;
        self.set_gpr_mem(out, 7, msz, Access::Read, 0, msz)?;
        self.set_suffix(out, msz)?;
        Ok(())
    }

    fn set_args_mem_bnd(&mut self, out: &mut Insn, args: args_mem_bnd) -> Result {
        let access = access_from_mask(args.rw);
        self.set_bnd_reg(out, args.b, access)
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
        self.set_simm_impl(out, value, self.mem_size.bits())
    }

    fn set_simm32(&mut self, out: &mut Insn, value: i32) -> Result {
        self.set_simm_impl(out, value, 32)
    }

    fn set_simm64(&mut self, out: &mut Insn, value: i32) -> Result {
        self.set_simm_impl(out, value, 64)
    }

    fn set_rel(&mut self, out: &mut Insn, mut value: i32) -> Result {
        if value == 0 {
            value = 8 << self.mem_size.suffix();
        }
        let disp = match value {
            8 => self.bytes.read_u8()? as i8 as i64,
            16 => self.bytes.read_u16()? as i16 as i64,
            32 => self.bytes.read_u32()? as i32 as i64,
            64 => self.bytes.read_u64()? as i64,
            _ => unreachable!("unexpected relative offset size"),
        };

        let address = self
            .address
            .wrapping_add(self.bytes.offset() as u64)
            .wrapping_add(disp as u64);
        let mut operand = Operand::new(OperandKind::Absolute(address));
        operand.flags_mut().set(OP_NO_PTR);
        out.push_operand(operand);
        Ok(())
    }

    fn set_i(&mut self, out: &mut Insn, value: i32) -> Result {
        out.push_imm(value as i64);
        Ok(())
    }

    fn set_es(&mut self, _: &mut Insn, value: i32) -> Result {
        if value != 0 {
            self.segment = SEGMENT_ES;
        }
        Ok(())
    }

    fn set_ds(&mut self, _: &mut Insn, value: i32) -> Result {
        if value != 0 {
            self.segment = SEGMENT_DS;
        }
        Ok(())
    }

    fn set_vi_r(&mut self, out: &mut Insn, value: i32) -> Result {
        self.set_vec_is4(out, value, self.vec_size, Access::Read)
    }

    fn set_rb(&mut self, out: &mut Insn, value: i32) -> Result {
        out.push_reg(Reg::new(
            RegClass::INT,
            Size::Byte.encode_gpr(value as u8, self.rex),
        ));
        Ok(())
    }

    fn set_st_m(&mut self, out: &mut Insn, _: i32) -> Result {
        out.push_st();
        Ok(())
    }

    fn set_si_r(&mut self, out: &mut Insn, value: i32) -> Result {
        out.push_sti(value as u64);
        Ok(())
    }

    fn set_si_w(&mut self, out: &mut Insn, value: i32) -> Result {
        out.push_sti(value as u64);
        Ok(())
    }

    fn set_si_m(&mut self, out: &mut Insn, value: i32) -> Result {
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
    ($($func:ident = $name:ident),+$(,)?) => {
        $(fn $func(&self) -> bool {
            self.opts_arch.ext.$name
        })+
    }
}

impl X86Decode for Inner<'_> {
    fn need_more(&self, size: usize) -> Self::Error {
        Error::More(size - FIXED_PREFIX * 2)
    }

    fn fail(&self) -> Self::Error {
        Error::Failed(0)
    }

    fn advance(&mut self, count: usize) {
        self.bytes.advance(count / 8 - FIXED_PREFIX)
    }

    #[inline(always)]
    fn cond_never(&self) -> bool {
        false
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
        cond_cmov = cmov,
        cond_cmpxchg8b = cmpxchg8b,
        cond_cmpxchg16b = cmpxchg16b,
        cond_cpuid = cpuid,
        cond_mmx = mmx,
        cond_sse = sse,
        cond_sse2 = sse2,
        cond_sse3 = sse3,
        cond_ssse3 = ssse3,
        cond_sse4_1 = sse4_1,
        cond_sse4_2 = sse4_2,
        cond_aes = aes,
        cond_aeskle = aeskle,
        cond_adx = adx,
        cond_bmi = bmi,
        cond_mcommit = mcommit,
        cond_monitorx = monitorx,
        cond_movbe = movbe,
        cond_popcnt = popcnt,
        cond_lzcnt = lzcnt,
        cond_rtm = rtm,
        cond_tsc = tsc,
        cond_rdtscp = rdtscp,
        cond_cet_ss = cet_ss,
        cond_cet_ibt = cet_ibt,
        cond_mpx = mpx,
        cond_smap = smap,
        cond_pclmulqdq = pclmulqdq,
        cond_fsgsbase = fsgsbase,
        cond_rdpid = rdpid,
        cond_rdrand = rdrand,
        cond_rdseed = rdseed,
        cond_uintr = uintr,
        cond_serialize = serialize,
        cond_sha = sha,
        cond_waitpkg = waitpkg,
        cond_wbnoinvd = wbnoinvd,
        cond_gfni = gfni,

        cond_i386 = i386,
        cond_amd64 = amd64,
    }

    fn cond_rtm_or_hle(&self) -> bool {
        self.cond_rtm() || self.opts_arch.ext.hle
    }

    fn cond_ospke(&self) -> bool {
        true
    }
}

impl X86DecodeVex for Inner<'_> {
    fn fail(&self) -> Self::Error {
        Error::Failed(0)
    }

    #[inline(always)]
    fn cond_never(&self) -> bool {
        false
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
    fn cond_never(&self) -> bool {
        false
    }

    impl_cond_ext! {
        cond_avx512vl = avx512vl,
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

    fn ex_reg(&self, value: i32) -> i32 {
        value ^ 0x08
    }

    fn ex_base(&self, value: i32) -> i32 {
        value ^ 0x18
    }

    fn ex_mm_v(&self, value: i32) -> i32 {
        value ^ 0x1f
    }

    fn ex_vl(&self, value: i32) -> i32 {
        match value {
            0b00 => 128,
            0b01 => 256,
            0b10 => 512,
            0b11 => 1024,
            _ => unreachable!("unexpected vl={value}"),
        }
    }
}

struct Decoder {
    opts: crate::Options,
    opts_arch: Options,
}

impl Decoder {
    fn new(opts: crate::Options, opts_arch: Options) -> Self {
        Self { opts, opts_arch }
    }
}

impl super::Decoder for Decoder {
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

    fn insn_size_min(&self) -> u16 {
        INSN_MIN as u16
    }

    fn insn_size_max(&self) -> u16 {
        INSN_MAX as u16
    }

    #[cfg(feature = "mnemonic")]
    fn mnemonic(&self, insn: &Insn) -> Option<(&'static str, &'static str)> {
        let m = self::opcode::mnemonic(insn.opcode())?;
        Some((m, ""))
    }
}

fn access_from_mask(mask: i32) -> Access {
    match mask {
        1 => Access::Read,
        2 => Access::Write,
        3 => Access::ReadWrite,
        _ => unreachable!("unexpected access mask {mask:#x}"),
    }
}

fn sign_extend(value: u64, from: usize, to: usize) -> u64 {
    let shift = 64 - from;
    ((((value << shift) as i64) >> shift) as u64) & (!0 >> (64 - to))
}

pub(crate) fn decoder(opts: crate::Options, opts_arch: Options) -> Box<dyn crate::Decoder> {
    Box::new(Decoder::new(opts, opts_arch))
}
