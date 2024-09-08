#![allow(dead_code)]
#![allow(unused_variables)]

mod generated;
#[cfg(feature = "print")]
mod printer;

use core::{
    cmp,
    ops::{Deref, DerefMut},
};

use crate::{
    bytes::Bytes,
    utils::{zextract, ZExtract},
    Access, ArchDecoder, Bundle, Error, Insn, Reg, RegClass, Slot,
};

pub use self::generated::opcode;

use self::generated::{E2KDecodeAlop, SetValue};

#[cfg(feature = "print")]
pub(crate) use self::printer::printer;

// Instruction slots
pub const SLOT_ALC0: Slot = Slot::new(0);
pub const SLOT_ALC1: Slot = Slot::new(1);
pub const SLOT_ALC2: Slot = Slot::new(2);
pub const SLOT_ALC3: Slot = Slot::new(3);
pub const SLOT_ALC4: Slot = Slot::new(4);
pub const SLOT_ALC5: Slot = Slot::new(5);

pub const SLOT_APB0: Slot = Slot::new(6);
pub const SLOT_APB1: Slot = Slot::new(7);
pub const SLOT_APB2: Slot = Slot::new(8);
pub const SLOT_APB3: Slot = Slot::new(9);

pub const SLOT_PLU0: Slot = Slot::new(10);
pub const SLOT_PLU1: Slot = Slot::new(11);
pub const SLOT_PLU2: Slot = Slot::new(12);

// Custom shared instruction flags
pub const INSN_SM: u32 = 1 << 31;

// Custom instruction flags
pub const SETWD_X: u32 = 1 << 16;
pub const SETWD_Z: u32 = 1 << 17;
pub const SETWD_MCN: u32 = 1 << 18;

pub const ADVANCE_T: u32 = 1 << 16;
pub const ADVANCE_F: u32 = 1 << 17;

pub const MOVA_BE: u32 = 1 << 16;
pub const MOVA_AM: u32 = 1 << 17;

// Custom register classes
pub const REG_CLASS_PREG: RegClass = RegClass::arch(0);
pub const REG_CLASS_SREG: RegClass = RegClass::arch(1);
pub const REG_CLASS_CTPR: RegClass = RegClass::arch(2);
pub const REG_CLASS_AAD: RegClass = RegClass::arch(3);
pub const REG_CLASS_AASTI: RegClass = RegClass::arch(4);
pub const REG_CLASS_AAIND: RegClass = RegClass::arch(5);
pub const REG_CLASS_AAINCR: RegClass = RegClass::arch(6);
pub const REG_CLASS_PCNT: RegClass = RegClass::arch(7);
pub const REG_CLASS_IPR: RegClass = RegClass::arch(8);
pub const REG_CLASS_PRND: RegClass = RegClass::arch(9);

// Custom operands
pub const OP_LITERAL: u64 = 0;
pub const OP_EMPTY: u64 = 1;
pub const OP_UIMM: u64 = 2;
pub const OP_MAS: u64 = 3;
pub const OP_LCNTEX: u64 = 4;
pub const OP_SPRED: u64 = 5;
pub const OP_COND_START: u64 = 6;
pub const OP_WAIT: u64 = 7;
pub const OP_VFBG: u64 = 8;
pub const OP_IPD: u64 = 9;
pub const OP_NO_MRGC: u64 = 10;
pub const OP_PLU: u64 = 11;
pub const OP_FDAM: u64 = 12;
pub const OP_TRAR: u64 = 13;
pub const OP_LOOP_END: u64 = 14;
pub const OP_CT_COND: u64 = 15;
pub const OP_AREA: u64 = 16;

pub const PSRC_INVERT: u8 = 0x80;

// aaur{r,w} modes
const AAUR_MODE_AAD: i32 = 0;
const AAUR_MODE_AASTI: i32 = 1;
const AAUR_MODE_AAIND: i32 = 2;
const AAUR_MODE_AAINCR: i32 = 3;

// Values for SS.ct_cond
/// none
pub const CT_COND_NONE: u8 = 0;
/// unconditional
pub const CT_COND_ALWAYS: u8 = 1;
/// pN
pub const CT_COND_PREG: u8 = 2;
/// ~pN
pub const CT_COND_NOT_PREG: u8 = 3;
/// loop_end
pub const CT_COND_LOOP_END: u8 = 4;
/// ~loop_end
pub const CT_COND_NOT_LOOP_END: u8 = 5;
/// pN || loop_end
pub const CT_COND_PREG_OR_LOOP_END: u8 = 6;
/// ~pN && ~loop_end
pub const CT_COND_NOT_PREG_AND_NOT_LOOP_END: u8 = 7;
/// mlock
/// mlock || dt_al0134
pub const CT_COND_MLOCK_OR_DTAL: u8 = 8;
/// mlock || [~]cmpN
/// mlock || [~]cmpN || [~]cmpN
/// mlock || [~]clpN
pub const CT_COND_MLOCK_OR_CMP: u8 = 9;
/// {~}{cmp,clp}N
pub const CT_COND_CMP_CLP: u8 = 11;
/// ~pN || loop_end
pub const CT_COND_NOT_PREG_OR_LOOP_END: u8 = 14;
/// pN && ~loop_end
pub const CT_COND_PREG_AND_NOT_LOOP_END: u8 = 15;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Cluster {
    A,
    B,
}

trait InsnExt {
    fn push_literal(&mut self, literal: u64, size: u8);
    fn push_empty(&mut self);
    fn push_uimm_short<I: Into<u64>>(&mut self, uimm: I);
    fn push_mas(&mut self, mas: u8);
    fn push_pred(&mut self, pred: Pred);
    fn push_dst(&mut self, dst: i32);
    fn push_dst_movtd(&mut self, dst: i32);
    fn push_dst_preg(&mut self, dst: i32);
    fn push_mova_area(&mut self, area: u8, index: u8);
}

impl InsnExt for Insn {
    fn push_literal(&mut self, literal: u64, size: u8) {
        self.push_arch_spec(OP_LITERAL, literal, size as u64)
    }

    fn push_empty(&mut self) {
        self.push_arch_spec(OP_EMPTY, 0, 0);
    }

    fn push_uimm_short<I: Into<u64>>(&mut self, uimm: I) {
        self.push_arch_spec(OP_UIMM, uimm.into(), 0);
    }

    fn push_mas(&mut self, mas: u8) {
        if mas != 0 {
            self.push_arch_spec(OP_MAS, mas as u64, 0);
        }
    }

    fn push_pred(&mut self, pred: Pred) {
        match pred.psrc {
            Psrc::Lcntex => {
                self.push_arch_spec(OP_LCNTEX, 0, pred.invert as u64);
            }
            Psrc::Spred(mask) => {
                self.push_arch_spec(OP_SPRED, mask as u64, pred.invert as u64);
            }
            Psrc::Pcnt(mut index) => {
                if pred.invert {
                    index |= PSRC_INVERT;
                }
                self.push_reg(Reg::new(REG_CLASS_PCNT, index as u64).read());
            }
            Psrc::Preg(mut index) => {
                if pred.invert {
                    index |= PSRC_INVERT;
                }
                self.push_reg(Reg::new(REG_CLASS_PREG, index as u64).read());
            }
            Psrc::Prnd(mut index) => {
                if pred.invert {
                    index |= PSRC_INVERT;
                }
                self.push_reg(Reg::new(REG_CLASS_PRND, index as u64).read());
            }
        }
    }

    fn push_dst(&mut self, dst: i32) {
        match dst {
            0xde | 0xdf => self.push_empty(),
            _ => self.push_reg(Reg::new(RegClass::INT, dst as u64).write()),
        }
    }

    fn push_dst_movtd(&mut self, dst: i32) {
        match dst {
            0xd1..=0xd3 => {
                self.push_reg(Reg::new(REG_CLASS_CTPR, dst as u64 - 0xd0).write());
            }
            _ => self.push_dst(dst),
        }
    }

    fn push_dst_preg(&mut self, dst: i32) {
        self.push_reg(Reg::new(REG_CLASS_PREG, dst as u64).write());
    }

    fn push_mova_area(&mut self, area: u8, index: u8) {
        self.push_arch_spec(OP_AREA, area.into(), index.into());
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Options {
    pub isa: u8,
}

impl Default for Options {
    fn default() -> Self {
        Self { isa: 7 }
    }
}

struct Cursor<'a> {
    bytes: Bytes<'a>,
    next_half: Option<u16>,
}

impl<'a> Deref for Cursor<'a> {
    type Target = Bytes<'a>;

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl DerefMut for Cursor<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bytes
    }
}

impl<'a> Cursor<'a> {
    fn new(bytes: Bytes<'a>) -> Self {
        Self {
            bytes,
            next_half: None,
        }
    }

    fn read_u32_if(&mut self, cond: bool) -> Result<Option<u32>, Error> {
        cond.then(|| self.read_u32()).transpose()
    }

    fn read_half(&mut self) -> Result<u16, Error> {
        // stupid order of half-syllables...
        match self.next_half.take() {
            Some(raw) => Ok(raw),
            None => {
                self.next_half = Some(self.read_u16()?);
                Ok(self.read_u16()?)
            }
        }
    }

    fn read_half_if(&mut self, cond: bool) -> Result<Option<u16>, Error> {
        if cond {
            self.read_half().map(Some)
        } else {
            Ok(None)
        }
    }
}

macro_rules! impl_opcode_check {
    ($($mask:expr, $opcode:expr, $name:ident;)*) => ($(
        #[inline]
        fn $name(&self) -> bool {
            self.raw() & $mask == $opcode
        }
    )*);
}

// !!!! CAUTION !!!!
// !---------------!
// !  DANGER ZONE  !
// !---------------!
// ! HIGH RISK  OF !
// ! BRAIN DAMAGE  !
// !---------------!
// !   KEEP OUT    !
// !!!!!!!!!!!!!!!!!
macro_rules! impl_field {
    ($($name:ident =
        $pos:expr,
        $len:expr,
        $ret:tt $(: $cast:ty)?
        $(,$map:expr $(, $arg:ident: $arg_ty:ty)*)?
    ;)*) => ($(
        impl_field!(impl $name, $ret $(: $cast)?, $pos, $len $(,$map $(, $arg: $arg_ty)*)?);
    )*);
    (impl
         $name:ident,
         bool $(: $cast:ty)?,
         $pos:expr,
         $len:expr
         $(,$map:expr $(, $arg:ident: $arg_ty:ty)*)?
    ) => (
        fn $name(&self $($(, $arg: $arg_ty)*)?) -> bool {
            let ret = zextract(self.raw(), $pos, $len) $(as $cast)?;
            $(let ret = $map(ret $(, $arg)?);)?
            ret != 0
        }
    );
    (impl
        $name:ident,
        $ret:ty,
        $pos:expr,
        $len:expr
        $(,$map:expr $(, $arg:ident: $arg_ty:ty)*)?
    ) => (
        fn $name(&self $($(, $arg: $arg_ty)*)?) -> $ret {
            let ret = zextract(self.raw(), $pos, $len);
            $(let ret = $map(ret $(, $arg)?);)?
            ret as $ret
        }
    );
    (impl
        $name:ident,
        $ret:ty: $cast:ty,
        $pos:expr,
        $len:expr
        $(,$map:expr $(, $arg:ident: $arg_ty:ty)*)?
    ) => (
        fn $name(&self $($(, $arg: $arg_ty)*)?) -> $ret {
            let ret = zextract(self.raw(), $pos, $len) as $cast;
            $(let ret = $map(ret $(, $arg)?);)?
            ret
        }
    );
}

fn get_bit<U, T: ZExtract<U>>(mask: T, pos: usize) -> U {
    zextract(mask, pos as u32, 1)
}

fn check_mask(value: u32, pos: usize, len: usize, index: usize) -> bool {
    debug_assert!(index < len);
    zextract(value, (pos + index) as u32, 1) != 0
}

#[derive(Copy, Clone, Default)]
struct Hs(u32);

impl Hs {
    fn raw(&self) -> u32 {
        self.0
    }

    impl_field! {
        offset_half     =  0, 4, usize, |i| (i + 1) * 4;
        len             =  4, 3, usize, |i| (i + 1) * 8;
        nop             =  7, 3, u8;
        loop_mode       = 10, 1, bool;
        sim             = 11, 1, bool;
        has_ss          = 12, 1, bool;
        mdl             = 13, 1, bool;
        has_cs          = 14, 2, bool, get_bit, i: usize;
        cds_count       = 16, 2, usize;
        pls_count       = 18, 2, usize;
        has_ales        = 20, 6, bool, get_bit, i: usize;
        has_als         = 26, 6, bool, get_bit, i: usize;
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum SsFormat {
    A,
    B,
}

#[derive(Copy, Clone, Default)]
struct Ss(u32);

impl Ss {
    fn is_empty(&self) -> bool {
        self.0 == 0
    }

    fn raw(&self) -> u32 {
        self.0
    }

    impl_field! {
        ct_pred     =  0, 5, u8;
        ct_cond     =  5, 5, u8;
        ct_ctpr     = 10, 2, u8;
        format      = 20, 1, SsFormat, |i| match i {
            0 => SsFormat::A,
            1 => SsFormat::B,
            _ => unreachable!(),
        };
        ipd         = 30, 2, u8;

        // SsFormat::A
        has_aas     = 12, 4, bool, get_bit, i: usize;
        alc         = 16, 2, u8;
        abp         = 18, 2, u8;
        abn         = 21, 2, u8;
        abg         = 23, 2, u8;
        bap         = 28, 1, bool;
        eap         = 29, 1, bool;

        // SsFormat::B
        call_hint   = 12, 1, bool;
    }
}

#[derive(Copy, Clone, Default)]
struct Als(u32);

impl Als {
    fn raw(&self) -> u32 {
        self.0
    }

    fn sm(&self) -> bool {
        self.0 >> 31 != 0
    }
}

#[derive(Copy, Clone, Default)]
struct Ales(u16);

impl Ales {
    fn raw(&self) -> u16 {
        self.0
    }
}

#[derive(Copy, Clone, Default)]
struct Cs0(u32);

impl Cs0 {
    fn raw(&self) -> u32 {
        self.0
    }

    impl_opcode_check! {
        0xf0000000, 0x00000000, is_ibranch;
        0xf0000000, 0x10000000, is_pref;
        0xf0000000, 0x20000000, is_puttsd;
        0xf3fffff8, 0x30000000, is_done_base;
        0xf3ffffff, 0x30000000, is_done;
        0xf3ffffff, 0x30000002, is_done_iret;
        0xf3ffffff, 0x30000003, is_done_hret;
        0xf3ffffff, 0x30000004, is_done_glaunch;
        0x30000000, 0x00000000, is_prep_ct;
        0xf0000000, 0x90000000, is_prep_apb;
        0x30000000, 0x20000000, is_prep_sys;
        0xffffffff, 0xf0000000, is_prep_ret;
        0xffffffff, 0xf0000001, is_gettsd;
    }

    impl_field! {
        ctpr        = 30,  2, u8;
        disp   =  0, 28, i32, |i| ((i << 4) as i32) >> 1;
        done_fdam   = 26,  1, bool;
        done_trar   = 27,  1, bool;
        pref_ipr    =  0,  3, u8;
        pref_ipd    =  3,  1, bool;
        pref_disp   =  4, 24, u32;
    }
}

#[derive(Copy, Clone, Default)]
struct Cs1(u32);

impl Cs1 {
    fn raw(&self) -> u32 {
        self.0
    }

    impl_opcode_check! {
        0xe0000000, 0x00000000, is_setwd;
        0xe2000000, 0x02000000, is_setwd_settr;
        0x04000000, 0x04000000, is_setwd_setbn;
        0x08000000, 0x08000000, is_setwd_setbp;
        0xf0000000, 0x10000000, is_setwd_vfrpsz;
        0xffffff00, 0x20000000, is_setei;
        0xffffffff, 0x28000000, is_setsft;
        0xffffffe0, 0x30000000, is_wait;
        0xf0000000, 0x40000000, is_setwd2;
        0xffffff80, 0x50000000, is_call;
        0xffffff80, 0x50000080, is_icall;
        0xf0000000, 0x60000000, is_setmas;
        0xfffffffc, 0x70000000, is_flush;
        0xffffffff, 0x70000001, is_flush_r;
        0xffffffff, 0x70000002, is_flush_c;
        0xfffe0000, 0x80000000, is_vfbg;
    }

    impl_field! {
        setbn_rbs   =  0,  6, u8, |i| i * 2;
        setbn_rsz   =  6,  6, u8, |i| (i + 1) * 2;
        setbn_rcur  = 12,  6, u8, |i| i * 2;
        setbp_psz   = 18,  5, u8;
        setei_value =  0,  8, u8;
        wait_all_c  =  0,  1, bool;
        wait_all_e  =  1,  1, bool;
        wait_st_c   =  2,  1, bool;
        wait_ld_c   =  3,  1, bool;
        wait_fl_c   =  4,  1, bool;
        wait_ma_c   =  5,  1, bool;
        wait_trap   =  6,  1, bool;
        wait_sal    =  7,  1, bool;
        wait_sas    =  8,  1, bool;
        wait_bits   =  0,  9, u32;
        vfbg_umask  =  0,  8, u8;
        vfbg_dmask  =  8,  8, u8;
        vfbg_chkm4  = 16,  1, bool;
        vfbg_bits   =  0, 17, u32;
        call_wbs    =  0,  7, u8, |i| i * 2;
    }

    fn setmas(&self) -> Option<[u8; 6]> {
        self.is_setmas().then(|| {
            [
                zextract(self.0, 21, 7) as u8,
                0,
                zextract(self.0, 14, 7) as u8,
                zextract(self.0, 7, 7) as u8,
                0,
                zextract(self.0, 0, 7) as u8,
            ]
        })
    }
}

#[derive(Copy, Clone, Default)]
struct SetwdLts(u32);

impl SetwdLts {
    fn raw(&self) -> u32 {
        self.0
    }

    impl_field! {
        setwd_mcn   =  2,  1, bool;
        setwd_dbl   =  3,  1, bool;
        setwd_nfx   =  4,  1, bool;
        setwd_wsz   =  5,  7, u8;
        vfrpsz_rpsz = 12,  5, u8;
        settr_type  = 17, 15, u16;
    }
}

#[derive(Copy, Clone, Default)]
struct Pls(u32);

impl Pls {
    fn raw(&self) -> u32 {
        self.0
    }

    impl_field! {
        preg    =  0, 5, u8;
        write   =  5, 1, bool;
        lpsrc1  =  6, 3, u8;
        lpinv1  =  9, 1, bool;
        lpsrc0  = 10, 3, u8;
        lpinv0  = 13, 1, bool;
        op      = 14, 2, u8;
        elp1    = 16, 8, u8;
        elp0    = 24, 8, u8;
    }
}

#[derive(Copy, Clone)]
enum Psrc {
    Lcntex,
    Spred(u8),
    Pcnt(u8),
    Preg(u8),
    Prnd(u8),
}

impl Psrc {
    fn from_u8(raw: u8) -> Self {
        debug_assert!(raw & 0x80 == 0);

        // | 0000_0000 | lcntex
        // | 00xx_xxxx | spred012345
        // | 010x_xxxx | pcntN
        // | 011x_xxxx | pN
        // | 1100_0000 | %bgrpred
        // | 110x_xxxx | %rndpred1 .. %rndpred31

        if raw == 0 {
            Self::Lcntex
        } else if raw & 0xc0 == 0 {
            Self::Spred(raw & 0x3f)
        } else if raw & 0xe0 == 0x40 {
            Self::Pcnt(raw & 0x1f)
        } else if raw & 0xe0 == 0x60 {
            Self::Preg(raw & 0x1f)
        } else {
            Self::Prnd(raw & 0x1f)
        }
    }
}

#[derive(Copy, Clone)]
struct Pred {
    psrc: Psrc,
    invert: bool,
}

impl Pred {
    fn new(psrc: Psrc, invert: bool) -> Self {
        Self { psrc, invert }
    }

    fn from_u8(psrc: u8, invert: bool) -> Self {
        Self {
            psrc: Psrc::from_u8(psrc),
            invert,
        }
    }
}

#[derive(Copy, Clone, Default)]
struct Rlp(u16);

impl Rlp {
    fn raw(&self) -> u16 {
        self.0
    }

    impl_field! {
        psrc        =  0, 7, u8;
        invert      =  7, 3, bool, get_bit, i: usize;
        has         = 10, 3, bool, get_bit, i: usize;
        is_am       = 13, 1, bool;
        cluster     = 14, 1, Cluster, |i| if i == 0 {
            Cluster::A
        } else {
            Cluster::B
        };
        is_mrgc     = 15, 1, bool;
    }

    fn has_alc(&self, slot: Slot) -> bool {
        self.cluster() == alc_cluster(slot) && self.has(alc_cluster_index(slot))
    }

    fn get(&self, slot: Slot) -> Option<Pred> {
        if self.has_alc(slot) {
            let index = alc_cluster_index(slot);
            Some(Pred::from_u8(self.psrc(), self.invert(index)))
        } else {
            None
        }
    }
}

#[derive(Copy, Clone, Default)]
struct Aas(u16, u8);

impl Aas {
    const OPCODE_NONE: u8 = 0;
    const OPCODE_MOVA_B: u8 = 1;
    const OPCODE_MOVA_H: u8 = 2;
    const OPCODE_MOVA_W: u8 = 3;
    const OPCODE_MOVA_D: u8 = 4;
    const OPCODE_MOVA_Q: u8 = 5;
    const OPCODE_MOVA_QP: u8 = 7;

    fn raw(&self) -> u16 {
        self.0
    }

    fn dst(&self) -> u8 {
        self.1
    }

    impl_field! {
        am      =  0, 1, bool;
        index   =  1, 5, u8;
        area    =  6, 6, u8;
        opcode  = 12, 3, u8;
        be      = 15, 1, bool;
    }
}

#[derive(Default)]
struct UnpackedBundle {
    hs: Hs,
    ss: Ss,
    als: [Option<Als>; 6],
    ales: [Option<Ales>; 6],
    cs0: Option<Cs0>,
    cs1: Option<Cs1>,
    aas: [Option<Aas>; 4],
    lts: [Option<u32>; 4],
    pls: [Pls; 3],
    rlp: [Rlp; 6],
}

impl UnpackedBundle {
    fn unpack(isa: u8, mut cur: Cursor) -> Result<UnpackedBundle, Error> {
        let len = cur.len();
        let hs = cur.read_u32().map(Hs)?;
        let ss = Ss(cur.read_u32_if(hs.has_ss())?.unwrap_or(0));
        let mut als = [None; 6];
        for (i, als) in als.iter_mut().enumerate() {
            *als = cur.read_u32_if(hs.has_als(i))?.map(Als);
        }
        let cs0 = cur.read_u32_if(hs.has_cs(0))?.map(Cs0);
        let mut ales = [None; 6];
        let offset_half = hs.offset_half();
        if isa >= 4 && cur.offset() + if hs.has_cs(1) { 8 } else { 4 } == offset_half {
            // ALES2 and ALES5 become a real half-syllables only in elbrus-v4. The encoding
            // differs from other half-syllables for backward compatibility.
            for i in [2, 5] {
                let tmp = Some(cur.read_half().map(Ales)?);
                if hs.has_ales(i) {
                    ales[i] = tmp;
                }
            }
        } else {
            // ALES2 and ALES5 was a single bit in a header syllable before elbrus-v4.
            for i in [5, 2] {
                if hs.has_ales(i) {
                    // The value 0x01c0 used in elbrus-v4 to encode old single bit half-syllables.
                    ales[i] = Some(Ales(0x01c0));
                }
            }
        }
        let cs1 = cur.read_u32_if(hs.has_cs(1))?.map(Cs1);
        if cur.offset() != offset_half {
            return Err(Error::Failed(64));
        }
        for i in [0, 1, 3, 4] {
            ales[i] = cur.read_half_if(hs.has_ales(i))?.map(Ales);
        }
        let mut aas = [None; 4];
        if !ss.is_empty() && ss.format() == SsFormat::A {
            let mut dst = [0; 4];
            for i in [0, 2] {
                if ss.has_aas(i) || ss.has_aas(i + 1) {
                    let s = cur.read_half()?.to_be_bytes();
                    dst[i] = s[0];
                    dst[i + 1] = s[1];
                }
            }
            for i in (0..4).filter(|&i| ss.has_aas(i)) {
                aas[i] = Some(Aas(cur.read_half()?, dst[i]));
            }
        }

        let cds_count = hs.cds_count();
        let pls_count = hs.pls_count();
        let tail = ((len - cur.offset()) / 4)
            .checked_sub(cds_count + pls_count)
            .ok_or(Error::Failed(64))?;
        let lts_count = cmp::min(tail, 4);

        // skip padding
        cur.advance((tail - lts_count) * 4);

        let mut lts = [None; 4];
        for i in (0..lts_count).rev() {
            lts[i] = cur.read_u32_if(true)?;
        }

        let mut pls = [Pls(0); 3];
        for i in (0..pls_count).rev() {
            pls[i] = Pls(cur.read_u32()?);
        }

        let mut rlp = [Rlp(0); 6];
        let rlp_len = cds_count * 2;
        for i in (0..cds_count).rev() {
            let raw = cur.read_u32()?;
            rlp[i * 2] = Rlp(raw as u16);
            rlp[i * 2 + 1] = Rlp((raw >> 16) as u16);
        }

        debug_assert_eq!(cur.offset(), len);

        Ok(UnpackedBundle {
            hs,
            ss,
            als,
            ales,
            cs0,
            cs1,
            aas,
            lts,
            pls,
            rlp,
        })
    }

    fn rlp(&self) -> &[Rlp] {
        &self.rlp[..self.hs.cds_count() * 2]
    }
}

struct Decoder {
    isa: u8,
    alias: bool,
    address: u64,
    unpacked: UnpackedBundle,
    aaincr: Option<i32>,
    ct_decoded: bool,
}

impl Decoder {
    fn new(opts: crate::Options, arch_opts: Options) -> Self {
        Self {
            isa: arch_opts.isa,
            alias: opts.alias,
            unpacked: UnpackedBundle::default(),
            aaincr: None,
            address: 0,
            ct_decoded: false,
        }
    }
}

fn alc_slot_for(chan: usize) -> Slot {
    debug_assert!(chan < 6);
    Slot::new(SLOT_ALC0.raw() + (chan as u16))
}

fn is_first_cluster(slot: Slot) -> bool {
    debug_assert!((SLOT_ALC0..=SLOT_ALC5).contains(&slot));
    slot < SLOT_ALC3
}

fn is_second_cluster(slot: Slot) -> bool {
    !is_first_cluster(slot)
}

fn alc_cluster(slot: Slot) -> Cluster {
    if is_first_cluster(slot) {
        Cluster::A
    } else {
        Cluster::B
    }
}

fn alc_index(slot: Slot) -> usize {
    debug_assert!((SLOT_ALC0..=SLOT_ALC5).contains(&slot));
    (slot.raw() - SLOT_ALC0.raw()) as usize
}

fn alc_cluster_index(slot: Slot) -> usize {
    match alc_index(slot) {
        i if i < 3 => i,
        i => i - 3,
    }
}

fn alc_channel_encode(mut chan: usize) -> u64 {
    if chan >= 3 {
        chan += 1;
    }
    chan as u64
}

fn apb_slot_for(chan: usize) -> Slot {
    debug_assert!(chan < 4);
    Slot::new(SLOT_APB0.raw() + (chan as u16))
}

fn plu_slot_for(chan: usize) -> Slot {
    debug_assert!(chan < 3);
    Slot::new(SLOT_PLU0.raw() + (chan as u16))
}

impl Decoder {
    fn hs(&self) -> Hs {
        self.unpacked.hs
    }

    fn disp_to_absolute(&self, disp: i32) -> u64 {
        self.address.wrapping_add(disp as i64 as u64)
    }

    fn decode_hs(&mut self, out: &mut Bundle) {
        if self.hs().loop_mode() {
            out.peek().set_opcode(opcode::LOOP_MODE);
            out.next();
        }
        if self.hs().sim() {
            // TODO: todo!("HS[SIM] is set");
        }
        if self.hs().mdl() {
            // TODO: todo!("HS[MDL] is set");
        }
    }

    fn decode_ss_short(&mut self, out: &mut Bundle) {
        let ss = self.unpacked.ss;
        if ss.format() == SsFormat::A {
            let advance = |out: &mut Bundle, opcode, mask: u8| {
                if mask == 0 {
                    return;
                }
                out.push_with(opcode, |insn| {
                    insn.flags_mut()
                        .set_if(ADVANCE_T, mask & 1 != 0)
                        .set_if(ADVANCE_F, mask & 2 != 0);
                });
            };

            advance(out, opcode::ALC, ss.alc());
            advance(out, opcode::ABP, ss.abp());
            advance(out, opcode::ABN, ss.abn());
            advance(out, opcode::ABG, ss.abg());

            // TODO: vfdi
            // TODO: rp_{hi,lo}

            if ss.bap() {
                out.push(opcode::BAP);
            }

            if ss.eap() {
                out.push(opcode::EAP);
            }
        }

        // TODO: ipd
    }

    fn decode_ct(&mut self, out: &mut Bundle) {
        let ss = self.unpacked.ss;
        let cond = ss.ct_cond();
        if ss.is_empty() || self.ct_decoded || cond == CT_COND_NONE {
            return;
        }
        let insn = out.peek();
        let ctpr = ss.ct_ctpr();
        insn.set_opcode(opcode::INVALID_CT);
        if ctpr > 0 {
            if let Some((cs1, true)) = self.unpacked.cs1.map(|i| (i, i.is_call())) {
                insn.set_opcode(opcode::CALL);
                insn.push_uimm_short(cs1.call_wbs());
            } else {
                insn.set_opcode(opcode::CT);
            }
            insn.push_reg(Reg::new(REG_CLASS_CTPR, ctpr as u64).read());
        } else if let Some((cs0, true)) = self.unpacked.cs0.map(|i| (i, i.is_ibranch())) {
            if let Some((cs1, true)) = self.unpacked.cs1.map(|i| (i, i.is_icall())) {
                insn.set_opcode(opcode::ICALL);
                insn.push_uimm_short(cs1.call_wbs());
            } else {
                insn.set_opcode(opcode::IBRANCH);
            }
            insn.push_absolute(self.disp_to_absolute(cs0.disp()));
        } else if let Some((cs0, true)) = self.unpacked.cs0.map(|i| (i, i.is_done_base())) {
            if cs0.is_done() {
                insn.set_opcode(opcode::DONE);
                if cs0.done_fdam() {
                    insn.push_arch_spec(OP_FDAM, 0, 0);
                }
                if cs0.done_trar() {
                    insn.push_arch_spec(OP_TRAR, 0, 0);
                }
            } else if cs0.is_done_iret() {
                insn.set_opcode(opcode::IRET);
            } else if cs0.is_done_hret() {
                insn.set_opcode(opcode::HRET);
            } else if cs0.is_done_glaunch() {
                insn.set_opcode(opcode::GLAUNCH);
            }
        }

        if cond != CT_COND_ALWAYS {
            insn.push_arch_spec(OP_COND_START, 0, 0);
            insn.push_arch_spec(OP_CT_COND, cond as u64, ss.ct_pred() as u64);
        }

        // TODO: jump target hints

        out.next();
    }

    fn decode_cs0(&mut self, out: &mut Bundle) {
        let cs0 = match self.unpacked.cs0 {
            Some(cs0) => cs0,
            None => return,
        };

        if cs0.is_ibranch() {
            // handled in decode_ct
        } else if cs0.is_pref() {
            out.push_with(opcode::PREF, |insn| {
                insn.push_reg(Reg::new(REG_CLASS_IPR, cs0.pref_ipr() as u64).read());
                insn.push_uimm(cs0.pref_disp() as u64);
                if cs0.pref_ipd() {
                    insn.push_arch_spec(OP_IPD, 0, 0);
                }
            });
        } else if cs0.is_puttsd() {
            out.push_with(opcode::PUTTSD, |insn| {
                insn.push_absolute(self.disp_to_absolute(cs0.disp()));
            });
        } else if cs0.is_done_base() {
            // handled in decode_ct
        } else if cs0.is_prep_ct() {
            let mut opcode = opcode::PREP_CT;
            if self.isa >= 7 {
                let ss = self.unpacked.ss;
                if !ss.is_empty() && ss.format() == SsFormat::B && ss.call_hint() {
                    opcode = opcode::PREP_CALL;
                }
            }
            out.push_with(opcode, |insn| {
                insn.push_reg(Reg::new(REG_CLASS_CTPR, cs0.ctpr() as u64).write());
                insn.push_absolute(self.disp_to_absolute(cs0.disp()));
            });
        } else if cs0.is_prep_apb() {
            out.push_with(opcode::PREP_APB, |insn| {
                insn.push_reg(Reg::new(REG_CLASS_CTPR, cs0.ctpr() as u64).write());
                insn.push_absolute(self.disp_to_absolute(cs0.disp()));
            });
        } else if cs0.is_prep_sys() {
            out.push_with(opcode::PREP_SYS, |insn| {
                insn.push_reg(Reg::new(REG_CLASS_CTPR, cs0.ctpr() as u64).write());
                insn.push_uimm(cs0.disp() as u64);
            });
        } else if cs0.is_prep_ret() {
            out.push_with(opcode::PREP_RET, |insn| {
                insn.push_reg(Reg::new(REG_CLASS_CTPR, cs0.ctpr() as u64).write());
            });
        } else if cs0.is_gettsd() {
            out.push_with(opcode::GETTSD, |insn| {
                insn.push_reg(Reg::new(REG_CLASS_CTPR, cs0.ctpr() as u64).write());
            });
        } else {
            out.push_with(opcode::CS, |insn| {
                insn.push_uimm(0);
                insn.push_uimm(cs0.raw() as u64);
            });
        }
    }

    fn decode_cs1(&mut self, out: &mut Bundle) {
        let cs1 = match self.unpacked.cs1 {
            Some(cs1) => cs1,
            None => return,
        };

        if cs1.is_setwd() || cs1.is_setwd2() {
            if cs1.is_setwd_vfrpsz() {
                out.push_with(opcode::VFRPSZ, |insn| {
                    match self.unpacked.lts[0].map(SetwdLts) {
                        Some(lts) => insn.push_uimm(lts.vfrpsz_rpsz() as u64),
                        None => todo!("missing LTS0"),
                    }
                });
            }

            if cs1.is_setwd() {
                out.push_with(opcode::SETWD, |insn| {
                    match self.unpacked.lts[0].map(SetwdLts) {
                        Some(lts) => {
                            insn.flags_mut()
                                .set_if(SETWD_X, !lts.setwd_nfx())
                                .set_if(SETWD_Z, lts.setwd_dbl())
                                .set_if(SETWD_MCN, self.isa >= 7 && lts.setwd_mcn());
                            let wsz = lts.setwd_wsz() * 2;
                            insn.push_uimm_short(wsz);
                        }
                        None => todo!("missing LTS0"),
                    }
                });
            }

            if cs1.is_setwd_setbn() {
                out.push_with(opcode::SETBN, |insn| {
                    insn.push_uimm_short(cs1.setbn_rsz());
                    insn.push_uimm_short(cs1.setbn_rbs());
                    match cs1.setbn_rcur() {
                        0 => {}
                        rcur => insn.push_uimm_short(rcur),
                    }
                });
            }

            if cs1.is_setwd_setbp() {
                out.push_with(opcode::SETBP, |insn| {
                    insn.push_uimm_short(cs1.setbp_psz());
                });
            }

            if cs1.is_setwd_settr() {
                out.push_with(opcode::SETTR, |insn| {
                    match self.unpacked.lts[0].map(SetwdLts) {
                        Some(lts) => insn.push_uimm(lts.settr_type() as u64),
                        None => todo!("missing LTS0"),
                    }
                });
            }
        } else if cs1.is_setei() {
            out.push_with(opcode::SETEI, |insn| {
                insn.push_uimm(cs1.setei_value() as u64);
            });
        } else if cs1.is_setsft() {
            out.push(opcode::SETSFT);
        } else if cs1.is_wait() {
            out.push_with(opcode::WAIT, |insn| {
                insn.push_arch_spec(OP_WAIT, cs1.wait_bits() as u64, 0);
            });
        } else if cs1.is_call() || cs1.is_icall() {
            // handled in decode_ct
        } else if cs1.is_setmas() {
            // handled in decode_als
        } else if cs1.is_flush() {
            if cs1.is_flush_r() {
                out.push(opcode::FLUSH_R);
            }
            if cs1.is_flush_c() {
                out.push(opcode::FLUSH_C);
            }
        } else if cs1.is_vfbg() {
            out.push_with(opcode::VFBG, |insn| {
                insn.push_arch_spec(OP_VFBG, cs1.vfbg_bits() as u64, 0);
            });
        } else {
            out.push_with(opcode::CS, |insn| {
                insn.push_uimm(1);
                insn.push_uimm(cs1.raw() as u64);
            });
        }
    }

    fn decode_als(&mut self, out: &mut Bundle) {
        let mas = self
            .unpacked
            .cs1
            .and_then(|cs| cs.setmas())
            .unwrap_or_default();

        for (i, &mas) in mas.iter().enumerate() {
            let als = match self.unpacked.als[i] {
                Some(als) => als,
                None => continue,
            };

            let insn = out.peek();
            let slot = alc_slot_for(i);
            insn.set_slot(slot);
            insn.flags_mut().set_if(INSN_SM, als.sm());

            let mut raw = als.raw() as u64;
            raw |= (self.unpacked.ales[i].unwrap_or_default().raw() as u64) << 32;
            raw |= alc_channel_encode(i) << 48;
            raw |= (mas as u64) << 51;

            if E2KDecodeAlop::decode(self, raw, insn).is_err() {
                insn.set_opcode(opcode::ALS);
                insn.push_uimm(als.raw() as u64);
                if let Some(ales) = self.unpacked.ales[i] {
                    insn.push_uimm(ales.raw() as u64);
                }
                if mas != 0 {
                    insn.push_uimm(mas as u64);
                }
            }

            out.next();

            if let Some(aaincr) = self.aaincr.take() {
                out.push_with(opcode::INCR, |insn| {
                    insn.set_slot(slot);
                    self.set_aaincr(insn, aaincr, Access::Read);
                    self.set_am(insn);
                });
            }
        }
    }

    fn decode_aas(&mut self, out: &mut Bundle) {
        for (i, aas) in self.unpacked.aas.iter().enumerate() {
            let aas = match aas {
                Some(aas) => aas,
                None => continue,
            };

            let opcode = match aas.opcode() {
                Aas::OPCODE_NONE => continue,
                Aas::OPCODE_MOVA_B => opcode::MOVAB,
                Aas::OPCODE_MOVA_H => opcode::MOVAH,
                Aas::OPCODE_MOVA_W => opcode::MOVAW,
                Aas::OPCODE_MOVA_D => opcode::MOVAD,
                Aas::OPCODE_MOVA_Q => opcode::MOVAQ,
                Aas::OPCODE_MOVA_QP => opcode::MOVAQP,
                _ => opcode::INVALID,
            };
            let insn = out.peek();
            insn.set_opcode(opcode);
            insn.set_slot(apb_slot_for(i));
            insn.push_dst(aas.dst() as i32);
            insn.flags_mut()
                .set_if(MOVA_BE, aas.be())
                .set_if(MOVA_AM, aas.am());
            insn.push_mova_area(aas.area(), aas.index());
            out.next();
        }
    }

    fn decode_pls(&mut self, out: &mut Bundle) {
        let count = self.hs().pls_count();
        let mut used = [0_u8; 8];

        for i in 0..count {
            let pls = self.unpacked.pls[i];
            if pls.write() || used[i + 4] != 0 {
                used[i + 4] += 1;
                used[pls.lpsrc0() as usize] += 1;
                used[pls.lpsrc1() as usize] += 1;
            }
        }

        for i in (0..count).filter(|i| used[i + 4] != 0) {
            let pls = self.unpacked.pls[i];
            let insn = out.peek();
            insn.set_slot(plu_slot_for(i));

            let opcode = match pls.op() {
                0 => opcode::ANDP,
                1 => opcode::LANDP,
                2 => opcode::INVALID,
                3 => opcode::MOVEP,
                _ => unreachable!(),
            };
            insn.set_opcode(opcode);

            if pls.write() {
                insn.push_reg(Reg::new(REG_CLASS_PREG, pls.preg() as u64).write());
            } else {
                insn.push_empty();
            }

            for j in 0..2 {
                let (invert, lp) = match j {
                    0 => (pls.lpinv0(), pls.lpsrc0()),
                    _ => (pls.lpinv1(), pls.lpsrc1()),
                };
                if lp < 4 {
                    let pls = self.unpacked.pls[lp as usize / 2];
                    let elp = match lp & 1 {
                        0 => pls.elp0(),
                        _ => pls.elp1(),
                    };
                    let psrc = Psrc::from_u8(elp);
                    let pred = Pred::new(psrc, invert);
                    insn.push_pred(pred);
                } else {
                    insn.push_arch_spec(OP_PLU, (lp - 4) as u64, invert as u64);
                }
            }

            out.next();
        }
    }

    fn decode_nops(&self, out: &mut Bundle) {
        let nops = self.hs().nop();
        if nops != 0 || out.is_empty() {
            let insn = out.peek();
            insn.set_opcode(opcode::NOP);
            insn.push_uimm_short(nops + 1);
            out.next();
        }
    }

    fn end(&self, out: &mut Bundle) {
        // TODO: better way to bundle end?
        out.peek().set_opcode(opcode::BUNDLE_END);
        out.next();
    }
}

impl ArchDecoder for Decoder {
    fn decode(&mut self, address: u64, bytes: &[u8], out: &mut Bundle) -> Result<usize, Error> {
        let bytes = Bytes::new(bytes);
        let len = Hs(bytes.peek_u8().unwrap_or(0) as u32).len();
        let cur = bytes
            .truncate(len)
            .map(Cursor::new)
            .ok_or_else(|| Error::More((len - bytes.len()) * 8))?;
        match UnpackedBundle::unpack(self.isa, cur) {
            Ok(unpacked) => {
                self.address = address;
                self.unpacked = unpacked;
                self.ct_decoded = false;
                out.clear();
                self.decode_hs(out);
                self.decode_ss_short(out);
                self.decode_cs1(out);
                self.decode_als(out);
                self.decode_aas(out);
                self.decode_pls(out);
                self.decode_ct(out);
                self.decode_cs0(out);
                self.decode_nops(out);
                self.end(out);
                Ok(self.hs().len() * 8)
            }
            Err(_) => {
                if bytes.len() >= 16 {
                    out.clear();
                    // TODO: decode apb instructions
                    out.push(opcode::APB);
                    out.push(opcode::APB);
                    self.end(out);
                    Ok(128)
                } else {
                    Err(Error::Failed(bytes.len() * 8))
                }
            }
        }
    }
}

impl Decoder {
    fn set_lit(&mut self, out: &mut Insn, src: i32) {
        let index = zextract(src as u32, 0, 2) as usize;
        if let Some(low) = self.unpacked.lts[index] {
            if src & 0xdc == 0xdc {
                // 64-bit literal
                if let Some(Some(high)) = self.unpacked.lts.get(index + 1) {
                    let lit = ((*high as u64) << 32) | (low as u64);
                    out.push_literal(lit, 64);
                    return;
                }
            } else if src & 0xdc == 0xd8 {
                // 32-bit literal
                out.push_literal(low as u64, 32);
                return;
            } else if src & 0xda == 0xd0 {
                // 16-bit literal
                let shift = if src & 4 != 0 { 16 } else { 0 };
                let lit = (low >> shift) as u64 & 0xffff;
                out.push_literal(lit, 16);
                return;
            }
        }

        // invalid literal
        out.push_literal(src as u64, 0);
    }

    fn set_src1(&mut self, out: &mut Insn, src1: i32) {
        if (0xc0..0xe0).contains(&src1) {
            out.push_uimm_short(src1 as u8 - 0xc0);
        } else {
            out.push_reg(Reg::new(RegClass::INT, src1 as u64).read());
        }
    }

    fn set_src2(&mut self, out: &mut Insn, src2: i32) {
        if (0xc0..0xd0).contains(&src2) {
            out.push_uimm_short(src2 as u8 - 0xc0);
        } else if (0xd0..0xe0).contains(&src2) {
            self.set_lit(out, src2);
        } else {
            out.push_reg(Reg::new(RegClass::INT, src2 as u64).read());
        }
    }

    fn set_src3(&mut self, out: &mut Insn, src3: i32) {
        out.push_reg(Reg::new(RegClass::INT, src3 as u64).read());
    }

    fn set_lt3(&mut self, out: &mut Insn, lt3: i32) {
        if (0xd0..0xe0).contains(&lt3) {
            self.set_lit(out, lt3);
        } else {
            out.push_reg(Reg::new(RegClass::INT, lt3 as u64).read());
        }
    }

    fn set_src4(&mut self, out: &mut Insn, src4: i32) {
        if (0xc0..0xe0).contains(&src4) {
            // TODO:
            out.push_uimm((src4 - 0xc0) as u64);
        } else {
            out.push_reg(Reg::new(RegClass::INT, src4 as u64).read());
        }
    }

    fn set_dst_sreg(&mut self, out: &mut Insn, dst: i32) {
        out.push_reg(Reg::new(REG_CLASS_SREG, dst as u64).write());
    }

    fn set_src1_sreg(&mut self, out: &mut Insn, src2: i32) {
        out.push_reg(Reg::new(REG_CLASS_SREG, src2 as u64).read());
    }

    fn set_wbs(&mut self, out: &mut Insn, wbs: i32) {
        out.push_uimm_short(wbs as u64);
    }

    fn set_uimm(&mut self, out: &mut Insn, imm: u64) {
        out.push_uimm(imm);
    }

    fn set_reg(&mut self, out: &mut Insn, cls: RegClass, index: i32, access: Access) {
        out.push_reg(Reg::new(cls, index as u64).access(access));
    }

    fn set_aad(&mut self, out: &mut Insn, index: i32, access: Access) {
        self.set_reg(out, REG_CLASS_AAD, index, access);
    }

    fn set_aasti(&mut self, out: &mut Insn, index: i32, access: Access) {
        self.set_reg(out, REG_CLASS_AASTI, index, access);
    }

    fn set_aaind(&mut self, out: &mut Insn, index: i32, access: Access) {
        self.set_reg(out, REG_CLASS_AAIND, index, access);
    }

    fn set_aaincr(&mut self, out: &mut Insn, index: i32, access: Access) {
        self.set_reg(out, REG_CLASS_AAINCR, index, access);
    }

    fn set_aau(
        &mut self,
        out: &mut Insn,
        aau: i32,
        aad: i32,
        aaindex: i32,
        aaincr: i32,
        access: Access,
    ) {
        match aau {
            AAUR_MODE_AAD => self.set_aad(out, aad, access),
            AAUR_MODE_AASTI => self.set_aasti(out, aaindex, access),
            AAUR_MODE_AAIND => self.set_aaind(out, aaindex, access),
            AAUR_MODE_AAINCR => self.set_aaincr(out, aaincr, access),
            _ => unreachable!(),
        }
    }

    fn set_mrgc(&mut self, out: &mut Insn) {
        for rlp in self.unpacked.rlp().iter().filter(|i| i.is_mrgc()) {
            if let Some(pred) = rlp.get(out.slot()) {
                out.push_pred(pred);
                return;
            }
        }
        out.push_arch_spec(OP_NO_MRGC, 0, 0);
    }

    fn set_pred(&mut self, out: &mut Insn) {
        let mut first = true;
        for rlp in self.unpacked.rlp().iter().filter(|i| !i.is_mrgc()) {
            if let Some(pred) = rlp.get(out.slot()) {
                if first {
                    first = false;
                    out.push_arch_spec(OP_COND_START, 0, 0);
                }
                out.push_pred(pred);
            }
        }
    }

    fn set_ct_cond(&mut self, insn: &mut Insn) {
        self.ct_decoded = true;
        let ss = self.unpacked.ss;
        let cond = ss.ct_cond();
        if ss.is_empty() || cond == CT_COND_NONE || cond == CT_COND_ALWAYS {
            return;
        }
        insn.push_arch_spec(OP_COND_START, 0, 0);
        insn.push_arch_spec(OP_CT_COND, cond as u64, ss.ct_pred() as u64);
    }

    fn set_am(&mut self, insn: &mut Insn) {
        for rlp in self.unpacked.rlp().iter().filter(|i| i.is_am()) {
            if let Some(pred) = rlp.get(insn.slot()) {
                insn.push_pred(pred);
                break;
            }
        }
    }
}

#[allow(unused_variables)]
impl SetValue for Decoder {
    type Error = Error;

    fn set_args_alf1(&mut self, out: &mut Insn, args: generated::args_alf1) {
        out.push_dst(args.dst);
        self.set_src1(out, args.src1);
        self.set_src2(out, args.src2);
        self.set_pred(out);
    }

    fn set_args_alf1_mas(&mut self, out: &mut Insn, args: generated::args_alf1_mas) {
        out.push_dst(args.dst);
        self.set_src1(out, args.src1);
        self.set_src2(out, args.src2);
        out.push_mas(args.mas as u8);
        self.set_pred(out);
    }

    fn set_args_alf1_merge(&mut self, out: &mut Insn, args: generated::args_alf1_merge) {
        out.push_dst(args.dst);
        self.set_src1(out, args.src1);
        self.set_src2(out, args.src2);
        self.set_mrgc(out);
        self.set_pred(out);
    }

    fn set_args_alf2(&mut self, out: &mut Insn, args: generated::args_alf2) {
        out.push_dst(args.dst);
        self.set_src2(out, args.src2);
        self.set_pred(out);
    }

    fn set_args_alf2_movtd(&mut self, out: &mut Insn, args: generated::args_alf2_movtd) {
        out.push_dst_movtd(args.dst);
        self.set_src2(out, args.src2);
        self.set_pred(out);
    }

    fn set_args_alf3_mas(&mut self, out: &mut Insn, args: generated::args_alf3_mas) {
        self.set_src4(out, args.src4);
        self.set_src1(out, args.src1);
        self.set_src2(out, args.src2);
        out.push_mas(args.mas as u8);
        self.set_pred(out);
    }

    fn set_args_alf7(&mut self, out: &mut Insn, args: generated::args_alf7) {
        out.push_dst_preg(args.dst);
        self.set_src1(out, args.src1);
        self.set_src2(out, args.src2);
        self.set_pred(out);
    }

    fn set_args_alf8(&mut self, out: &mut Insn, args: generated::args_alf8) {
        out.push_dst_preg(args.dst);
        self.set_src2(out, args.src2);
        self.set_pred(out);
    }

    fn set_args_alf10_mas(&mut self, out: &mut Insn, args: generated::args_alf10_mas) {
        self.set_src4(out, args.src4);
        self.set_aad(out, args.aad, Access::Read);
        self.set_aasti(out, args.aaindex, Access::Read);
        if args.aalit != 0 {
            self.set_lit(out, 0xd8 + args.aalit - 1);
        }
        self.set_pred(out);
        if args.aainc != 0 {
            self.aaincr = Some(args.aaincr);
        }
    }

    fn set_args_alf11(&mut self, out: &mut Insn, args: generated::args_alf11) {
        out.push_dst(args.dst);
        self.set_src1(out, args.src1);
        self.set_src2(out, args.src2);
        self.set_pred(out);
    }

    fn set_args_alf11_mas(&mut self, out: &mut Insn, args: generated::args_alf11_mas) {
        out.push_dst(args.dst);
        self.set_src1(out, args.src1);
        self.set_src2(out, args.src2);
        out.push_mas(args.mas as u8);
        self.set_pred(out);
    }

    fn set_args_alf11_merge(&mut self, out: &mut Insn, args: generated::args_alf11_merge) {
        out.push_dst(args.dst);
        self.set_src1(out, args.src1);
        self.set_src2(out, args.src2);
        self.set_mrgc(out);
        self.set_pred(out);
    }

    fn set_args_alf11_lit8(&mut self, out: &mut Insn, args: generated::args_alf11_lit8) {
        out.push_dst(args.dst);
        self.set_src1(out, args.src1);
        self.set_src2(out, args.src2);
        self.set_uimm(out, args.imm as u64);
        self.set_pred(out);
    }

    fn set_args_alf12(&mut self, out: &mut Insn, args: generated::args_alf12) {
        out.push_dst(args.dst);
        self.set_src2(out, args.src2);
        self.set_pred(out);
    }

    fn set_args_alf12_pshufh(&mut self, out: &mut Insn, args: generated::args_alf12_pshufh) {
        out.push_dst(args.dst);
        self.set_src2(out, args.src2);
        self.set_uimm(out, args.imm as u64);
        self.set_pred(out);
    }

    fn set_args_alf12_ibranchd(&mut self, out: &mut Insn, args: generated::args_alf12_ibranchd) {
        out.push_dst(args.dst);
        self.set_src2(out, args.src2);
        self.set_ct_cond(out);
    }

    fn set_args_alf12_icalld(&mut self, out: &mut Insn, args: generated::args_alf12_icalld) {
        out.push_dst(args.dst);
        self.set_wbs(out, args.wbs);
        self.set_src2(out, args.src2);
        self.set_ct_cond(out);
    }

    fn set_args_alf13_mas(&mut self, out: &mut Insn, args: generated::args_alf13_mas) {
        self.set_src4(out, args.src4);
        self.set_src1(out, args.src1);
        self.set_src2(out, args.src2);
        out.push_mas(args.mas as u8);
        self.set_pred(out);
    }

    fn set_args_alf15(&mut self, out: &mut Insn, args: generated::args_alf15) {
        self.set_dst_sreg(out, args.dst);
        self.set_src2(out, args.src2);
        self.set_pred(out);
    }

    fn set_args_alf16(&mut self, out: &mut Insn, args: generated::args_alf16) {
        out.push_dst(args.dst);
        self.set_src1_sreg(out, args.src1);
        self.set_pred(out);
    }

    fn set_args_alf17(&mut self, out: &mut Insn, args: generated::args_alf17) {
        out.push_dst_preg(args.dst);
        self.set_src1(out, args.src1);
        self.set_src2(out, args.src2);
        self.set_pred(out);
    }

    fn set_args_alf21(&mut self, out: &mut Insn, args: generated::args_alf21) {
        out.push_dst(args.dst);
        self.set_src1(out, args.src1);
        self.set_src2(out, args.src2);
        self.set_src3(out, args.src3);
        self.set_pred(out);
    }

    fn set_args_alf21_merge(&mut self, out: &mut Insn, args: generated::args_alf21_merge) {
        out.push_dst(args.dst);
        self.set_src1(out, args.src1);
        self.set_src2(out, args.src2);
        self.set_src3(out, args.src3);
        self.set_mrgc(out);
        self.set_pred(out);
    }

    fn set_args_alf21_lt3(&mut self, out: &mut Insn, args: generated::args_alf21_lt3) {
        out.push_dst(args.dst);
        self.set_src1(out, args.src1);
        self.set_src2(out, args.src2);
        self.set_lt3(out, args.src3);
        self.set_pred(out);
    }

    fn set_args_alf21_log(&mut self, out: &mut Insn, args: generated::args_alf21_log) {
        out.push_dst(args.dst);
        self.set_uimm(out, args.table as u64);
        self.set_src1(out, args.src1);
        self.set_src2(out, args.src2);
        self.set_src3(out, args.src3);
        self.set_pred(out);
    }

    fn set_args_alf21_log_lt3(&mut self, out: &mut Insn, args: generated::args_alf21_log_lt3) {
        out.push_dst(args.dst);
        self.set_uimm(out, args.table as u64);
        self.set_src1(out, args.src1);
        self.set_src2(out, args.src2);
        self.set_lt3(out, args.src3);
        self.set_pred(out);
    }

    fn set_args_alf22(&mut self, out: &mut Insn, args: generated::args_alf22) {
        out.push_dst(args.dst);
        self.set_src2(out, args.src2);
        self.set_pred(out);
    }

    fn set_args_aaurr(&mut self, out: &mut Insn, args: generated::args_aaurr) {
        out.push_dst(args.dst);
        self.set_aau(
            out,
            args.aau,
            args.aad,
            args.aaindex,
            args.aaincr,
            Access::Read,
        );
        self.set_pred(out);
    }

    fn set_args_aaurw(&mut self, out: &mut Insn, args: generated::args_aaurw) {
        self.set_aau(
            out,
            args.aau,
            args.aad,
            args.aaindex,
            args.aaincr,
            Access::Write,
        );
        self.set_src4(out, args.src4);
        self.set_pred(out);
    }
}

macro_rules! impl_cond_isa {
    ($($name:ident = $version:expr),+ $(,)?) => (
        $(
            fn $name(&self) -> bool {
                self.isa >= $version
            }
        )+
    );
}

impl E2KDecodeAlop for Decoder {
    fn fail(&self) -> Self::Error {
        Error::Failed(0)
    }

    fn ex_lshift_1(&self, value: i32) -> i32 {
        value << 1
    }

    fn cond_alias(&self) -> bool {
        self.alias
    }

    impl_cond_isa! {
        cond_v2 = 2,
        cond_v3 = 3,
        cond_v4 = 4,
        cond_v5 = 5,
        cond_v6 = 6,
        cond_v7 = 7,
    }
}

#[cfg(feature = "mnemonic")]
fn mnemonic(insn: &Insn) -> Option<(&'static str, &'static str)> {
    fn advance_sub<'a>(insn: &Insn, f: &'a str, t: &'a str, both: &'a str) -> &'a str {
        let flags = insn.flags();
        let f0 = flags.any(ADVANCE_F);
        let f1 = flags.any(ADVANCE_T);
        match (f0, f1) {
            (false, false) => "",
            (true, false) => f,
            (false, true) => t,
            (true, true) => both,
        }
    }

    fn mova_sub(insn: &Insn) -> &'static str {
        let flags = insn.flags();
        let f0 = flags.any(MOVA_BE);
        let f1 = flags.any(MOVA_AM);
        match (f0, f1) {
            (false, false) => "",
            (true, false) => "be",
            (false, true) => "am",
            (true, true) => "be.am",
        }
    }

    Some(match insn.opcode() {
        opcode::INVALID_CT => ("<invalid ct>", ""),
        opcode::BUNDLE_END => ("--", ""),
        opcode::HS => ("hs", ""),
        opcode::SS => ("ss", ""),
        opcode::CS => ("cs", ""),
        opcode::ALS => ("als", ""),
        opcode::AAS => ("aas", ""),
        opcode::LTS => ("lts", ""),
        opcode::PLS => ("pls", ""),
        opcode::CDS => ("cds", ""),
        opcode::NOP => ("nop", ""),
        opcode::LOOP_MODE => ("loop_mode", ""),
        opcode::ALC => ("alc", advance_sub(insn, "f", "t", "tf")),
        opcode::ABP => ("abp", advance_sub(insn, "f", "t", "tf")),
        opcode::ABN => ("abn", advance_sub(insn, "f", "t", "tf")),
        opcode::ABG => ("abg", advance_sub(insn, "i", "d", "di")),
        opcode::BAP => ("bap", ""),
        opcode::EAP => ("eap", ""),
        opcode::INCR => ("incr", ""),
        opcode::SETWD => {
            let flags = insn.flags();
            let mask = (flags.any(SETWD_X) as usize)
                | ((flags.any(SETWD_Z) as usize) << 1)
                | ((flags.any(SETWD_MCN) as usize) << 2);
            // TODO: to complicated...
            let sub = match mask {
                0b000 => "",
                0b001 => "x",
                0b010 => "z",
                0b011 => "x.z",
                0b100 => "mcn",
                0b101 => "x.mcn",
                0b110 => "z.mcn",
                0b111 => "x.z.mcn",
                _ => unreachable!(),
            };
            ("setwd", sub)
        }
        opcode::SETBP => ("setbp", ""),
        opcode::SETBN => ("setbn", ""),
        opcode::SETTR => ("settr", ""),
        opcode::VFRPSZ => ("vfrpsz", ""),
        opcode::SETEI => ("setei", ""),
        opcode::SETSFT => ("setsft", ""),
        opcode::WAIT => ("wait", ""),
        opcode::FLUSH_R => ("flush", "r"),
        opcode::FLUSH_C => ("flush", "c"),
        opcode::VFBG => ("vfbg", ""),
        opcode::PREP_CT => ("prep", ""),
        opcode::PREP_CALL => ("prep", "call"),
        opcode::PREP_APB => ("prep", "apb"),
        opcode::PREP_SYS => ("prep", "sys"),
        opcode::PREP_RET => ("prep", "ret"),
        opcode::IBRANCH => ("ibranch", ""),
        opcode::PREF => ("pref", ""),
        opcode::PUTTSD => ("puttsd", ""),
        opcode::GETTSD => ("gettsd", ""),
        opcode::DONE => ("done", ""),
        opcode::IRET => ("iret", ""),
        opcode::ANDP => ("andp", ""),
        opcode::LANDP => ("landp", ""),
        opcode::MOVEP => ("movep", ""),
        opcode::CT => ("ct", ""),
        opcode::CALL => ("call", ""),
        opcode::ICALL => ("icall", ""),
        opcode::HRET => ("hret", ""),
        opcode::GLAUNCH => ("glaunch", ""),
        opcode::MOVAB => ("movab", mova_sub(insn)),
        opcode::MOVAH => ("movah", mova_sub(insn)),
        opcode::MOVAW => ("movaw", mova_sub(insn)),
        opcode::MOVAD => ("movad", mova_sub(insn)),
        opcode::MOVAQ => ("movaq", mova_sub(insn)),
        opcode::MOVAQP => ("movaqp", mova_sub(insn)),
        opcode::APB => ("apb", ""),
        opcode => (self::opcode::mnemonic(opcode)?, ""),
    })
}

pub(crate) fn decoder(opts: crate::Options, opts_arch: Options) -> Box<dyn ArchDecoder> {
    Box::new(Decoder::new(opts, opts_arch))
}
