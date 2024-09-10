/// Instruction slots
pub mod slot {
    use crate::Slot;

    pub const ALC0: Slot = Slot::new(0);
    pub const ALC1: Slot = Slot::new(1);
    pub const ALC2: Slot = Slot::new(2);
    pub const ALC3: Slot = Slot::new(3);
    pub const ALC4: Slot = Slot::new(4);
    pub const ALC5: Slot = Slot::new(5);

    pub const APB0: Slot = Slot::new(6);
    pub const APB1: Slot = Slot::new(7);
    pub const APB2: Slot = Slot::new(8);
    pub const APB3: Slot = Slot::new(9);

    pub const PLU0: Slot = Slot::new(10);
    pub const PLU1: Slot = Slot::new(11);
    pub const PLU2: Slot = Slot::new(12);

    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub(crate) enum Cluster {
        A,
        B,
    }

    pub(crate) fn alc_slot_for(chan: usize) -> Slot {
        debug_assert!(chan < 6);
        Slot::new(ALC0.raw() + (chan as u16))
    }

    pub(crate) fn is_first_cluster(slot: Slot) -> bool {
        debug_assert!((ALC0..=ALC5).contains(&slot));
        slot < ALC3
    }

    pub(crate) fn is_second_cluster(slot: Slot) -> bool {
        !is_first_cluster(slot)
    }

    pub(crate) fn alc_cluster(slot: Slot) -> Cluster {
        if is_first_cluster(slot) {
            Cluster::A
        } else {
            Cluster::B
        }
    }

    pub(crate) fn alc_index(slot: Slot) -> usize {
        debug_assert!((ALC0..=ALC5).contains(&slot));
        (slot.raw() - ALC0.raw()) as usize
    }

    pub(crate) fn alc_cluster_index(slot: Slot) -> usize {
        match alc_index(slot) {
            i if i < 3 => i,
            i => i - 3,
        }
    }

    pub(crate) fn alc_channel_encode(mut chan: usize) -> u64 {
        if chan >= 3 {
            chan += 1;
        }
        chan as u64
    }

    pub(crate) fn apb_slot_for(chan: usize) -> Slot {
        debug_assert!(chan < 4);
        Slot::new(APB0.raw() + (chan as u16))
    }

    pub(crate) fn plu_slot_for(chan: usize) -> Slot {
        debug_assert!(chan < 3);
        Slot::new(PLU0.raw() + (chan as u16))
    }
}

/// Custom instruction flags
pub mod insn {
    pub const SM: u32 = 1 << 31;

    pub const SETWD_X: u32 = 1 << 16;
    pub const SETWD_Z: u32 = 1 << 17;
    pub const SETWD_MCN: u32 = 1 << 18;

    pub const ADVANCE_T: u32 = 1 << 16;
    pub const ADVANCE_F: u32 = 1 << 17;

    pub const MOVA_BE: u32 = 1 << 16;
    pub const MOVA_AM: u32 = 1 << 17;
}

/// Custom register classes
pub mod reg_class {
    use crate::RegClass;

    pub const PREG: RegClass = RegClass::arch(0);
    pub const SREG: RegClass = RegClass::arch(1);
    pub const CTPR: RegClass = RegClass::arch(2);
    pub const AAD: RegClass = RegClass::arch(3);
    pub const AASTI: RegClass = RegClass::arch(4);
    pub const AAIND: RegClass = RegClass::arch(5);
    pub const AAINCR: RegClass = RegClass::arch(6);
    pub const PCNT: RegClass = RegClass::arch(7);
    pub const IPR: RegClass = RegClass::arch(8);
    pub const PRND: RegClass = RegClass::arch(9);
}

/// Custom operands
pub mod operand {
    crate::macros::impl_arch_operands! {
        pub enum E2KOperand {
            Literal = 0,
            Empty = 1,
            Uimm = 2,
            Mas = 3,
            Lcntex = 4,
            Spred = 5,
            CondStart = 6,
            Wait = 7,
            Vfbg = 8,
            Ipd = 9,
            NoMrgc = 10,
            Plu = 11,
            Fdam = 12,
            Trar = 13,
            LoopEnd = 14,
            CtCond = 15,
            Area = 16,
            NoSs = 17,
            ApbCt = 18,
            ApbDpl = 19,
            ApbDcd = 20,
            ApbFmt = 21,
            ApbMrng = 22,
            ApbAsz = 23,
            ApbAbs = 24,
        }
    }

    pub const PSRC_INVERT: u8 = 0x80;

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
}
