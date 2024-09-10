/// Custom instruction flags
pub mod insn {
    use crate::flags::Field;

    pub const FIELD_SUFFIX: Field = Field::new(16, 3);
    pub const FIELD_REP: Field = Field::new(19, 2);
    pub const FIELD_SEGMENT: Field = Field::new(21, 3);
    pub const REX_W: u32 = 1 << 27;
    pub const ADDR32: u32 = 1 << 28;
    pub const DATA16: u32 = 1 << 29;
    pub const LOCK: u32 = 1 << 30;
    pub const SUFFIX: u32 = 1 << 31;

    pub const SUFFIX_B: u32 = 0;
    pub const SUFFIX_W: u32 = 1;
    pub const SUFFIX_L: u32 = 2;
    pub const SUFFIX_Q: u32 = 3;
    pub const SUFFIX_FP_S: u32 = 4;
    pub const SUFFIX_FP_L: u32 = 5;
    pub const SUFFIX_FP_LL: u32 = 6;

    pub const REP_NONE: u32 = 0;
    pub const REP: u32 = 1;
    pub const REPZ: u32 = 2;
    pub const REPNZ: u32 = 3;

    pub const SEGMENT_NONE: u32 = 0;
    pub const SEGMENT_ES: u32 = 1;
    pub const SEGMENT_CS: u32 = 2;
    pub const SEGMENT_SS: u32 = 3;
    pub const SEGMENT_DS: u32 = 4;
    pub const SEGMENT_FS: u32 = 5;
    pub const SEGMENT_GS: u32 = 6;
}

/// Custom register classes
pub mod reg_class {
    use crate::RegClass;

    pub const K: RegClass = RegClass::arch(0);
    pub const K_MASK: RegClass = RegClass::arch(1);
    pub const BND: RegClass = RegClass::arch(2);
    pub const SEGMENT: RegClass = RegClass::arch(3);
}

/// Custom operands
pub mod operand {
    use crate::flags::Field;

    crate::macros::impl_arch_operands! {
        pub enum X86Operand {
            ST = 0,
            STI = 1,
            Sae = 2,
            SaeEr = 3,
            MemOffset = 4,
        }
    }

    pub const INDIRECT: u32 = 8;

    pub const FIELD_MEM: Field = Field::new(16, 4);
    pub const FIELD_BCST: Field = Field::new(20, 3);
    pub const FIELD_SEGMENT: Field = Field::new(23, 3);

    pub const SIZE_NONE: u8 = 0;
    pub const SIZE_BYTE: u8 = 1;
    pub const SIZE_WORD: u8 = 2;
    pub const SIZE_DWORD: u8 = 3;
    pub const SIZE_QWORD: u8 = 4;
    pub const SIZE_OWORD: u8 = 5;
    pub const SIZE_XMMWORD: u8 = 6;
    pub const SIZE_YMMWORD: u8 = 7;
    pub const SIZE_ZMMWORD: u8 = 8;
    pub const SIZE_TBYTE: u8 = 9;
    pub const SIZE_FWORD_48: u8 = 10;
    pub const SIZE_FWORD_80: u8 = 11;

    pub const BROADCAST_NONE: u8 = 0;
    pub const BROADCAST_1TO2: u8 = 1;
    pub const BROADCAST_1TO4: u8 = 2;
    pub const BROADCAST_1TO8: u8 = 3;
    pub const BROADCAST_1TO16: u8 = 4;
    pub const BROADCAST_1TO32: u8 = 5;

    pub const BCST_FORCE: u32 = 1 << 30;
    pub const NO_PTR: u32 = 1 << 31;
}
