/// Custom instruction flags
pub mod insn {
    pub const INSN_AQ: u32 = 1 << 16;
    pub const INSN_RL: u32 = 1 << 17;
}

/// Custom register classes
pub mod reg_class {
    use crate::RegClass;

    pub const CSR: RegClass = RegClass::arch(0);
}

/// Custom operands
pub mod operand {
    disasm_core::macros::impl_arch_operands! {
        pub enum RiscvOperand {
            Fence = 0,
            RM = 1,
        }
    }

    // rm values for fops
    pub const RM_RNE: u8 = 0;
    pub const RM_RTZ: u8 = 1;
    pub const RM_RDN: u8 = 2;
    pub const RM_RUP: u8 = 3;
    pub const RM_RMM: u8 = 4;
    pub const RM_DYN: u8 = 7;
}
