#![allow(dead_code)]
#![allow(unused_variables)]

use crate::{
    utils::{sextract, zextract},
    Insn, Opcode,
};

pub mod opcode {
    pub use super::opcode_generated::*;
    pub use crate::Opcode;

    pub const INVALID: Opcode = Opcode(0);

    pub const FMV_S: Opcode = Opcode(1);
    pub const FMV_D: Opcode = Opcode(2);
    pub const FABS_S: Opcode = Opcode(3);
    pub const FABS_D: Opcode = Opcode(4);
    pub const FNEG_S: Opcode = Opcode(5);
    pub const FNEG_D: Opcode = Opcode(6);

    pub(super) const BASE_OPCODE: u32 = 4096;
}

include!(concat!(env!("OUT_DIR"), "/arch/riscv/decode.rs"));
