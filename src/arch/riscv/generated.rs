#![allow(dead_code)]
#![allow(unused_variables)]

use crate::{
    utils::{sextract, zextract},
    Insn, Opcode,
};

pub mod opcode {
    pub use crate::Opcode;

    pub const INVALID: Opcode = Opcode(0);

    pub(super) const BASE_OPCODE: u32 = 4096;

    include!(concat!(env!("OUT_DIR"), "/arch/riscv/generated_opcodes.rs"));
}

include!(concat!(env!("OUT_DIR"), "/arch/riscv/generated.rs"));
