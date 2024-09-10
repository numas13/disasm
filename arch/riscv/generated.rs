#![allow(dead_code)]
#![allow(unused_variables)]

use disasm_core::{
    insn::{Insn, Opcode},
    utils::{sextract, zextract},
};

pub mod opcode {
    use disasm_core::insn::Opcode;

    pub const INVALID: Opcode = Opcode::INVALID;

    pub(super) const BASE_OPCODE: u32 = 4096;

    include!(concat!(env!("OUT_DIR"), "/generated_opcodes.rs"));
}

include!(concat!(env!("OUT_DIR"), "/generated_set.rs"));

include!(concat!(env!("OUT_DIR"), "/generated_decode16.rs"));

include!(concat!(env!("OUT_DIR"), "/generated_decode32.rs"));