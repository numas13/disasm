#![allow(dead_code)]
#![allow(unused_variables)]

use crate::{
    utils::{sextract, zextract},
    Insn, Opcode, Options,
};

use super::RiscvDecoder;

pub trait Args {
    fn set(&self, dec: &RiscvDecoder, address: u64, insn: &mut Insn);
}

include!(concat!(env!("OUT_DIR"), "/arch/riscv/decode.rs"));
