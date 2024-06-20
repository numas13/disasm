#![allow(dead_code)]
#![allow(unused_variables)]

use crate::{
    utils::{sextract, zextract},
    Insn, Opcode,
};

include!(concat!(env!("OUT_DIR"), "/arch/riscv/decode.rs"));
