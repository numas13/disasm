#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(non_camel_case_types)]

use crate::{utils::zextract, Insn, Opcode};

pub mod opcode {
    pub use crate::Opcode;

    pub const INVALID: Opcode = Opcode(0);

    pub(super) const BASE_OPCODE: u32 = 4096;

    include!(concat!(env!("OUT_DIR"), "/arch/x86/generated_opcodes.rs"));
}

include!(concat!(env!("OUT_DIR"), "/arch/x86/generated_set.rs"));

include!(concat!(env!("OUT_DIR"), "/arch/x86/generated_decode.rs"));

include!(concat!(
    env!("OUT_DIR"),
    "/arch/x86/generated_decode_vex.rs"
));

include!(concat!(
    env!("OUT_DIR"),
    "/arch/x86/generated_decode_evex.rs"
));
