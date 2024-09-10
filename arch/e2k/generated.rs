#![allow(dead_code)]
#![allow(unused_variables)]

use disasm_core::{
    insn::{Insn, Opcode},
    utils::zextract,
};

pub mod opcode {
    use disasm_core::insn::Opcode;

    pub const INVALID: Opcode = Opcode::INVALID;
    pub const BUNDLE_END: Opcode = Opcode(1);
    pub const HS: Opcode = Opcode(2);
    pub const SS: Opcode = Opcode(3);
    pub const CS: Opcode = Opcode(4);
    pub const ALS: Opcode = Opcode(6);
    pub const AAS: Opcode = Opcode(7);
    pub const LTS: Opcode = Opcode(8);
    pub const PLS: Opcode = Opcode(9);
    pub const CDS: Opcode = Opcode(10);
    pub const NOP: Opcode = Opcode(11);
    pub const LOOP_MODE: Opcode = Opcode(12);
    pub const ALC: Opcode = Opcode(13);
    pub const ABP: Opcode = Opcode(14);
    pub const ABN: Opcode = Opcode(15);
    pub const ABG: Opcode = Opcode(16);
    pub const BAP: Opcode = Opcode(17);
    pub const EAP: Opcode = Opcode(18);
    pub const INCR: Opcode = Opcode(19);
    pub const SETWD: Opcode = Opcode(20);
    pub const SETBP: Opcode = Opcode(21);
    pub const SETBN: Opcode = Opcode(22);
    pub const SETTR: Opcode = Opcode(23);
    pub const VFRPSZ: Opcode = Opcode(24);
    pub const SETEI: Opcode = Opcode(25);
    pub const SETSFT: Opcode = Opcode(26);
    pub const WAIT: Opcode = Opcode(27);
    pub const FLUSH_R: Opcode = Opcode(28);
    pub const FLUSH_C: Opcode = Opcode(29);
    pub const VFBG: Opcode = Opcode(30);
    pub const PREP_CT: Opcode = Opcode(31);
    pub const PREP_APB: Opcode = Opcode(32);
    pub const PREP_SYS: Opcode = Opcode(33);
    pub const PREP_RET: Opcode = Opcode(34);
    pub const IBRANCH: Opcode = Opcode(35);
    pub const PREF: Opcode = Opcode(36);
    pub const PUTTSD: Opcode = Opcode(37);
    pub const GETTSD: Opcode = Opcode(38);
    pub const DONE: Opcode = Opcode(39);
    pub const IRET: Opcode = Opcode(40);
    pub const PREP_CALL: Opcode = Opcode(41);
    pub const ANDP: Opcode = Opcode(42);
    pub const LANDP: Opcode = Opcode(43);
    pub const MOVEP: Opcode = Opcode(44);
    pub const CT: Opcode = Opcode(45);
    pub const CALL: Opcode = Opcode(46);
    pub const ICALL: Opcode = Opcode(47);
    pub const HRET: Opcode = Opcode(48);
    pub const GLAUNCH: Opcode = Opcode(49);
    pub const INVALID_CT: Opcode = Opcode(50);
    pub const APB: Opcode = Opcode(51);
    pub const MOVAB: Opcode = Opcode(52);
    pub const MOVAH: Opcode = Opcode(53);
    pub const MOVAW: Opcode = Opcode(54);
    pub const MOVAD: Opcode = Opcode(55);
    pub const MOVAQ: Opcode = Opcode(56);
    pub const MOVAQP: Opcode = Opcode(57);
    pub const IPD: Opcode = Opcode(58);
    pub const RBRANCH: Opcode = Opcode(59);

    pub(super) const BASE_OPCODE: u32 = 4096;

    include!(concat!(env!("OUT_DIR"), "/generated_opcodes.rs"));
}

include!(concat!(env!("OUT_DIR"), "/generated_set.rs"));

include!(concat!(env!("OUT_DIR"), "/generated_decode_alop.rs"));
