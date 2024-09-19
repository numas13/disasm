#![allow(dead_code)]
#![allow(unused_variables)]

use disasm_core::{
    insn::{Insn, Opcode},
    utils::zextract,
};

pub mod opcode {
    use disasm_core::{insn::Opcode, macros::define_opcodes};

    pub const INVALID: Opcode = Opcode::INVALID;

    pub(super) const BASE_OPCODE: u32 = 4096;

    define_opcodes! {
        BUNDLE_END      = "--",
        INVALID_CT      = "<invalid ct>",
        HS              = "hs",
        SS              = "ss",
        CS              = "cs",
        ALS             = "als",
        AAS             = "aas",
        LTS             = "lts",
        PLS             = "pls",
        CDS             = "cds",
        NOP             = "nop",
        LOOP_MODE       = "loop_mode",
        ALC             = "alc",
        ABP             = "abp",
        ABN             = "abn",
        ABG             = "abg",
        BAP             = "bap",
        EAP             = "eap",
        INCR            = "incr",
        SETWD           = "setwd",
        SETBP           = "setbp",
        SETBN           = "setbn",
        SETTR           = "settr",
        VFRPSZ          = "vfrpsz",
        SETEI           = "setei",
        SETSFT          = "setsft",
        WAIT            = "wait",
        FLUSH_R         = "flush",
        FLUSH_C         = "flush",
        VFBG            = "vfbg",
        PREP_CT         = "prep",
        PREP_CALL       = "prep",
        PREP_APB        = "prep",
        PREP_SYS        = "prep",
        PREP_RET        = "prep",
        IBRANCH         = "ibranch",
        RBRANCH         = "rbranch",
        PREF            = "pref",
        PUTTSD          = "puttsd",
        GETTSD          = "gettsd",
        DONE            = "done",
        IRET            = "iret",
        ANDP            = "andp",
        LANDP           = "landp",
        MOVEP           = "movep",
        CT              = "ct",
        CALL            = "call",
        ICALL           = "icall",
        HRET            = "hret",
        GLAUNCH         = "glaunch",
        MOVAB           = "movab",
        MOVAH           = "movah",
        MOVAW           = "movaw",
        MOVAD           = "movad",
        MOVAQ           = "movaq",
        MOVAQP          = "movaqp",
        APB             = "apb",
        IPD             = "ipd",
    }

    include!(concat!(env!("OUT_DIR"), "/generated_opcodes.rs"));

    #[inline(always)]
    pub(crate) fn mnemonic(opcode: Opcode) -> Option<&'static str> {
        defined_mnemonic(opcode).or_else(|| generated_mnemonic(opcode))
    }
}

include!(concat!(env!("OUT_DIR"), "/generated_set.rs"));

include!(concat!(env!("OUT_DIR"), "/generated_decode_alop.rs"));
