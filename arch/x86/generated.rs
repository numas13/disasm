#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(non_camel_case_types)]

use disasm_core::{
    insn::{Insn, Opcode},
    utils::zextract,
};

pub mod opcode {
    use disasm_core::{insn::Opcode, macros::define_opcodes};

    pub const INVALID: Opcode = Opcode::INVALID;

    pub(super) const BASE_OPCODE: u32 = 4096;

    define_opcodes! {
        CMPEQPS             = "cmpeqps",
        CMPLTPS             = "cmpltps",
        CMPLEPS             = "cmpleps",
        CMPUNORDPS          = "cmpunordps",
        CMPNEQPS            = "cmpneqps",
        CMPNLTPS            = "cmpnltps",
        CMPNLEPS            = "cmpnleps",
        CMPORDPS            = "cmpordps",
        CMPEQSS             = "cmpeqss",
        CMPLTSS             = "cmpltss",
        CMPLESS             = "cmpless",
        CMPUNORDSS          = "cmpunordss",
        CMPNEQSS            = "cmpneqss",
        CMPNLTSS            = "cmpnltss",
        CMPNLESS            = "cmpnless",
        CMPORDSS            = "cmpordss",
        CMPEQPD             = "cmpeqpd",
        CMPLTPD             = "cmpltpd",
        CMPLEPD             = "cmplepd",
        CMPUNORDPD          = "cmpunordpd",
        CMPNEQPD            = "cmpneqpd",
        CMPNLTPD            = "cmpnltpd",
        CMPNLEPD            = "cmpnlepd",
        CMPORDPD            = "cmpordpd",
        CMPEQSD             = "cmpeqsd",
        CMPLTSD             = "cmpltsd",
        CMPLESD             = "cmplesd",
        CMPUNORDSD          = "cmpunordsd",
        CMPNEQSD            = "cmpneqsd",
        CMPNLTSD            = "cmpnltsd",
        CMPNLESD            = "cmpnlesd",
        CMPORDSD            = "cmpordsd",

        PCLMULLQLQDQ        = "pclmullqlqdq",
        PCLMULHQLQDQ        = "pclmulhqlqdq",
        PCLMULLQHQDQ        = "pclmullqhqdq",
        PCLMULHQHQDQ        = "pclmulhqhqdq",
        VPCLMULLQLQDQ       = "vpclmullqlqdq",
        VPCLMULHQLQDQ       = "vpclmulhqlqdq",
        VPCLMULLQHQDQ       = "vpclmullqhqdq",
        VPCLMULHQHQDQ       = "vpclmulhqhqdq",

        VCMPEQSS            = "vcmpeqss",
        VCMPLTSS            = "vcmpltss",
        VCMPLESS            = "vcmpless",
        VCMPUNORDSS         = "vcmpunordss",
        VCMPNEQSS           = "vcmpneqss",
        VCMPNLTSS           = "vcmpnltss",
        VCMPNLESS           = "vcmpnless",
        VCMPORDSS           = "vcmpordss",
        VCMPEQ_UQSS         = "vcmpeq_uqss",
        VCMPNGESS           = "vcmpngess",
        VCMPNGTSS           = "vcmpngtss",
        VCMPFALSESS         = "vcmpfalsess",
        VCMPNEQ_OQSS        = "vcmpneq_oqss",
        VCMPGESS            = "vcmpgess",
        VCMPGTSS            = "vcmpgtss",
        VCMPTRUESS          = "vcmptruess",
        VCMPEQ_OSSS         = "vcmpeq_osss",
        VCMPLT_OQSS         = "vcmplt_oqss",
        VCMPLE_OQSS         = "vcmple_oqss",
        VCMPUNORD_SSS       = "vcmpunord_sss",
        VCMPNEQ_USSS        = "vcmpneq_usss",
        VCMPNLT_UQSS        = "vcmpnlt_uqss",
        VCMPNLE_UQSS        = "vcmpnle_uqss",
        VCMPORD_SSS         = "vcmpord_sss",
        VCMPEQ_USSS         = "vcmpeq_usss",
        VCMPNGE_UQSS        = "vcmpnge_uqss",
        VCMPNGT_UQSS        = "vcmpngt_uqss",
        VCMPFALSE_OSSS      = "vcmpfalse_osss",
        VCMPNEQ_OSSS        = "vcmpneq_osss",
        VCMPGE_OQSS         = "vcmpge_oqss",
        VCMPGT_OQSS         = "vcmpgt_oqss",
        VCMPTRUE_USSS       = "vcmptrue_usss",
        VCMPEQSD            = "vcmpeqsd",
        VCMPLTSD            = "vcmpltsd",
        VCMPLESD            = "vcmplesd",
        VCMPUNORDSD         = "vcmpunordsd",
        VCMPNEQSD           = "vcmpneqsd",
        VCMPNLTSD           = "vcmpnltsd",
        VCMPNLESD           = "vcmpnlesd",
        VCMPORDSD           = "vcmpordsd",
        VCMPEQ_UQSD         = "vcmpeq_uqsd",
        VCMPNGESD           = "vcmpngesd",
        VCMPNGTSD           = "vcmpngtsd",
        VCMPFALSESD         = "vcmpfalsesd",
        VCMPNEQ_OQSD        = "vcmpneq_oqsd",
        VCMPGESD            = "vcmpgesd",
        VCMPGTSD            = "vcmpgtsd",
        VCMPTRUESD          = "vcmptruesd",
        VCMPEQ_OSSD         = "vcmpeq_ossd",
        VCMPLT_OQSD         = "vcmplt_oqsd",
        VCMPLE_OQSD         = "vcmple_oqsd",
        VCMPUNORD_SSD       = "vcmpunord_ssd",
        VCMPNEQ_USSD        = "vcmpneq_ussd",
        VCMPNLT_UQSD        = "vcmpnlt_uqsd",
        VCMPNLE_UQSD        = "vcmpnle_uqsd",
        VCMPORD_SSD         = "vcmpord_ssd",
        VCMPEQ_USSD         = "vcmpeq_ussd",
        VCMPNGE_UQSD        = "vcmpnge_uqsd",
        VCMPNGT_UQSD        = "vcmpngt_uqsd",
        VCMPFALSE_OSSD      = "vcmpfalse_ossd",
        VCMPNEQ_OSSD        = "vcmpneq_ossd",
        VCMPGE_OQSD         = "vcmpge_oqsd",
        VCMPGT_OQSD         = "vcmpgt_oqsd",
        VCMPTRUE_USSD       = "vcmptrue_ussd",
        VCMPEQPS            = "vcmpeqps",
        VCMPLTPS            = "vcmpltps",
        VCMPLEPS            = "vcmpleps",
        VCMPUNORDPS         = "vcmpunordps",
        VCMPNEQPS           = "vcmpneqps",
        VCMPNLTPS           = "vcmpnltps",
        VCMPNLEPS           = "vcmpnleps",
        VCMPORDPS           = "vcmpordps",
        VCMPEQ_UQPS         = "vcmpeq_uqps",
        VCMPNGEPS           = "vcmpngeps",
        VCMPNGTPS           = "vcmpngtps",
        VCMPFALSEPS         = "vcmpfalseps",
        VCMPNEQ_OQPS        = "vcmpneq_oqps",
        VCMPGEPS            = "vcmpgeps",
        VCMPGTPS            = "vcmpgtps",
        VCMPTRUEPS          = "vcmptrueps",
        VCMPEQ_OSPS         = "vcmpeq_osps",
        VCMPLT_OQPS         = "vcmplt_oqps",
        VCMPLE_OQPS         = "vcmple_oqps",
        VCMPUNORD_SPS       = "vcmpunord_sps",
        VCMPNEQ_USPS        = "vcmpneq_usps",
        VCMPNLT_UQPS        = "vcmpnlt_uqps",
        VCMPNLE_UQPS        = "vcmpnle_uqps",
        VCMPORD_SPS         = "vcmpord_sps",
        VCMPEQ_USPS         = "vcmpeq_usps",
        VCMPNGE_UQPS        = "vcmpnge_uqps",
        VCMPNGT_UQPS        = "vcmpngt_uqps",
        VCMPFALSE_OSPS      = "vcmpfalse_osps",
        VCMPNEQ_OSPS        = "vcmpneq_osps",
        VCMPGE_OQPS         = "vcmpge_oqps",
        VCMPGT_OQPS         = "vcmpgt_oqps",
        VCMPTRUE_USPS       = "vcmptrue_usps",
        VCMPEQPD            = "vcmpeqpd",
        VCMPLTPD            = "vcmpltpd",
        VCMPLEPD            = "vcmplepd",
        VCMPUNORDPD         = "vcmpunordpd",
        VCMPNEQPD           = "vcmpneqpd",
        VCMPNLTPD           = "vcmpnltpd",
        VCMPNLEPD           = "vcmpnlepd",
        VCMPORDPD           = "vcmpordpd",
        VCMPEQ_UQPD         = "vcmpeq_uqpd",
        VCMPNGEPD           = "vcmpngepd",
        VCMPNGTPD           = "vcmpngtpd",
        VCMPFALSEPD         = "vcmpfalsepd",
        VCMPNEQ_OQPD        = "vcmpneq_oqpd",
        VCMPGEPD            = "vcmpgepd",
        VCMPGTPD            = "vcmpgtpd",
        VCMPTRUEPD          = "vcmptruepd",
        VCMPEQ_OSPD         = "vcmpeq_ospd",
        VCMPLT_OQPD         = "vcmplt_oqpd",
        VCMPLE_OQPD         = "vcmple_oqpd",
        VCMPUNORD_SPD       = "vcmpunord_spd",
        VCMPNEQ_USPD        = "vcmpneq_uspd",
        VCMPNLT_UQPD        = "vcmpnlt_uqpd",
        VCMPNLE_UQPD        = "vcmpnle_uqpd",
        VCMPORD_SPD         = "vcmpord_spd",
        VCMPEQ_USPD         = "vcmpeq_uspd",
        VCMPNGE_UQPD        = "vcmpnge_uqpd",
        VCMPNGT_UQPD        = "vcmpngt_uqpd",
        VCMPFALSE_OSPD      = "vcmpfalse_ospd",
        VCMPNEQ_OSPD        = "vcmpneq_ospd",
        VCMPGE_OQPD         = "vcmpge_oqpd",
        VCMPGT_OQPD         = "vcmpgt_oqpd",
        VCMPTRUE_USPD       = "vcmptrue_uspd",

        VPCMPEQUD           = "vpcmpequd",
        VPCMPLTUD           = "vpcmpltud",
        VPCMPLEUD           = "vpcmpleud",
        VPCMPNEQUD          = "vpcmpnequd",
        VPCMPNLTUD          = "vpcmpnltud",
        VPCMPNLEUD          = "vpcmpnleud",
        VPCMPLTD            = "vpcmpltd",
        VPCMPLED            = "vpcmpled",
        VPCMPNEQD           = "vpcmpneqd",
        VPCMPNLTD           = "vpcmpnltd",
        VPCMPNLED           = "vpcmpnled",
        VPCMPEQUB           = "vpcmpequb",
        VPCMPLTUB           = "vpcmpltub",
        VPCMPLEUB           = "vpcmpleub",
        VPCMPNEQUB          = "vpcmpnequb",
        VPCMPNLTUB          = "vpcmpnltub",
        VPCMPNLEUB          = "vpcmpnleub",
        VPCMPLTB            = "vpcmpltb",
        VPCMPLEB            = "vpcmpleb",
        VPCMPNEQB           = "vpcmpneqb",
        VPCMPNLTB           = "vpcmpnltb",
        VPCMPNLEB           = "vpcmpnleb",
        VPCMPEQUQ           = "vpcmpequq",
        VPCMPLTUQ           = "vpcmpltuq",
        VPCMPLEUQ           = "vpcmpleuq",
        VPCMPNEQUQ          = "vpcmpnequq",
        VPCMPNLTUQ          = "vpcmpnltuq",
        VPCMPNLEUQ          = "vpcmpnleuq",
        VPCMPLTQ            = "vpcmpltq",
        VPCMPLEQ            = "vpcmpleq",
        VPCMPNEQQ           = "vpcmpneqq",
        VPCMPNLTQ           = "vpcmpnltq",
        VPCMPNLEQ           = "vpcmpnleq",
        VPCMPEQUW           = "vpcmpequw",
        VPCMPLTUW           = "vpcmpltuw",
        VPCMPLEUW           = "vpcmpleuw",
        VPCMPNEQUW          = "vpcmpnequw",
        VPCMPNLTUW          = "vpcmpnltuw",
        VPCMPNLEUW          = "vpcmpnleuw",
        VPCMPLTW            = "vpcmpltw",
        VPCMPLEW            = "vpcmplew",
        VPCMPNEQW           = "vpcmpneqw",
        VPCMPNLTW           = "vpcmpnltw",
        VPCMPNLEW           = "vpcmpnlew",
        VCMPEQPH            = "vcmpeqph",
        VCMPLTPH            = "vcmpltph",
        VCMPLEPH            = "vcmpleph",
        VCMPUNORDPH         = "vcmpunordph",
        VCMPNEQPH           = "vcmpneqph",
        VCMPNLTPH           = "vcmpnltph",
        VCMPNLEPH           = "vcmpnleph",
        VCMPORDPH           = "vcmpordph",
        VCMPEQ_UQPH         = "vcmpeq_uqph",
        VCMPNGEPH           = "vcmpngeph",
        VCMPNGTPH           = "vcmpngtph",
        VCMPFALSEPH         = "vcmpfalseph",
        VCMPNEQ_OQPH        = "vcmpneq_oqph",
        VCMPGEPH            = "vcmpgeph",
        VCMPGTPH            = "vcmpgtph",
        VCMPTRUEPH          = "vcmptrueph",
        VCMPEQ_OSPH         = "vcmpeq_osph",
        VCMPLT_OQPH         = "vcmplt_oqph",
        VCMPLE_OQPH         = "vcmple_oqph",
        VCMPUNORD_SPH       = "vcmpunord_sph",
        VCMPNEQ_USPH        = "vcmpneq_usph",
        VCMPNLT_UQPH        = "vcmpnlt_uqph",
        VCMPNLE_UQPH        = "vcmpnle_uqph",
        VCMPORD_SPH         = "vcmpord_sph",
        VCMPEQ_USPH         = "vcmpeq_usph",
        VCMPNGE_UQPH        = "vcmpnge_uqph",
        VCMPNGT_UQPH        = "vcmpngt_uqph",
        VCMPFALSE_OSPH      = "vcmpfalse_osph",
        VCMPNEQ_OSPH        = "vcmpneq_osph",
        VCMPGE_OQPH         = "vcmpge_oqph",
        VCMPGT_OQPH         = "vcmpgt_oqph",
        VCMPTRUE_USPH       = "vcmptrue_usph",
        VCMPEQSH            = "vcmpeqsh",
        VCMPLTSH            = "vcmpltsh",
        VCMPLESH            = "vcmplesh",
        VCMPUNORDSH         = "vcmpunordsh",
        VCMPNEQSH           = "vcmpneqsh",
        VCMPNLTSH           = "vcmpnltsh",
        VCMPNLESH           = "vcmpnlesh",
        VCMPORDSH           = "vcmpordsh",
        VCMPEQ_UQSH         = "vcmpeq_uqsh",
        VCMPNGESH           = "vcmpngesh",
        VCMPNGTSH           = "vcmpngtsh",
        VCMPFALSESH         = "vcmpfalsesh",
        VCMPNEQ_OQSH        = "vcmpneq_oqsh",
        VCMPGESH            = "vcmpgesh",
        VCMPGTSH            = "vcmpgtsh",
        VCMPTRUESH          = "vcmptruesh",
        VCMPEQ_OSSH         = "vcmpeq_ossh",
        VCMPLT_OQSH         = "vcmplt_oqsh",
        VCMPLE_OQSH         = "vcmple_oqsh",
        VCMPUNORD_SSH       = "vcmpunord_ssh",
        VCMPNEQ_USSH        = "vcmpneq_ussh",
        VCMPNLT_UQSH        = "vcmpnlt_uqsh",
        VCMPNLE_UQSH        = "vcmpnle_uqsh",
        VCMPORD_SSH         = "vcmpord_ssh",
        VCMPEQ_USSH         = "vcmpeq_ussh",
        VCMPNGE_UQSH        = "vcmpnge_uqsh",
        VCMPNGT_UQSH        = "vcmpngt_uqsh",
        VCMPFALSE_OSSH      = "vcmpfalse_ossh",
        VCMPNEQ_OSSH        = "vcmpneq_ossh",
        VCMPGE_OQSH         = "vcmpge_oqsh",
        VCMPGT_OQSH         = "vcmpgt_oqsh",
        VCMPTRUE_USSH       = "vcmptrue_ussh",
    }

    include!(concat!(env!("OUT_DIR"), "/generated_opcodes.rs"));

    #[cfg(feature = "mnemonic")]
    #[inline(always)]
    pub(crate) fn mnemonic(opcode: Opcode) -> Option<&'static str> {
        defined_mnemonic(opcode).or_else(|| generated_mnemonic(opcode))
    }
}

include!(concat!(env!("OUT_DIR"), "/generated_set.rs"));
include!(concat!(env!("OUT_DIR"), "/generated_decode.rs"));
include!(concat!(env!("OUT_DIR"), "/generated_decode_0f.rs"));
include!(concat!(env!("OUT_DIR"), "/generated_decode_0f_38.rs"));
include!(concat!(env!("OUT_DIR"), "/generated_decode_0f_3a.rs"));
include!(concat!(env!("OUT_DIR"), "/generated_decode_vex.rs"));
include!(concat!(env!("OUT_DIR"), "/generated_decode_evex.rs"));
