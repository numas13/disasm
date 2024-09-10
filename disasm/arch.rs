#[cfg(feature = "e2k")]
pub mod e2k {
    pub use disasm_e2k::*;
}

#[cfg(feature = "riscv")]
pub mod riscv {
    pub use disasm_riscv::*;
}

#[cfg(feature = "x86")]
pub mod x86 {
    pub use disasm_x86::*;
}
