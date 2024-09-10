use disasm_gen::{Arch, DecodeOptions};

fn main() {
    let arch = Arch::new("riscv")
        .value_type("i32")
        .decode(
            "insn16.decode",
            "generated_decode16.rs",
            DecodeOptions {
                trait_name: "RiscvDecode16",
                insn_size: &[16],
                insn_type: "u16",
                ..DecodeOptions::default()
            },
        )
        .decode(
            "insn32.decode",
            "generated_decode32.rs",
            DecodeOptions {
                trait_name: "RiscvDecode32",
                insn_size: &[32],
                insn_type: "u32",
                ..DecodeOptions::default()
            },
        );

    if let Err(err) = arch.generate() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
