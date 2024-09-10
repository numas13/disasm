use disasm_gen::{Arch, DecodeOptions};

fn main() {
    let arch = Arch::new("x86")
        .value_type("i32")
        .set_return_error(true)
        .mnemonic_dot(false)
        .decode(
            "insn.decode",
            "generated_decode.rs",
            DecodeOptions {
                trait_name: "X86Decode",
                insn_size: &[24, 32],
                variable_size: true,
                insn_type: "u64",
                ..DecodeOptions::default()
            },
        )
        .decode(
            "insn_vex.decode",
            "generated_decode_vex.rs",
            DecodeOptions {
                trait_name: "X86DecodeVex",
                insn_size: &[32],
                insn_type: "u64",
                ..DecodeOptions::default()
            },
        )
        .decode(
            "insn_evex.decode",
            "generated_decode_evex.rs",
            DecodeOptions {
                trait_name: "X86DecodeEvex",
                insn_size: &[40],
                insn_type: "u64",
                ..DecodeOptions::default()
            },
        );

    if let Err(err) = arch.generate() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
