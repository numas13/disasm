use disasm_gen::{Arch, DecodeOptions};

fn main() {
    let arch = Arch::new("e2k")
        .mnemonic_dot(false)
        .value_type("i32")
        .decode(
            "alop.decode",
            "generated_decode_alop.rs",
            DecodeOptions {
                trait_name: "E2KDecodeAlop",
                insn_size: &[32 + 16 + 3 + 7],
                insn_type: "u64",
                ..DecodeOptions::default()
            },
        );

    if let Err(err) = arch.generate() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
