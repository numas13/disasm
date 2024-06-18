use std::{
    borrow::Cow,
    collections::HashSet,
    fs::{self, File},
    io::{self, BufWriter, Write},
    path::Path,
};

use decodetree::{
    gen::{Gen, Generator, Pad},
    Pattern, ValueKind,
};

#[derive(Default)]
struct Helper {
    args: HashSet<String>,
}

impl Helper {
    fn pass_arg(name: &str) -> bool {
        name != "alias"
    }
}

impl<T> Gen<T> for Helper {
    fn pass_arg(&self, name: &str) -> bool {
        Self::pass_arg(name)
    }

    fn additional_args(&self) -> &[(&str, &str)] {
        &[("address", "u64"), ("out", "&mut Insn")]
    }

    fn gen_trans_body<W: Write>(
        &mut self,
        out: &mut W,
        pad: Pad,
        pattern: &Pattern<T>,
    ) -> io::Result<bool> {
        let p = pad.shift();
        writeln!(out, " {{")?;
        let name = pattern.name.to_uppercase();
        writeln!(out, "{p}out.set_opcode(opcode::{name});")?;
        for set in pattern.sets.iter().filter(|i| !i.is_extern) {
            writeln!(out, "{p}self.set_args(address, out, {});", set.name)?;
        }
        for arg in pattern.args.iter().filter(|i| Self::pass_arg(&i.name)) {
            let name = &arg.name;
            if !self.args.contains(name) {
                self.args.insert(name.clone());
            }
            writeln!(out, "{p}self.set_{name}(address, out, {name} as i64);")?;
        }
        writeln!(out, "{p}true")?;
        writeln!(out, "{pad}}}")?;
        Ok(true)
    }

    fn gen_trait_body<W: Write>(&mut self, out: &mut W, pad: Pad) -> io::Result<()> {
        writeln!(out)?;
        writeln!(
            out,
            "{pad}fn set_args<A: Args>(&mut self, address: u64, out: &mut Insn, args: A);"
        )?;
        writeln!(out, "{pad}fn opts(&self) -> &Options;")?;

        if !self.args.is_empty() {
            writeln!(out)?;
            for i in &self.args {
                writeln!(
                    out,
                    "{pad}fn set_{i}(&mut self, address: u64, out: &mut Insn, {i}: i64);"
                )?;
            }
        }

        Ok(())
    }

    fn additional_cond(&self, pattern: &Pattern<T>) -> Option<Cow<'static, str>> {
        // decode aliases only if enabled
        if let Some(arg) = pattern.args.iter().find(|i| i.name == "alias") {
            if let ValueKind::Const(val) = arg.kind {
                if val != 0 {
                    return Some(Cow::Borrowed("self.opts().alias"));
                }
            }
        }
        None
    }

    fn gen_on_success<W: Write>(
        &mut self,
        out: &mut W,
        pad: Pad,
        pattern: &Pattern<T>,
    ) -> io::Result<()> {
        // set alias flag if pattern has alias=1
        if let Some(arg) = pattern.args.iter().find(|i| i.name == "alias") {
            if let ValueKind::Const(val) = arg.kind {
                if val != 0 {
                    writeln!(out, "{pad}out.set_alias();")?;
                }
            }
        }
        Ok(())
    }

    fn gen_opcodes<W: Write>(
        &mut self,
        out: &mut W,
        pad: Pad,
        opcodes: &HashSet<&str>,
    ) -> io::Result<()> {
        let opcodes = {
            let mut vec: Vec<_> = opcodes.iter().collect();
            vec.sort();
            vec
        };

        writeln!(out)?;
        writeln!(out, "{pad}pub mod opcode {{")?;
        {
            let pad = pad.shift();
            writeln!(out, "{pad}use super::Opcode;")?;
            writeln!(out, "{pad}pub const INVALID: Opcode = Opcode(0);")?;
            for (i, s) in opcodes.iter().enumerate() {
                writeln!(
                    out,
                    "{pad}pub const {}: Opcode = Opcode({});",
                    s.to_uppercase(),
                    i + 1
                )?;
            }
        }
        writeln!(out, "{pad}}}")?; // pub mod opcode

        writeln!(out)?;
        writeln!(out, "{pad}#[cfg(feature = \"mnemonic\")]")?;
        writeln!(
            out,
            "{pad}pub fn mnemonic(opcode: Opcode) -> Option<&'static str> {{"
        )?;
        {
            let pad = pad.shift();
            writeln!(out, "{pad}Some(match opcode {{")?;
            {
                let pad = pad.shift();
                for i in opcodes {
                    write!(out, "{pad}opcode::{} => \"", i.to_uppercase())?;
                    for c in i.chars() {
                        match c {
                            '_' => write!(out, ".")?,
                            _ => write!(out, "{}", c)?,
                        }
                    }
                    writeln!(out, "\",")?;
                }
                writeln!(out, "{pad}_ => return None,")?;
            }
            writeln!(out, "{pad}}})")?; // match
        }
        writeln!(out, "{pad}}}")?; // fn mnemonic

        Ok(())
    }
}

fn gen<T>(trait_name: &str, path: &str, out: &str)
where
    T: Default + std::hash::Hash + std::fmt::LowerHex + Ord + decodetree::Insn,
{
    println!("cargo:rerun-if-changed={path}");

    let src = fs::read_to_string(path).unwrap();
    let tree = match decodetree::parse::<T>(&src) {
        Ok(tree) => tree,
        Err(errors) => {
            for err in errors.iter(path) {
                eprintln!("{err}");
            }
            std::process::exit(1);
        }
    };
    if let Some(parent) = Path::new(out).parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let mut out = BufWriter::new(File::create(out).unwrap());

    Generator::<T, Helper>::builder()
        .trait_name(trait_name)
        .build(&tree, Helper::default())
        .gen(&mut out)
        .unwrap();
}

fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();

    #[cfg(feature = "riscv")]
    gen::<u32>(
        "RiscvDecode",
        "src/arch/riscv/insn.decode",
        &format!("{out_dir}/arch/riscv/decode.rs"),
    );
}
