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
    sets: HashSet<String>,
    cond: HashSet<String>,
}

impl Helper {
    fn is_cond(s: &str) -> bool {
        s == "alias" || s.starts_with("has_")
    }
}

impl<T> Gen<T> for Helper {
    fn pass_arg(&self, name: &str) -> bool {
        !Self::is_cond(name)
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
        for i in pattern.args.iter() {
            let name = &i.name;
            if Self::is_cond(name) {
                if !self.cond.contains(name) {
                    self.cond.insert(name.clone());
                }
            } else if i.is_set() {
                if !self.sets.contains(name) {
                    self.sets.insert(name.clone());
                }
                writeln!(out, "{p}self.set_args_{name}(address, out, {name});")?;
            } else {
                if !self.args.contains(name) {
                    self.args.insert(name.clone());
                }
                writeln!(out, "{p}self.set_{name}(address, out, {name} as i64);")?;
            }
        }
        writeln!(out, "{p}true")?;
        writeln!(out, "{pad}}}")?;
        Ok(true)
    }

    fn gen_trait_body<W: Write>(&mut self, out: &mut W, pad: Pad) -> io::Result<()> {
        if !self.args.is_empty() {
            writeln!(out)?;
            for i in &self.args {
                writeln!(
                    out,
                    "{pad}fn set_{i}(&mut self, address: u64, out: &mut Insn, {i}: i64);"
                )?;
            }
        }

        if !self.sets.is_empty() {
            writeln!(out)?;
            for i in &self.sets {
                writeln!(
                    out,
                    "{pad}fn set_args_{i}(&mut self, address: u64, out: &mut Insn, args: &args_{i});"
                )?;
            }
        }

        if !self.cond.is_empty() {
            writeln!(out)?;
            for i in &self.cond {
                writeln!(out, "{pad}fn {i}(&self) -> bool;")?;
            }
        }

        Ok(())
    }

    fn additional_cond(&self, pattern: &Pattern<T>) -> Option<Cow<'static, str>> {
        if pattern.args.iter().any(|i| Self::is_cond(&i.name)) {
            let mut out = String::new();
            for i in pattern.args.iter().filter(|i| Self::is_cond(&i.name)) {
                if let ValueKind::Const(val) = i.kind {
                    if !out.is_empty() {
                        out.push_str(" && ");
                    }
                    if val == 0 {
                        out.push('!');
                    }
                    out.push_str("self.");
                    out.push_str(&i.name);
                    out.push_str("()");
                }
            }
            return Some(Cow::Owned(out));
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
