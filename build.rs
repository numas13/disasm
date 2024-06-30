use std::{
    collections::{
        hash_map::{Entry, HashMap},
        HashSet,
    },
    fs::{self, File},
    io::{self, BufWriter, Write},
    path::Path,
    process,
};

use decodetree::{
    gen::{Gen, Pad},
    Insn, Parser, Pattern,
};

#[cfg(not(any(feature = "riscv")))]
compile_error!("enable at least one arch");

#[derive(Default)]
struct UserGen<'src> {
    generate: Generate<'src>,

    args: HashSet<String>,
    sets: HashSet<String>,
    formats: HashMap<String, Vec<(String, String)>>,

    set_args: String,
    set_args_def: String,

    value_type: String,
}

impl<'src> UserGen<'src> {
    fn new(generate: Generate<'src>) -> Self {
        let mut set_args = String::from("");
        let mut set_args_def = String::from("&mut self");

        for (i, (arg, ty)) in Self::shared_args().iter().enumerate() {
            if i != 0 {
                set_args.push_str(", ");
            }
            set_args.push_str(arg);

            set_args_def.push_str(", ");
            set_args_def.push_str(arg);
            set_args_def.push_str(": ");
            set_args_def.push_str(ty);
        }

        Self {
            generate,
            set_args,
            set_args_def,
            value_type: generate.value_type.into(),
            ..Self::default()
        }
    }

    fn shared_args() -> &'static [(&'static str, &'static str)] {
        &[("out", "&mut Insn")]
    }
}

impl<'src, T> Gen<T, &'src str> for UserGen<'src> {
    fn trait_attrs(&self) -> &[&str] {
        &["#[allow(clippy::too_many_arguments)]"]
    }

    fn decode_args(&self) -> &[(&str, &str)] {
        Self::shared_args()
    }

    fn cond_args(&self, name: &str) -> &[(&str, &str)] {
        if name.starts_with("is_") {
            &[("insn", "RawInsn")]
        } else {
            &[]
        }
    }

    fn trans_proto_check(&self, _: &str) -> bool {
        // do not generate translate functions
        false
    }

    fn trait_body<W: Write>(&mut self, out: &mut W, mut pad: Pad) -> io::Result<()> {
        let set_args = &self.set_args_def;

        if !self.args.is_empty() {
            writeln!(out)?;
        }
        for i in &self.args {
            writeln!(
                out,
                "{pad}fn set_{i}({set_args}, {i}: {});",
                self.value_type
            )?;
        }

        if !self.sets.is_empty() {
            writeln!(out)?;
        }
        for i in &self.sets {
            writeln!(out, "{pad}fn set_args_{i}({set_args}, args: args_{i});")?;
        }

        for (name, args) in &self.formats {
            writeln!(out)?;
            write!(out, "{pad}fn {name}({set_args}, opcode: Opcode")?;
            for (arg, ty) in args {
                write!(out, ", {arg}: {ty}")?;
            }
            writeln!(out, ") {{")?;
            pad.right();

            writeln!(out, "{pad}out.set_opcode(opcode);")?;

            for (arg, ty) in args {
                let prefix = if ty.starts_with("args_") { "args_" } else { "" };
                writeln!(
                    out,
                    "{pad}self.set_{prefix}{arg}({}, {arg});",
                    self.set_args
                )?;
            }
            pad.left();
            writeln!(out, "{pad}}}")?;
        }

        Ok(())
    }

    fn trans_success<W: Write>(
        &mut self,
        out: &mut W,
        pad: Pad,
        pattern: &Pattern<T, &'src str>,
    ) -> io::Result<()> {
        // set alias flag if pattern has alias condition
        if let Some(cond) = pattern.conditions().iter().find(|i| *i.name() == "alias") {
            if !cond.invert() {
                writeln!(out, "{pad}out.set_alias();")?;
            }
        }

        let mut format = String::from("format");
        for value in pattern.values() {
            let name = value.name();
            let hash_set = if value.is_set() {
                &mut self.sets
            } else {
                &mut self.args
            };
            if !hash_set.contains(*name) {
                hash_set.insert(name.to_string());
            }
            format.push('_');
            format.push_str(name);
        }

        write!(out, "{pad}self.{format}({}", self.set_args)?;
        write!(out, ", opcode::{}", pattern.name().to_uppercase())?;

        for value in pattern.values() {
            write!(out, ", {}", value.name())?;
        }
        writeln!(out, ");")?;

        if let Entry::Vacant(e) = self.formats.entry(format) {
            let mut args = Vec::new();
            for value in pattern.values() {
                let name = String::from(*value.name());
                let ty = if value.is_set() {
                    format!("args_{name}")
                } else {
                    self.value_type.clone()
                };
                args.push((name, ty));
            }
            e.insert(args);
        }

        Ok(())
    }

    fn end<W: Write>(
        &mut self,
        out: &mut W,
        mut pad: Pad,
        opcodes: &HashSet<&str>,
    ) -> io::Result<()> {
        writeln!(out, "type RawInsn = {};", self.generate.insn_type)?;

        let opcodes = {
            let mut vec: Vec<_> = opcodes.iter().collect();
            vec.sort();
            vec
        };

        writeln!(out)?;
        writeln!(out, "{pad}pub mod opcode_generated {{")?;
        pad.right();
        writeln!(out, "{pad}use super::opcode::{{Opcode, BASE_OPCODE}};")?;
        for (i, s) in opcodes.iter().enumerate() {
            write!(out, "{pad}pub const {}: Opcode = Opcode(", s.to_uppercase())?;
            write!(out, "BASE_OPCODE")?;
            if i > 0 {
                write!(out, " + {i}")?;
            }
            writeln!(out, ");")?;
        }
        pad.left();
        writeln!(out, "{pad}}}")?; // pub mod opcode

        writeln!(out)?;
        writeln!(out, "{pad}#[cfg(feature = \"mnemonic\")]")?;
        writeln!(
            out,
            "{pad}pub fn mnemonic(opcode: Opcode) -> Option<&'static str> {{"
        )?;
        pad.right();
        writeln!(out, "{pad}Some(match opcode {{")?;
        pad.right();
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
        pad.left();
        writeln!(out, "{pad}}})")?; // match
        pad.left();
        writeln!(out, "{pad}}}")?; // fn mnemonic

        Ok(())
    }
}

#[derive(Copy, Clone)]
struct Generate<'a> {
    source: &'a str,
    trait_name: &'a str,
    insn_type: &'a str,
    insn_size: &'a [u32],
    value_type: &'a str,
    optimize: bool,
    stubs: bool,
    variable_size: bool,
}

impl Default for Generate<'_> {
    fn default() -> Self {
        Self {
            source: "",
            trait_name: "Decode",
            insn_type: "u32",
            insn_size: &[32],
            value_type: "i32",
            optimize: true,
            stubs: false,
            variable_size: false,
        }
    }
}

impl<'a> Generate<'a> {
    fn gen<T: Insn>(self, out: impl AsRef<Path>) {
        println!("cargo:rerun-if-changed={}", self.source);

        let src = fs::read_to_string(self.source).unwrap();
        let parser = Parser::<T, &str>::new(&src).set_insn_size(self.insn_size);
        let mut tree = match parser.parse() {
            Ok(tree) => tree,
            Err(errors) => {
                for err in errors.iter(self.source) {
                    eprintln!("{err}");
                }
                process::exit(1);
            }
        };
        if self.optimize {
            tree.optimize();
        }

        if let Some(parent) = out.as_ref().parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut out = BufWriter::new(File::create(&out).unwrap());

        decodetree::Generator::builder()
            .trait_name(self.trait_name)
            .insn_type(self.insn_type)
            .value_type(self.value_type)
            .stubs(self.stubs)
            .variable_size(self.variable_size)
            .build(&tree, UserGen::new(self))
            .generate(&mut out)
            .unwrap();
    }
}

fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();

    #[cfg(feature = "riscv")]
    Generate {
        source: "src/arch/riscv/insn.decode",
        trait_name: "RiscvDecode",
        insn_size: &[16, 32],
        insn_type: "u32",
        value_type: "i32",
        ..Generate::default()
    }
    .gen::<u32>(format!("{out_dir}/arch/riscv/generated.rs"));
}
