use std::{
    collections::{
        hash_map::{Entry, HashMap},
        HashSet,
    },
    fmt::{self, Write as _},
    fs::{self, File},
    io::{self, BufWriter, Write},
    path::{Path, PathBuf},
    process,
};

use decodetree::{
    gen::{Gen, Pad},
    Parser, Pattern,
};

#[cfg(not(any(feature = "riscv")))]
compile_error!("enable at least one arch");

#[derive(Debug)]
enum ErrorKind {
    SourceFile(io::Error),
    OutputDir(io::Error),
    OutputFile(io::Error),
    Parse(String),
    Generate(io::Error),
}

#[derive(Debug)]
struct Error {
    path: PathBuf,
    kind: ErrorKind,
}

impl Error {
    fn new<S: Into<PathBuf>>(path: S, kind: ErrorKind) -> Self {
        Self {
            path: path.into(),
            kind,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        use ErrorKind as E;

        let path = self.path.display();
        match &self.kind {
            E::SourceFile(error) => {
                write!(fmt, "failed to read source file \"{path}\", {error}")
            }
            E::OutputDir(error) => {
                write!(fmt, "failed to create output directory \"{path}\", {error}")
            }
            E::OutputFile(error) => {
                write!(fmt, "failed to create output file \"{path}\", {error}")
            }
            E::Parse(errors) => errors.fmt(fmt),
            E::Generate(error) => {
                write!(fmt, "failed to generate output file \"{path}\", {error}")
            }
        }
    }
}

struct UserGen<'a> {
    generate: &'a Generate,
    opcodes: &'a mut HashSet<String>,

    args: HashSet<String>,
    sets: HashSet<String>,
    formats: HashMap<String, Vec<(String, String)>>,

    set_args: String,
    set_args_def: String,
}

impl<'a> UserGen<'a> {
    fn new(generate: &'a Generate, opcodes: &'a mut HashSet<String>) -> Self {
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
            opcodes,
            set_args,
            set_args_def,
            args: Default::default(),
            sets: Default::default(),
            formats: Default::default(),
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
        let ret = if self.generate.set_error {
            " -> Result<(), Self::Error>"
        } else {
            ""
        };
        let ty = &self.generate.value_type;

        if self.generate.variable_size {
            writeln!(out, "{pad}fn advance(&mut self, size: usize);")?;
        }

        if !self.args.is_empty() {
            writeln!(out)?;
        }
        for i in &self.args {
            writeln!(out, "{pad}fn set_{i}({set_args}, {i}: {ty}){ret};")?;
        }

        if !self.sets.is_empty() {
            writeln!(out)?;
        }
        for i in &self.sets {
            writeln!(
                out,
                "{pad}fn set_args_{i}({set_args}, args: args_{i}){ret};"
            )?;
        }

        for (name, args) in &self.formats {
            writeln!(out)?;
            write!(out, "{pad}fn {name}({set_args}, opcode: Opcode")?;
            for (arg, ty) in args {
                write!(out, ", {arg}: {ty}")?;
            }
            writeln!(out, "){ret} {{")?;
            pad.right();

            writeln!(out, "{pad}out.set_opcode(opcode);")?;

            for (arg, ty) in args {
                let prefix = if ty.starts_with("args_") { "args_" } else { "" };
                write!(out, "{pad}self.set_{prefix}{arg}({}, {arg})", self.set_args)?;
                if self.generate.set_error {
                    write!(out, "?")?;
                }
                writeln!(out, ";")?;
            }
            if self.generate.set_error {
                writeln!(out, "{pad}Ok(())")?;
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

        if self.generate.variable_size {
            writeln!(out, "{pad}self.advance({});", pattern.size())?;
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
        if self.generate.set_error {
            writeln!(out, ")?;")?;
        } else {
            writeln!(out, ");")?;
        }

        if let Entry::Vacant(e) = self.formats.entry(format) {
            let mut args = Vec::new();
            for value in pattern.values() {
                let name = String::from(*value.name());
                let ty = if value.is_set() {
                    format!("args_{name}")
                } else {
                    self.generate.value_type.to_owned()
                };
                args.push((name, ty));
            }
            e.insert(args);
        }

        Ok(())
    }

    fn end<W: Write>(&mut self, out: &mut W, pad: Pad, opcodes: &HashSet<&str>) -> io::Result<()> {
        self.opcodes.extend(opcodes.iter().map(|i| i.to_string()));
        writeln!(out, "{pad}type RawInsn = {};", self.generate.insn_type)?;
        Ok(())
    }
}

fn create_file(path: &Path) -> Result<File, Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| Error::new(parent, ErrorKind::OutputDir(error)))?;
    }
    File::create(path).map_err(|error| Error::new(path, ErrorKind::OutputFile(error)))
}

fn gen_opcodes_write<W: Write>(mut out: W, opcodes: HashSet<String>) -> io::Result<()> {
    let out = &mut out;
    let opcodes = {
        let mut vec: Vec<_> = opcodes.iter().collect();
        vec.sort();
        vec
    };

    writeln!(out)?;
    for (i, s) in opcodes.iter().enumerate() {
        write!(
            out,
            "pub const {}: Opcode = Opcode(BASE_OPCODE",
            s.to_uppercase()
        )?;
        if i > 0 {
            write!(out, " + {i}")?;
        }
        writeln!(out, ");")?;
    }

    writeln!(out)?;
    writeln!(out, "#[cfg(feature = \"mnemonic\")]")?;
    writeln!(
        out,
        "pub(crate) fn mnemonic(opcode: Opcode) -> Option<&'static str> {{"
    )?;
    let mut pad = Pad::default().right();
    writeln!(out, "{pad}Some(match opcode {{")?;
    pad.right();
    for i in opcodes {
        write!(out, "{pad}{} => \"", i.to_uppercase())?;
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
    writeln!(out, "}}")?; // fn mnemonic

    Ok(())
}

fn gen_opcodes(path: impl AsRef<Path>, opcodes: HashSet<String>) -> Result<(), Error> {
    let path = path.as_ref();
    let out = create_file(path).map(BufWriter::new)?;
    gen_opcodes_write(out, opcodes).map_err(|error| Error::new(path, ErrorKind::Generate(error)))
}

#[derive(Clone)]
struct Generate {
    source: &'static str,
    trait_name: &'static str,
    insn_type: &'static str,
    insn_size: &'static [u32],
    value_type: &'static str,
    optimize: bool,
    stubs: bool,
    variable_size: bool,
    set_error: bool,
}

impl Default for Generate {
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
            set_error: false,
        }
    }
}

impl Generate {
    fn gen(self, path: impl AsRef<Path>, opcodes: &mut HashSet<String>) -> Result<(), Error> {
        println!("cargo:rerun-if-changed={}", self.source);

        let path = path.as_ref();
        let src = fs::read_to_string(self.source)
            .map_err(|error| Error::new(self.source, ErrorKind::SourceFile(error)))?;
        let parser = Parser::<u64, &str>::new(&src).set_insn_size(self.insn_size);
        let mut tree = match parser.parse() {
            Ok(tree) => tree,
            Err(errors) => {
                let mut buffer = String::new();
                for (i, err) in errors.iter(self.source).enumerate() {
                    if i > 0 {
                        buffer.push('\n');
                    }
                    write!(&mut buffer, "{err}").unwrap();
                }
                return Err(Error::new("", ErrorKind::Parse(buffer)));
            }
        };

        if self.optimize {
            tree.optimize();
        }

        let mut out = create_file(path).map(BufWriter::new)?;
        decodetree::Generator::builder()
            .trait_name(self.trait_name)
            .insn_type(self.insn_type)
            .value_type(self.value_type)
            .stubs(self.stubs)
            .variable_size(self.variable_size)
            .build(&tree, UserGen::new(&self, opcodes))
            .generate(&mut out)
            .map_err(|error| Error::new(path, ErrorKind::Generate(error)))
    }
}

fn generate() -> Result<(), Error> {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    #[cfg(feature = "riscv")]
    {
        let out_dir = out_dir.join("arch/riscv");
        let mut opcodes = Default::default();

        Generate {
            source: "src/arch/riscv/insn.decode",
            trait_name: "RiscvDecode",
            insn_size: &[16, 32],
            insn_type: "u32",
            value_type: "i32",
            ..Generate::default()
        }
        .gen(out_dir.join("generated.rs"), &mut opcodes)?;

        gen_opcodes(out_dir.join("generated_opcodes.rs"), opcodes)?;
    }

    Ok(())
}

fn main() {
    if let Err(err) = generate() {
        eprintln!("error: {err}");
        process::exit(1);
    }
}
