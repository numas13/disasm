use std::{
    collections::{hash_map::HashMap, HashSet},
    fmt::{self, Write as _},
    fs::{self, File},
    io::{self, BufWriter, Write},
    mem,
    path::{Path, PathBuf},
};

use decodetree::{
    gen::{Gen, Pad},
    Parser, Pattern, ValueKind,
};

#[derive(Debug)]
pub enum ErrorKind {
    SourceFile(io::Error),
    OutputDir(io::Error),
    OutputFile(io::Error),
    Parse(String),
    Generate(io::Error),
}

#[derive(Debug)]
pub struct Error {
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
    opts: &'a DecodeOptions,
    arch: &'a mut Arch,

    cond_args_for_is: Vec<(&'static str, &'static str)>,
}

impl<'a> UserGen<'a> {
    fn new(opts: &'a DecodeOptions, arch: &'a mut Arch) -> Self {
        Self {
            opts,
            arch,
            cond_args_for_is: vec![("insn", opts.insn_type)],
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

    fn trait_parents(&self) -> &[&str] {
        &["SetValue"]
    }

    fn decode_args(&self) -> &[(&str, &str)] {
        Self::shared_args()
    }

    fn cond_args(&self, name: &str) -> &[(&str, &str)] {
        if name.starts_with("is_") {
            &self.cond_args_for_is
        } else {
            &[]
        }
    }

    fn trans_proto_check(&self, _: &str) -> bool {
        // do not generate translate functions
        false
    }

    fn trait_body<W: Write>(&mut self, out: &mut W, pad: Pad) -> io::Result<()> {
        if self.opts.variable_size {
            writeln!(out, "{pad}fn advance(&mut self, size: usize);")?;
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

        if self.opts.variable_size {
            writeln!(out, "{pad}self.advance({});", pattern.size())?;
        }
        writeln!(
            out,
            "{pad}out.set_opcode(opcode::{});",
            pattern.name().to_uppercase()
        )?;

        for value in pattern.values() {
            let shared = &self.arch.shared_args;
            let name = value.name();
            match value.kind() {
                ValueKind::Set(ty, ..) => {
                    if !self.arch.sets.contains_key(*name) {
                        self.arch.sets.insert(name.to_string(), ty.to_string());
                    }
                    write!(out, "{pad}self.set_args_{name}({shared}, ")?;
                    if self.arch.args_by_ref {
                        write!(out, "&")?;
                    }
                    write!(out, "{name})")?;
                }
                _ => {
                    if !self.arch.args.contains(*name) {
                        self.arch.args.insert(name.to_string());
                    }
                    write!(out, "{pad}self.set_{name}({shared}, {name})")?;
                }
            };
            if self.arch.set_return_error {
                write!(out, "?")?;
            }
            writeln!(out, ";")?;
        }

        Ok(())
    }

    fn end<W: Write>(&mut self, _: &mut W, _: Pad, opcodes: &HashSet<&str>) -> io::Result<()> {
        self.arch.add_opcodes(opcodes);
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

#[derive(Clone)]
pub struct DecodeOptions {
    pub trait_name: &'static str,
    pub insn_type: &'static str,
    pub insn_size: &'static [u32],
    pub optimize: bool,
    pub stubs: bool,
    pub variable_size: bool,
}

impl Default for DecodeOptions {
    fn default() -> Self {
        Self {
            trait_name: "Decode",
            insn_type: "u32",
            insn_size: &[32],
            optimize: true,
            stubs: false,
            variable_size: false,
        }
    }
}

struct DecodeGen {
    source: PathBuf,
    output: PathBuf,
    opts: DecodeOptions,
}

impl DecodeGen {
    fn new(source: PathBuf, output: PathBuf, opts: DecodeOptions) -> Self {
        Self {
            source,
            output,
            opts,
        }
    }

    fn generate(&mut self, arch: &mut Arch) -> Result<(), Error> {
        let source = &self.source;
        let path = &self.output;
        let opts = &self.opts;

        println!("cargo:rerun-if-changed={}", source.display());

        let src = fs::read_to_string(source)
            .map_err(|error| Error::new(source, ErrorKind::SourceFile(error)))?;
        let parser = Parser::<u64, &str>::new(&src).set_insn_size(opts.insn_size);
        let mut tree = match parser.parse() {
            Ok(tree) => tree,
            Err(errors) => {
                let mut buffer = String::new();
                for (i, err) in errors.iter(&source.to_string_lossy()).enumerate() {
                    if i > 0 {
                        buffer.push('\n');
                    }
                    write!(&mut buffer, "{err}").unwrap();
                }
                return Err(Error::new("", ErrorKind::Parse(buffer)));
            }
        };

        if opts.optimize {
            tree.optimize();
        }

        let mut out = create_file(path).map(BufWriter::new)?;
        decodetree::Generator::builder()
            .trait_name(opts.trait_name)
            .insn_type(opts.insn_type)
            .value_type(arch.value_type)
            .stubs(opts.stubs)
            .variable_size(opts.variable_size)
            .error_type(false)
            .build(&tree, UserGen::new(opts, arch))
            .generate(&mut out)
            .map_err(|error| Error::new(path, ErrorKind::Generate(error)))?;

        Ok(())
    }
}

pub struct Arch {
    value_type: &'static str,
    set_return_error: bool,
    mnemonic_dot: bool,
    args_by_ref: bool,
    shared_args: String,
    shared_args_def: String,

    out_dir: PathBuf,
    set_output: PathBuf,
    opcodes_output: PathBuf,
    decode: Vec<DecodeGen>,
    opcodes: HashSet<String>,
    args: HashSet<String>,
    sets: HashMap<String, String>,
}

impl Arch {
    pub fn new(_name: &str) -> Self {
        let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
        let set_output = out_dir.join("generated_set.rs");
        let opcodes_output = out_dir.join("generated_opcodes.rs");

        let mut shared_args = String::from("");
        let mut shared_args_def = String::from("&mut self");

        for (i, (arg, ty)) in UserGen::shared_args().iter().enumerate() {
            if i != 0 {
                shared_args.push_str(", ");
            }
            shared_args.push_str(arg);

            shared_args_def.push_str(", ");
            shared_args_def.push_str(arg);
            shared_args_def.push_str(": ");
            shared_args_def.push_str(ty);
        }

        Self {
            value_type: "i32",
            set_return_error: false,
            mnemonic_dot: true,
            args_by_ref: true,
            shared_args,
            shared_args_def,

            out_dir,
            set_output,
            opcodes_output,
            decode: Vec::new(),
            opcodes: Default::default(),
            args: Default::default(),
            sets: Default::default(),
        }
    }

    pub fn value_type(mut self, s: &'static str) -> Self {
        self.value_type = s;
        self
    }

    pub fn set_return_error(mut self, b: bool) -> Self {
        self.set_return_error = b;
        self
    }

    pub fn mnemonic_dot(mut self, b: bool) -> Self {
        self.mnemonic_dot = b;
        self
    }

    pub fn args_by_ref(mut self, enabled: bool) -> Self {
        self.args_by_ref = enabled;
        self
    }

    pub fn decode(
        mut self,
        source: impl AsRef<Path>,
        output: impl AsRef<Path>,
        opts: DecodeOptions,
    ) -> Self {
        let source = source.as_ref().into();
        let output = self.out_dir.join(output);
        self.decode.push(DecodeGen::new(source, output, opts));
        self
    }

    fn add_opcodes(&mut self, opcodes: &HashSet<&str>) {
        self.opcodes.extend(opcodes.iter().map(|i| i.to_string()));
    }

    fn gen_trait_set_value<W: Write>(&self, mut out: W) -> io::Result<()> {
        let out = &mut out;
        let shared = &self.shared_args_def;
        let ret = if self.set_return_error {
            " -> Result<(), Self::Error>"
        } else {
            ""
        };
        writeln!(out, "pub trait SetValue {{")?;
        writeln!(out, "    type Error;")?;
        let ty = &self.value_type;
        for i in &self.args {
            writeln!(out, "    fn set_{i}({shared}, {i}: {ty}){ret};")?;
        }
        if !self.sets.is_empty() {
            writeln!(out)?;
        }
        for (name, ty) in &self.sets {
            write!(out, "    fn set_args_{name}({shared}, args: ")?;
            if self.args_by_ref {
                write!(out, "&")?;
            }
            writeln!(out, "args_{ty}){ret};")?;
        }
        writeln!(out, "}}")?;
        Ok(())
    }

    fn gen_opcodes<W: Write>(&self, mut out: W) -> io::Result<()> {
        let out = &mut out;
        let opcodes = {
            let mut vec: Vec<_> = self.opcodes.iter().collect();
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
            "pub(crate) fn generated_mnemonic(opcode: Opcode) -> Option<&'static str> {{"
        )?;
        writeln!(out, "    Some(match opcode {{")?;
        for i in opcodes {
            write!(out, "        {} => \"", i.to_uppercase())?;
            for c in i.chars() {
                match c {
                    '_' if self.mnemonic_dot => write!(out, ".")?,
                    _ => write!(out, "{}", c)?,
                }
            }
            writeln!(out, "\",")?;
        }
        writeln!(out, "        _ => return None,")?;
        writeln!(out, "    }})")?; // match
        writeln!(out, "}}")?; // fn mnemonic

        Ok(())
    }

    pub fn generate(mut self) -> Result<(), Error> {
        for mut i in mem::take(&mut self.decode) {
            i.generate(&mut self)?;
        }

        let out = create_file(&self.set_output).map(BufWriter::new)?;
        self.gen_trait_set_value(out)
            .map_err(|error| Error::new(&self.set_output, ErrorKind::Generate(error)))?;

        let out = create_file(&self.opcodes_output).map(BufWriter::new)?;
        self.gen_opcodes(out)
            .map_err(|error| Error::new(&self.opcodes_output, ErrorKind::Generate(error)))?;

        Ok(())
    }
}
