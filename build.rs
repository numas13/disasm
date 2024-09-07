use std::{
    collections::{
        hash_map::{Entry, HashMap},
        HashSet,
    },
    fmt::{self, Write as _},
    fs::{self, File},
    io::{self, BufWriter, Write},
    mem,
    path::{Path, PathBuf},
    process,
};

use decodetree::{
    gen::{Gen, Pad},
    Parser, Pattern, ValueKind,
};

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
    opts: &'a DecodeOptions,
    arch: &'a mut Arch,

    formats: HashMap<String, Vec<(String, String)>>,

    cond_args_for_is: Vec<(&'static str, &'static str)>,
}

impl<'a> UserGen<'a> {
    fn new(opts: &'a DecodeOptions, arch: &'a mut Arch) -> Self {
        Self {
            opts,
            arch,
            formats: Default::default(),
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

    fn trait_body<W: Write>(&mut self, out: &mut W, mut pad: Pad) -> io::Result<()> {
        if self.opts.variable_size {
            writeln!(out, "{pad}fn advance(&mut self, size: usize);")?;
        }

        let shared = &self.arch.shared_args_def;
        let ret = if self.arch.set_return_error {
            " -> Result<(), Self::Error>"
        } else {
            ""
        };
        for (name, args) in &self.formats {
            writeln!(out)?;
            write!(out, "{pad}fn {name}({shared}, opcode: Opcode")?;
            for (arg, ty) in args {
                write!(out, ", {arg}: {ty}")?;
            }
            writeln!(out, "){ret} {{")?;
            pad.right();

            writeln!(out, "{pad}out.set_opcode(opcode);")?;

            for (arg, ty) in args {
                let prefix = if ty.starts_with("args_") { "args_" } else { "" };
                write!(
                    out,
                    "{pad}self.set_{prefix}{arg}({}, {arg})",
                    self.arch.shared_args
                )?;
                if self.arch.set_return_error {
                    write!(out, "?")?;
                }
                writeln!(out, ";")?;
            }
            if self.arch.set_return_error {
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

        if self.opts.variable_size {
            writeln!(out, "{pad}self.advance({});", pattern.size())?;
        }

        let mut format = String::from("format");
        for value in pattern.values() {
            let name = value.name();
            match value.kind() {
                ValueKind::Set(ty, ..) => {
                    if !self.arch.sets.contains_key(*name) {
                        self.arch.sets.insert(name.to_string(), ty.to_string());
                    }
                }
                _ => {
                    if !self.arch.args.contains(*name) {
                        self.arch.args.insert(name.to_string());
                    }
                }
            }
            format.push('_');
            format.push_str(name);
        }

        write!(out, "{pad}self.{format}({}", self.arch.shared_args)?;
        write!(out, ", opcode::{}", pattern.name().to_uppercase())?;

        for value in pattern.values() {
            write!(out, ", {}", value.name())?;
        }
        if self.arch.set_return_error {
            writeln!(out, ")?;")?;
        } else {
            writeln!(out, ");")?;
        }

        if let Entry::Vacant(e) = self.formats.entry(format) {
            let mut args = Vec::new();
            for value in pattern.values() {
                let name = String::from(*value.name());
                let ty = match value.kind() {
                    ValueKind::Set(ty, ..) => format!("args_{ty}"),
                    _ => self.arch.value_type.to_owned(),
                };
                args.push((name, ty));
            }
            e.insert(args);
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
struct DecodeOptions {
    trait_name: &'static str,
    insn_type: &'static str,
    insn_size: &'static [u32],
    optimize: bool,
    stubs: bool,
    variable_size: bool,
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

struct Arch {
    value_type: &'static str,
    set_return_error: bool,
    mnemonic_dot: bool,
    shared_args: String,
    shared_args_def: String,

    src_dir: PathBuf,
    out_dir: PathBuf,
    set_output: PathBuf,
    opcodes_output: PathBuf,
    decode: Vec<DecodeGen>,
    opcodes: HashSet<String>,
    args: HashSet<String>,
    sets: HashMap<String, String>,
}

impl Arch {
    fn new(name: &str) -> Self {
        let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
        let out_dir = out_dir.join("arch").join(name);
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
            shared_args,
            shared_args_def,

            src_dir: Path::new("src/arch").join(name),
            out_dir,
            set_output,
            opcodes_output,
            decode: Vec::new(),
            opcodes: Default::default(),
            args: Default::default(),
            sets: Default::default(),
        }
    }

    fn value_type(mut self, s: &'static str) -> Self {
        self.value_type = s;
        self
    }

    fn set_return_error(mut self, b: bool) -> Self {
        self.set_return_error = b;
        self
    }

    fn mnemonic_dot(mut self, b: bool) -> Self {
        self.mnemonic_dot = b;
        self
    }

    fn decode(
        mut self,
        source: impl AsRef<Path>,
        output: impl AsRef<Path>,
        opts: DecodeOptions,
    ) -> Self {
        let source = self.src_dir.join(source);
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
            writeln!(
                out,
                "    fn set_args_{name}({shared}, args: args_{ty}){ret};"
            )?;
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
            "pub(crate) fn mnemonic(opcode: Opcode) -> Option<&'static str> {{"
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

    fn generate(mut self) -> Result<(), Error> {
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

fn generate() {
    let arch_list: Vec<Arch> = vec![
        #[cfg(feature = "e2k")]
        Arch::new("e2k").value_type("i32").decode(
            "alop.decode",
            "generated_decode_alop.rs",
            DecodeOptions {
                trait_name: "E2KDecodeAlop",
                insn_size: &[32 + 16 + 3 + 7],
                insn_type: "u64",
                ..DecodeOptions::default()
            },
        ),
        #[cfg(feature = "riscv")]
        Arch::new("riscv")
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
            ),
        #[cfg(feature = "x86")]
        Arch::new("x86")
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
            ),
    ];

    if arch_list.is_empty() {
        return;
    }

    let mut failed = false;
    for arch in arch_list {
        if let Err(err) = arch.generate() {
            eprintln!("{err}");
            failed = true;
        }
    }
    if failed {
        process::exit(1);
    }
}

fn main() {
    generate();
}
