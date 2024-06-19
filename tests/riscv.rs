use disasm::{Arch, Bundle, Disasm, Options};

#[cfg(feature = "print")]
#[test]
fn riscv_print() {
    fn test(address: u64, raw: u32, expect: &str) {
        let mut bundle = Bundle::empty();
        let mut disasm = Disasm::new(
            Arch::Riscv,
            address,
            Options {
                alias: false,
                ..Options::default()
            },
        )
        .unwrap();
        if disasm.decode(&raw.to_le_bytes(), &mut bundle).is_ok() {
            let output = format!("{}", bundle[0].printer(&disasm, ()));
            assert_eq!(output, expect);
        } else {
            panic!("failed to decode {raw:#08x}, expected \"{expect}\"");
        }
    }

    // RV32I
    test(0, 0xdeadb7b7, "lui\ta5,0xdeadb");
    test(0, 0xdbeefe17, "auipc\tt3,0xdbeef");
    test(0, 0x4aafe0ef, "jal\tra,fe4aa");
    test(0, 0x000e0367, "jalr\tt1,0(t3)");
    test(0xa16a2, 0x02fa0c63, "beq\ts4,a5,a16da");
    test(0xa2164, 0x00b51763, "bne\ta0,a1,a2172");
    test(0xa2250, 0x00f74563, "blt\ta4,a5,a225a");
    test(0xa238e, 0x0067d563, "bge\ta5,t1,a2398");
    test(0xa24cc, 0x00e7ee63, "bltu\ta5,a4,a24e8");
    test(0xa2382, 0x00d5f663, "bgeu\ta1,a3,a238e");
    test(0, 0x00098783, "lb\ta5,0(s3)");
    test(0, 0x00099783, "lh\ta5,0(s3)");
    test(0, 0x0009a783, "lw\ta5,0(s3)");
    test(0, 0x0009c783, "lbu\ta5,0(s3)");
    test(0, 0x0009d783, "lhu\ta5,0(s3)");
    test(0, 0x06d108a3, "sb\ta3,113(sp)");
    test(0, 0x06d118a3, "sh\ta3,113(sp)");
    test(0, 0x06d128a3, "sw\ta3,113(sp)");
    test(0, 0x34c60613, "addi\ta2,a2,844");
    test(0, 0x0025a793, "slti\ta5,a1,2");
    test(0, 0x0017b513, "sltiu\ta0,a5,1");
    test(0, 0xfffdc793, "xori\ta5,s11,-1");
    test(0, 0x0089e613, "ori\ta2,s3,8");
    test(0, 0x0ff5f693, "andi\ta3,a1,255");
    test(0, 0x00199593, "slli\ta1,s3,0x1");
    test(0, 0x0086d593, "srli\ta1,a3,0x8");
    test(0, 0x404b5713, "srai\ta4,s6,0x4");
    test(0, 0x01448533, "add\ta0,s1,s4");
    test(0, 0x412a0633, "sub\ta2,s4,s2");
    test(0, 0x00a49633, "sll\ta2,s1,a0");
    test(0, 0x00d7a7b3, "slt\ta5,a5,a3");
    test(0, 0x00fc3733, "sltu\ta4,s8,a5");
    test(0, 0x00c5c733, "xor\ta4,a1,a2");
    test(0, 0x00c6d433, "srl\ts0,a3,a2");
    test(0, 0x40f55533, "sra\ta0,a0,a5");
    test(0, 0x00abe533, "or\ta0,s7,a0");
    test(0, 0x01377733, "and\ta4,a4,s3");
    test(0, 0x0330000f, "fence\trw,rw");
    test(0, 0x8330000f, "fence.tso");
    test(0, 0x0100000f, "pause");
    test(0, 0x00000073, "ecall");
    test(0, 0x00100073, "ebreak");

    // RV64I
    test(0, 0x0009e783, "lwu\ta5,0(s3)");
    test(0, 0x0009b783, "ld\ta5,0(s3)");
    test(0, 0x06d138a3, "sd\ta3,113(sp)");
    test(0, 0x03f99593, "slli\ta1,s3,0x3f");
    test(0, 0x03f6d593, "srli\ta1,a3,0x3f");
    test(0, 0x43fb5713, "srai\ta4,s6,0x3f");
    test(0, 0xfff2829b, "addiw\tt0,t0,-1");
    test(0, 0x0025169b, "slliw\ta3,a0,0x2");
    test(0, 0x01f5551b, "srliw\ta0,a0,0x1f");
    test(0, 0x4105d59b, "sraiw\ta1,a1,0x10");
    test(0, 0x00d7073b, "addw\ta4,a4,a3");
    test(0, 0x40d7073b, "subw\ta4,a4,a3");
    test(0, 0x008a95bb, "sllw\ta1,s5,s0");
    test(0, 0x008ad5bb, "srlw\ta1,s5,s0");
    test(0, 0x408ad5bb, "sraw\ta1,s5,s0");

    // Zicsr
    test(0, 0x00151573, "csrrw\ta0,fflags,a0");
    test(0, 0x00152573, "csrrs\ta0,fflags,a0");
    test(0, 0x00153573, "csrrc\ta0,fflags,a0");
    test(0, 0x00155573, "csrrwi\ta0,fflags,10");
    test(0, 0x00156573, "csrrsi\ta0,fflags,10");
    test(0, 0x00157573, "csrrci\ta0,fflags,10");

    // RV32M
    test(0, 0x02950533, "mul\ta0,a0,s1");
    test(0, 0x02951533, "mulh\ta0,a0,s1");
    test(0, 0x02952533, "mulhsu\ta0,a0,s1");
    test(0, 0x02953533, "mulhu\ta0,a0,s1");
    test(0, 0x02954533, "div\ta0,a0,s1");
    test(0, 0x02955533, "divu\ta0,a0,s1");
    test(0, 0x02956533, "rem\ta0,a0,s1");
    test(0, 0x02957533, "remu\ta0,a0,s1");

    // RV64M
    test(0, 0x0295053b, "mulw\ta0,a0,s1");
    test(0, 0x0295453b, "divw\ta0,a0,s1");
    test(0, 0x0295553b, "divuw\ta0,a0,s1");
    test(0, 0x0295653b, "remw\ta0,a0,s1");
    test(0, 0x0295753b, "remuw\ta0,a0,s1");
}
