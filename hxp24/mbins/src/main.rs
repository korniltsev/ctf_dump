use crate::Insn::TODO;
use anyhow::{anyhow, bail};
use goblin::elf::Elf;
use std::fmt::{Debug, Formatter, Pointer};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};

struct Regno {
    no: u8,
}

impl Debug for Regno {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.no == 30 {
            f.write_str("RSP")
        } else if self.no == 31 {
            f.write_str("PC")
        } else {
            f.write_fmt(format_args!("REG_{:}", self.no))
        }
    }
}

#[derive(Debug)]
enum CmpType {
    EQ,
    NE,
    LEQ,
    LE,
    LEQ_UNSIGNED,
    LE_UNSIGNED,
    ZERO,
}
#[derive(Debug)]
enum CmpRV {
    IMM(u32),
    REG(Regno),
}
#[derive(Debug)]
enum BitOpType {
    OR,
    XOR,
    AND,
    ADD,
    SUB,
    MUL,
    DIV_UNSIGNED,
    DIV,
    REM_UNSIGNED,
    REM,
    SHL,
    SHR,
    SHR_UNSIGNED,
    ROL,
    ROR,
    ZERO,
}

enum Insn {
    Cmp {
        typ: CmpType,
        lv: Regno,
        rv: CmpRV,
        dst: Regno,
    },
    BitOp {
        typ: BitOpType,
        lv: Regno,
        rv: CmpRV,
        dst: Regno,
    },
    Call {
        reg: Regno,
    },
    RET,
    MOV_SRC_REL {
        src: Regno,
        src_idx: i64,
        dst: Regno,
    },
    MOV_DST_REL {
        src: Regno,
        dst: Regno,
        dst_idx: i64,
        sz: u8,
    },

    TODO{
        opcode: u32
    },
    MovIMM { imm: u64, regno:Regno },
}
impl Debug for Insn {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Insn::Cmp { typ, lv, rv, dst } => {
                if dst.no == lv.no {
                    f.write_fmt(format_args!("{:?} {:?}, {:?} ", typ, lv, rv))
                } else {
                    f.write_fmt(format_args!("{:?} {:?} <= {:?} {:?} ", typ, dst, lv, rv))
                }
            }
            Insn::BitOp { typ, lv, rv, dst } => {
                if dst.no == lv.no {
                    f.write_fmt(format_args!("{:?} {:?}, {:?} ", typ, lv, rv))
                } else {
                    f.write_fmt(format_args!("{:?} {:?} <= {:?} {:?} ", typ, dst, lv, rv))
                }
            }
            Insn::Call { reg } => f.write_fmt(format_args!("CALL {:?}", reg)),
            TODO{opcode} => f.write_fmt(format_args!("[TODO] {:x}", opcode)),
            Insn::RET => f.write_str("RET"),
            Insn::MOV_SRC_REL { src, src_idx, dst } => f.write_fmt(format_args!(
                "MOV qword {:?}, [{:?} + {:?}]",
                dst, src, src_idx,
            )),
            Insn::MOV_DST_REL {
                src,
                dst,
                dst_idx,
                sz,
            } => {
                let sqstr = match sz {
                    1 => "byte",
                    2 => "word",
                    4 => "dword",
                    8 => "qword",
                    &_ => "WTF",
                };
                f.write_fmt(format_args!(
                    "MOV {:?}  [{:?} + {:?}], {:?}",
                    sqstr, dst, dst_idx, src
                ))
            }
            Insn::MovIMM { imm, regno } => {
                f.write_fmt(format_args!("MOV {:?}, 0x{:x}", regno, imm))
            }
        }
    }
}

struct DisasmContext {
    data: Vec<u8>,
}

impl DisasmContext {
    fn new(data: &[u8]) -> Self {
        Self {
            data: data.to_owned(),
        }
    }

    fn new_from_elf(elfpath: &str) -> anyhow::Result<Self> {
        let mut fbytes = Vec::new();
        {
            let mut f = File::open(elfpath)?;
            f.read_to_end(&mut fbytes)?;
        }

        let e = Elf::parse(&fbytes).expect("elf parse");
        let data = e
            .section_headers
            .iter()
            .find(|it| {
                let string = e.shdr_strtab[it.sh_name].to_owned();
                string == ".data"
            })
            .ok_or_else(|| anyhow!("no .data section"))?;

        let data =
            &fbytes[data.sh_offset as usize..data.sh_offset as usize + data.sh_size as usize];
        let data = &data[0x10..];
        Ok(Self::new(&data))
    }

    fn dump_bin(&self, f: &str) -> anyhow::Result<()> {
        let mut of = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(f)
            .expect("open  vm.bin for write");
        of.write(&self.data)?;
        Ok(())
    }

    // 2 : type
    //>>> bin(1<<29)       '0b100000000000000000000000000000'
    //>>> bin(2<<29)      '0b1000000000000000000000000000000'
    //>>> bin(0x10000000)   '0b10000000000000000000000000000'
    //>>> bin(0x20000000)  '0b100000000000000000000000000000'
    fn disassemble_one(code: & mut &[u8]) -> anyhow::Result<Insn> {
        if code.len() % 4 != 0 || code.len() == 0 {
            bail!("invalid code len")
        }
        let opcode: &[u8; 4] = &code[0..4].try_into()?; // todo create func
        *code = &code[4..];
        let byte3_opcode = opcode[0];
        let opcode = u32::from_be_bytes(*opcode); // 0 1 2 3 => 3 2 1 0

        let typ = opcode >> 29;

        if (opcode < 0x20000000 || typ == 1 && ((opcode & 0x10000000) == 0)) {
            let dst = Regno {
                no: ((opcode >> 19) & 0x1F) as u8,
            };
            let rv = if ((byte3_opcode & 1 & (typ == 1) as u8) != 0 || (opcode & 0xE1000000) == 0) {
                if (typ == 1 || opcode >> 25 == 9 || opcode >> 25 == 7) {
                    CmpRV::IMM((((opcode as u64) << 50) >> 50) as u32)
                } else {
                    CmpRV::IMM(opcode & 0x3FFF)
                }
            } else {
                CmpRV::REG(Regno {
                    no: ((opcode >> 9) & 0x1F) as u8,
                })
            };
            let lv = Regno {
                no: ((opcode >> 14) & 0x1F) as u8,
            };
            let cmp_typ = opcode >> 25;
            let insn = if (typ == 1) {
                let cmp_typ = match cmp_typ & 0x7 {
                    0 => CmpType::EQ,
                    1 => CmpType::NE,
                    2 => CmpType::LEQ,
                    3 => CmpType::LE,
                    4 => CmpType::LEQ_UNSIGNED,
                    5 => CmpType::LE_UNSIGNED,
                    _ => CmpType::ZERO,
                };
                Insn::Cmp {
                    typ: cmp_typ,
                    lv,
                    rv,
                    dst,
                }
            } else {
                let bitop_typ = match cmp_typ & 0xf {
                    0 => BitOpType::OR,
                    1 => BitOpType::XOR,
                    2 => BitOpType::AND,
                    3 => BitOpType::ADD,
                    4 => BitOpType::SUB,
                    5 => BitOpType::MUL,
                    6 => BitOpType::DIV_UNSIGNED,
                    7 => BitOpType::DIV,
                    8 => BitOpType::REM_UNSIGNED,
                    9 => BitOpType::REM,
                    0xa => BitOpType::SHL,
                    0xb => BitOpType::SHR,
                    0xc => BitOpType::SHR_UNSIGNED,
                    0xd => BitOpType::ROL,
                    0xe => BitOpType::ROR,
                    _ => BitOpType::ZERO,
                };
                Insn::BitOp {
                    typ: bitop_typ,
                    lv,
                    rv,
                    dst,
                }
            };
            return Ok(insn);
        }
        if typ == 1 {
            let typ = (opcode >> 26) & 3;
            if typ == 2 {
                let regno = (opcode >> 20) & 0x1F;
                return Ok(Insn::Call {
                    reg: Regno { no: regno as u8 },
                });
            }
            if typ == 0 {
                return Ok(Insn::RET);
            }
            return Ok(TODO{opcode }); //todo strange fallthrough
        }
        if typ == 2 {
            let typ = ((opcode >> 27) & 3);
            if typ != 0 {
                let srcregno = (opcode >> 21) & 0x1F;
                let dstregno = (opcode >> 0x10) & 0x1F;
                let mut k = opcode as u16 as i64 - 0x8000;
                if ((opcode & 0x8000) == 0) {
                    k = opcode as u16 as i64;
                }

                if (((opcode >> 27) & 3) == 1) {
                    // k = *(_QWORD *)(a1->regs[dstregno] + k);
                    // a1->regs[srcregno] = k;
                    return Ok(Insn::MOV_SRC_REL {
                        src: Regno { no: srcregno as u8 },
                        src_idx: k,
                        dst: Regno { no: dstregno as u8 },
                    });
                } else {
                    let sz = match (opcode >> 26) & 3 {
                        0 => 1,
                        1 => 2,
                        2 => 4,
                        3 => 8,
                        _ => bail!("imposible"),
                    };
                    return Ok(Insn::MOV_DST_REL {
                        src: Regno { no: srcregno as u8 },
                        dst: Regno { no: dstregno as u8 },
                        dst_idx: k,
                        sz: sz,
                    });
                }
            } else {
                if code.len() < 8 {
                    bail!("invalid code len")
                }
                let imm_quad: &[u8; 8] = &code[0..8].try_into()?; // todo create func
                *code = &code[8..];
                let imm_quad = u64::from_be_bytes(*imm_quad);
                let regno = (opcode >> 0x10) & 0x1F;
                return Ok(Insn::MovIMM{
                    imm: imm_quad,
                    regno: Regno{no: regno as u8},
                })

            }
        }
        return Ok(TODO{opcode});
    }

    fn disassemble_all(&self) -> anyhow::Result<Vec<Insn>> {
        if self.data.len() % 4 != 0 {
            bail!("invalid program len {}", self.data.len())
        }
        let mut res = Vec::new();

        let mut datas = &self.data[..];
        while datas.len() > 0 {
            let opcode = &mut datas;
            let insn = Self::disassemble_one(opcode)?;
            println!("{:?}", insn);
            res.push(insn);
        }
        Ok(res)
    }
}

fn main() -> anyhow::Result<()> {
    let fpath = std::env::args()
        .nth(1)
        .expect("usage - path elf file as argv1");
    let ctx = DisasmContext::new_from_elf(&fpath)?;

    let _prog = ctx.disassemble_all()?;


    Ok(())
}
