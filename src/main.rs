use unicorn_engine::{RegisterX86, Unicorn};
use unicorn_engine::unicorn_const::{Arch, Mode, Permission};
use clap::Parser;
use object::{Object,ObjectSection};
use std::error::Error;
use std::fs;
mod parser;

pub const ARG_TABLE: [RegisterX86; 6] = [RegisterX86::RDI, RegisterX86::RSI, RegisterX86::RDX, RegisterX86::RCX, RegisterX86::R8, RegisterX86::R9];
pub const REG_TABLE: [RegisterX86; 7] = [RegisterX86::RAX, RegisterX86::RDI, RegisterX86::RSI, RegisterX86::RDX, RegisterX86::RCX, RegisterX86::R8, RegisterX86::R9];



// Read the given file, grab the .text section, memory map into the emulator
// Start at the beginning with CLI numbers for the registers
fn main() -> Result<(), Box<dyn Error>> {
    let args = parser::Arguments::parse();
    let bin_data = fs::read(args.filename())?;
    let obj_file = object::File::parse(&*bin_data)?;
    let Some(text_section) = obj_file.section_by_name(".text") else {
        panic!("This object file does not contain a .text section")
    };
    let Ok(instructions) = text_section.data() else {
        panic!("There was an error reading the instructions provided in the .text")
    };


    let mut emu = Unicorn::new(Arch::X86, Mode::MODE_64).expect("failed to initalize the emulator");
    emu.mem_map(0x1000, page_align_up(instructions.len()), Permission::ALL).expect("failed to map");
    emu.mem_write(0x1000, instructions).expect("failed to write instructions");

    setup_registers(&mut emu, &args);

    emu.emu_start(0x1000, (0x1000 + instructions.len() - 1) as u64, 0, 0).unwrap();

    print_registers(&mut emu);

    Ok(())
}

// TODO: Could potentially refactor this weird function
fn setup_registers(emulator: &mut Unicorn<()>, args: &parser::Arguments) {
    for (i, arg) in args.registers().iter().enumerate() {
        emulator.reg_write(ARG_TABLE[i], *arg).expect("failed to write a register");
    }
}

fn print_registers(emulator: &mut Unicorn<()>) {
    for reg in REG_TABLE {
        let ret_val = emulator.reg_read(reg).expect("failed to read a register");
        println!("{:?} : {}", reg, ret_val);
    }
}

fn page_align_up(num: usize) -> usize {
    (num) + ((0x1000)-1) & !((0x1000) - 1)
}