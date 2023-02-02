use unicorn_engine::{RegisterX86::{*}, Unicorn};
use unicorn_engine::unicorn_const::{Arch, Mode, Permission, SECOND_SCALE};
use clap::Parser;
use object::{Object,ObjectSection};
use std::error::Error;
use std::fs;


#[derive(Default, Parser, Debug)]
struct Arguments {
    o_file : String,
    rdi_start : u64,
    rsi_start : u64,
}


// Read the given file, grab the .text section, memory map into the emulator
// Start at the beginning with CLI numbers for the registers
fn main() -> Result<(), Box<dyn Error>> {
    let args = Arguments::parse();
    let bin_data = fs::read(args.o_file)?;
    let obj_file = object::File::parse(&*bin_data)?;
    let Some(text_section) = obj_file.section_by_name(".text") else {
        panic!("This object file does not contain a .text section")
    };
    let Ok(instructions) = text_section.data() else {
        panic!("There was an error reading the instructions provided in the .text")
    };

    let mut emu = Unicorn::new(Arch::X86, Mode::MODE_64).expect("failed to initalize the emulator");
    emu.mem_map(0x1000, 0x8000, Permission::ALL).expect("failed to map");
    emu.mem_write(0x1000, instructions).expect("failed to write instructions");

    emu.reg_write(RDI, args.rdi_start).expect("fail to write rdi");
    emu.reg_write(RSI, args.rsi_start).expect("fail to write rsi");

    emu.emu_start(0x1000, (0x1000 + instructions.len() - 1) as u64, 0, 0).unwrap();

    println!("The return value of the function: {} \nThe starting values RDI and RSI : {} {}", emu.reg_read(RAX).unwrap(), emu.reg_read(RDI).unwrap(), emu.reg_read(RSI).unwrap());

    Ok(())
}
