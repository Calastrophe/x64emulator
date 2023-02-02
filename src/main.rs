use unicorn_engine::{RegisterX86::{*}, Unicorn};
use unicorn_engine::unicorn_const::{Arch, Mode, Permission, SECOND_SCALE};
use clap::Parser;
use object::{Object,ObjectSection};
use std::error::Error;
use std::fs;


#[derive(Default, Parser, Debug)]
struct Arguments {
    o_file : String,
    #[clap(default_value_t=0)]
    _rdi : u64,
    #[clap(default_value_t=0)]
    _rsi : u64,
    #[clap(default_value_t=0)]
    _rdx : u64,
    #[clap(default_value_t=0)]
    _rcx : u64,
    #[clap(default_value_t=0)]
    _r8 : u64,
    #[clap(default_value_t=0)]
    _r9 : u64
}


// Read the given file, grab the .text section, memory map into the emulator
// Start at the beginning with CLI numbers for the registers
fn main() -> Result<(), Box<dyn Error>> {
    let args = Arguments::parse();
    let bin_data = fs::read(args.o_file.clone())?;
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

    setup_registers(&mut emu, &args);

    emu.emu_start(0x1000, (0x1000 + instructions.len() - 1) as u64, 0, 0).unwrap();

    println!("The return value of the function: {} \nThe starting values RDI and RSI : {} {}", emu.reg_read(RAX).unwrap(), emu.reg_read(RDI).unwrap(), emu.reg_read(RSI).unwrap());

    Ok(())
}


fn setup_registers(emulator: &mut Unicorn<()>, args: &Arguments) {
    emulator.reg_write(RDI, args._rdi).expect("failed to write RDI");
    emulator.reg_write(RSI, args._rsi).expect("failed to write RSI");
    emulator.reg_write(RDX, args._rdx).expect("failed to write RDI");
    emulator.reg_write(RCX, args._rcx).expect("failed to write RSI");
    emulator.reg_write(R8, args._r8).expect("failed to write R8");
    emulator.reg_write(R9, args._r9).expect("failed to write R9");
}