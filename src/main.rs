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
    let bin_data = fs::read(&args.o_file)?;
    let obj_file = object::File::parse(&*bin_data)?;
    let Some(text_section) = obj_file.section_by_name(".text") else {
        panic!("This object file does not contain a .text section")
    };
    let Ok(instructions) = text_section.data() else {
        panic!("There was an error reading the instructions provided in the .text")
    };


    let mut emu = Unicorn::new(Arch::X86, Mode::MODE_64).expect("failed to initalize the emulator");
    let instructions_size = page_align_up(instructions.len());
    emu.mem_map(0x1000, instructions_size, Permission::ALL).expect("failed to map");


    // Handling potential arrays in memory
    if let Some(array_address) = args.array_address {
        let Some(array_values) = &args.values else {
            panic!("You provided an array address, but did not specify the values to be stored at the address.")
        };

        // We have to align the addresses by a 4KB boundary
        let lower_bound = page_align_down(array_address);
        let array_size = page_align_up(array_values.len()*8);

        let current_memory_end = (0x1000+instructions_size) as u64;

        // If the address aligned downwards conflicts with a page already mapped, then we have an issue.
        if lower_bound >= 0x1000 && lower_bound <= current_memory_end {
            panic!("Conflicting array address, choose another position, currently mapped memory between 0x1000 and {:#x}", current_memory_end);
        }

        // Map the given memory into the emulator
        emu.mem_map(lower_bound, array_size, Permission::ALL).expect("failed to map the array into the emulator");

        // Turn Vec<u64> into Vec<u8>
        let bytes = array_values.iter().flat_map(|x| x.to_le_bytes()).collect::<Vec<u8>>();
        // Write the Vec<u8> to memory
        emu.mem_write(array_address, &bytes).expect("failed to write the array");
    }

    emu.mem_write(0x1000, instructions).expect("failed to write instructions");

    setup_registers(&mut emu, &args);

    let end_addr = (0x1000 + instructions.len() - 1) as u64;
    emu.emu_start(0x1000, end_addr, 0, 0).expect("runtime error");

    print_registers(&mut emu);

    Ok(())
}

// TODO: Could potentially refactor this weird function
fn setup_registers(emulator: &mut Unicorn<()>, args: &parser::Arguments) {
    for (i, arg) in args.registers().iter().enumerate() {
        emulator.reg_write(ARG_TABLE[i], *arg).expect("failed to write a register");
    }
}

fn print_registers(emulator: &Unicorn<()>) {
    for reg in REG_TABLE {
        let ret_val = emulator.reg_read(reg).expect("failed to read a register");
        println!("{:?} : {ret_val}\n Binary view: {ret_val:b}", reg);
    }
}

fn page_align_up(num: usize) -> usize {
    (num) + ((0x1000)-1) & !((0x1000) - 1)
}

fn page_align_down(num: u64) -> u64 {
    return (num) & !(0x1000-1);
}
