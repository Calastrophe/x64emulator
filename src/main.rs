use unicorn_engine::{RegisterX86, Unicorn};
use unicorn_engine::unicorn_const::{Arch, Mode, Permission};
use clap::Parser;
use object::{Object,ObjectSection};
use std::error::Error;
use std::fs;
mod parser;

pub const ARG_TABLE: [RegisterX86; 6] = [RegisterX86::RDI, RegisterX86::RSI, RegisterX86::RDX, RegisterX86::RCX, RegisterX86::R8, RegisterX86::R9];
pub const REG_TABLE: [RegisterX86; 7] = [RegisterX86::RAX, RegisterX86::RDI, RegisterX86::RSI, RegisterX86::RDX, RegisterX86::RCX, RegisterX86::R8, RegisterX86::R9];


// Refactor with interface.rs, introduce GUI and start to parse given files
fn main() -> Result<(), Box<dyn Error>> {
    Ok(())
}

// TODO: Could potentially refactor this weird function
fn setup_registers(emulator: &mut Unicorn<()>, args: &parser::Arguments) {
    for (i, arg) in args.registers().iter().enumerate() {
        emulator.reg_write(ARG_TABLE[i], *arg).expect("failed to write a register");
    }
}

fn page_align_up(num: usize) -> usize {
    (num) + ((0x1000)-1) & !((0x1000) - 1)
}

fn page_align_down(num: u64) -> u64 {
    return (num) & !(0x1000-1);
}
