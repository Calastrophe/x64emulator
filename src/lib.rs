use unicorn_engine::{RegisterX86, Unicorn};
use unicorn_engine::unicorn_const::{Arch, Mode, Permission};
use clap::Parser;
use object::{Object,ObjectSection};
use std::error::Error;
use std::fs;

// NOTE: This file is acting like the library for the emulator

pub const ARG_TABLE: [RegisterX86; 6] = [RegisterX86::RDI, RegisterX86::RSI, RegisterX86::RDX, RegisterX86::RCX, RegisterX86::R8, RegisterX86::R9];
pub const REG_TABLE: [RegisterX86; 7] = [RegisterX86::RAX, RegisterX86::RDI, RegisterX86::RSI, RegisterX86::RDX, RegisterX86::RCX, RegisterX86::R8, RegisterX86::R9];


// A context which is created each time a new file is loaded.
pub struct Context<'a> {
    uc: Unicorn<'a, ()>, // Architecture and mode will be found here.
    file: object::File<'a> // The file which is associated with this new context
}





fn page_align_up(num: usize) -> usize {
    (num) + ((0x1000)-1) & !((0x1000) - 1)
}

fn page_align_down(num: u64) -> u64 {
    return (num) & !(0x1000-1);
}
