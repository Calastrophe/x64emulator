use unicorn_engine::Unicorn;
use unicorn_engine::unicorn_const::{Arch, Mode, Permission};
use object::{Object,ObjectSection, Architecture};
use std::error::Error;
use std::fs;

// NOTE: This file is acting like the emulation library for the interface.

// A context which is created each time a new file is loaded.
pub struct Context<'a> {
    uc: Unicorn<'a, ()>, // Architecture and mode will be found here.
    file: object::File<'a> // The file which is associated with this new context
}

impl<'a> Context<'a> {
    // Only x86_x64, ARM, ARM64 supported at the moment.
    fn get_arch_and_mode(&self) -> Option<(Arch, Mode)> {
        match self.file.architecture() {
            Architecture::Aarch64 => Some((Arch::ARM64, Mode::ARM)),
            Architecture::Arm => Some((Arch::ARM, Mode::ARM)),
            Architecture::X86_64 => Some((Arch::X86, Mode::MODE_64)),
            Architecture::X86_64_X32 => Some((Arch::X86, Mode::MODE_32)),
            _ => None
        }
    }

    // Generate function signatures to display in listing
    // Try to use debug symbols to determine signature first
    fn generate_function_sigs(&self) {
        return;
    }

    pub fn new(filename: String) -> Self {
        // Parse the given filename and parse into a File object

        // Create a context with retrieved arch and mode

        // Map each segment into the context's unicorn instance

        
    }
}






fn page_align_up(num: usize) -> usize {
    (num) + ((0x1000)-1) & !((0x1000) - 1)
}

fn page_align_down(num: u64) -> u64 {
    return (num) & !(0x1000-1);
}
