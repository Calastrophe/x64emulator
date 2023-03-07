use unicorn_engine::Unicorn;
use unicorn_engine::unicorn_const::{MemRegion, uc_error, Arch, Mode, Permission};
use object::{Object,ObjectSection, Architecture, File};
use thiserror::Error;


// Add onto the file struct to generate Unicorn acceptable Arch/Mode
trait ArchMode {
    fn get_arch_and_mode(&self) -> Result<(Arch, Mode), LibErr>;
}

impl ArchMode for File<'_> {
    // Only x86_64 and x86_64_32 is supported currently.
    fn get_arch_and_mode(&self) -> Result<(Arch, Mode), LibErr> {
        match self.architecture() {
            Architecture::Aarch64 => {
                Err(LibErr::UnsupportedArch)
                // match self.is_little_endian() {
                //     true => Ok((Arch::ARM64, Mode::ARM)),
                //     false => Ok((Arch::ARM64, Mode::ARM | Mode::BIG_ENDIAN))
                // }
            }
            Architecture::Arm => {
                Err(LibErr::UnsupportedArch)
                // match self.is_little_endian() {
                //     true => Ok((Arch::ARM, Mode::ARM)),
                //     false => Ok((Arch::ARM, Mode::ARM | Mode::BIG_ENDIAN))
                // }
            }
            Architecture::X86_64 => Ok((Arch::X86, Mode::MODE_64)),
            Architecture::X86_64_X32 => Ok((Arch::X86, Mode::MODE_32)),
            _ => Err(LibErr::UnsupportedArch)
        }
    }
}

struct Context<'a> {
    uc: Unicorn<'a, ()>,
    file: File<'a>
}

impl<'a> Context<'a> {
    pub fn new(pefile: File) -> Result<Context, LibErr> {
        let (arch, mode) = pefile.get_arch_and_mode()?;
        let uc = Unicorn::new(arch, mode).expect("This should not fail...");
        let context = Context{uc: uc, file: pefile};
        // Map every region into the context from the pefile and return Context
        todo!()
    }


    // Given start and end will be aligned to meet emulator requirements.
    pub fn mem_map(&mut self, start: usize, size: usize, perms: Permission) -> Result<(), LibErr> {
        self.uc.mem_map(page_align_down(start) as u64, page_align_up(size), perms).map_err(|_e| LibErr::MemMapErr)
    }

    // Retrieves the memory regions and set an error that implements std::error::Error
    pub fn mem_regions(&self) -> Result<Vec<MemRegion>, LibErr> {
        self.uc.mem_regions().map_err(|_e| LibErr::MemRegionErr)
    }

    // Retrieves the functions inside the object/executable file
    // NOTE: Return strings may not need to be an owned type?
    pub fn functions(&self) -> Vec<String> { 
        unimplemented!() 
    }

    // Retrieves the current state of the registers inside the Unicorn instance, depends on architecture.
    pub fn registers(&self) -> Vec<usize> { unimplemented!() }

    // Sets the state of the registers inside the Unicorn instance.
    // TODO: Determine if bigger numbers than will fit in register should be allowed
    // NOTE: usize *may* be bigger than the target architecture register. 
    pub fn set_registers(&mut self, new_regs: Vec<usize>) { unimplemented!() }

    // TODO: Outline calling convention for this function and its return
    pub fn call_func(&mut self, start: usize) { unimplemented!() }
}

mod constants {
    const ARM
}



// TODO: RENAME
#[derive(Error, Debug)]
pub enum LibErr {
    #[error("Unsupported architecture found in object/executable file.")]
    UnsupportedArch,
    #[error("There was an error mapping memory into the context.")]
    MemMapErr,
    #[error("There was an error reading memory regions.")]
    MemRegionErr,
    #[error("Unmapped error")]
    Unknown
}


fn page_align_up(num: usize) -> usize {
    (num) + ((0x1000)-1) & !((0x1000) - 1)
}

fn page_align_down(num: usize) -> usize {
    (num) & !(0x1000-1)
}
