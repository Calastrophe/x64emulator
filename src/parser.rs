use clap::Parser;


#[derive(Default, Parser, Debug)]
#[clap(author = "Calastrophe", version, about)]
pub struct Arguments {
    o_file : String,
    #[clap(default_value_t=0)]
    rdi : u64,
    #[clap(default_value_t=0)]
    rsi : u64,
    #[clap(default_value_t=0)]
    rdx : u64,
    #[clap(default_value_t=0)]
    rcx : u64,
    #[clap(default_value_t=0)]
    r8 : u64,
    #[clap(default_value_t=0)]
    r9 : u64,
    #[clap(short, long)]
    /// specify starting array address
    pub array_address: Option<u64>,
    #[clap(short, long, value_parser, num_args = 1.., value_delimiter = ',')]
    /// values inside the array
    pub values: Option<Vec<u64>>,
}

impl Arguments {
    pub fn registers(&self) -> [u64; 6] {
        [self.rdi, self.rsi, self.rdx, self.rcx, self.r8, self.r9]
    }

    pub fn filename(&self) -> String {
        self.o_file.clone()
    }
}