pub enum Command {
    Compare,
    Convert,
    Add,
    Sub,
    Multiply,
    Divide,
    Module,
    TestFFCElement,
    TestGPBigInt,
    TestPeer,
    Unknown,
}

impl From<u32> for Command {
    #[inline]
    fn from(value: u32) -> Command {
        match value {
            0 => Command::Compare,
            1 => Command::Convert,
            2 => Command::Add,
            3 => Command::Sub,
            4 => Command::Multiply,
            5 => Command::Divide,
            6 => Command::Module,
            7 => Command::TestFFCElement,
            8 => Command::TestGPBigInt,
            9 => Command::TestPeer,
            _ => Command::Unknown,
        }
    }
}

pub const UUID: &str = &include_str!(concat!(env!("OUT_DIR"), "/uuid.txt"));
