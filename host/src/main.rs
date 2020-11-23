use optee_teec::{Context, Operation, ParamType, Session, Uuid};
use optee_teec::{ParamNone, ParamTmpRef, ParamValue};
use proto::{Command, UUID};

//use num_bigint::{BigInt};
// use message_passing_interface;

fn big_int(session: &mut Session) -> optee_teec::Result<()> {
    let number0 = [
        0x01u8, 0x23u8, 0x45u8, 0x67u8, 0x89u8, 0xabu8, 0xcdu8, 0xefu8,
    ];
    let number1: u32 = 2;

    let p0 = ParamTmpRef::new_input(&number0);
    let p1 = ParamValue::new(number1, 0, ParamType::ValueInput);
    let mut operation = Operation::new(0, p0, p1, ParamNone, ParamNone);

    // session.invoke_command(Command::Compare as u32, &mut operation)?;
    // session.invoke_command(Command::Convert as u32, &mut operation)?;
    // session.invoke_command(Command::Add as u32, &mut operation)?;
    // session.invoke_command(Command::Sub as u32, &mut operation)?;
    // session.invoke_command(Command::Multiply as u32, &mut operation)?;
    // session.invoke_command(Command::Divide as u32, &mut operation)?;
    // session.invoke_command(Command::Module as u32, &mut operation)?;
    // session.invoke_command(Command::TestFFCElement as u32, &mut operation)?;
    session.invoke_command(Command::TestGPBigInt as u32, &mut operation)?;
    session.invoke_command(Command::TestPeer as u32, &mut operation)?;
    

    Ok(())
}

fn main() -> optee_teec::Result<()> {
    let mut ctx = Context::new()?;
    let uuid = Uuid::parse_str(UUID).unwrap();
    let mut session = ctx.open_session(uuid)?;

    big_int(&mut session)?;

    println!("Success");

    // message_passing_interface::test_main()?;
    Ok(())
}
