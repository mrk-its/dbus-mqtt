#[macro_use]
extern crate log;

mod dbus_mqtt;
mod dbus_json;
mod err;

use dbus_mqtt::DBusMqtt;

use clap::{App, Arg, ArgMatches};
use dbus::blocking::Connection;
use std::env;
use uuid::Uuid;

use err::Result;

fn generate_client_id() -> String {
    format!("/MQTT/rust/{}", Uuid::new_v4())
}


fn cli_opts() -> ArgMatches<'static> {
    App::new("dbus-mqtt")
        .author("<mrk@sed.pl>")
        .arg(
            Arg::with_name("SERVER")
                .short("S")
                .long("server")
                .takes_value(true)
                .required(true)
                .help("MQTT server address (host:port)"),
        )
        .arg(
            Arg::with_name("PASSWORD")
                .short("p")
                .long("password")
                .takes_value(true)
                .help("Password"),
        )
        .arg(
            Arg::with_name("CLIENT_ID")
                .short("i")
                .long("client-identifier")
                .takes_value(true)
                .help("Client identifier"),
        )
        .get_matches()
}

fn setup_logger() {
    // configure logging
    env::set_var(
        "RUST_LOG",
        env::var_os("RUST_LOG").unwrap_or_else(|| "info".into()),
    );
    env_logger::init();
}

fn main() -> Result<()> {
    setup_logger();
    let matches = cli_opts();
    let mut system_bus = Connection::new_system().expect("cannot connect to system bus");

    let mqtt_server_addr = matches.value_of("SERVER").ok_or("err")?;
    let client_id = matches
        .value_of("CLIENT_ID")
        .map(|x| x.to_owned())
        .unwrap_or_else(generate_client_id);

    let dbus_mqtt = DBusMqtt::new("org.bluez", mqtt_server_addr, &client_id, "dbus")?;
    dbus_mqtt.run(&mut system_bus)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_byte_sig() {
        assert_eq!(
            dbus::arg::messageitem::MessageItem::Byte(1).signature(),
            "y".into()
        );
    }
    #[test]
    fn test_array_creation() {
        assert_eq!(
            dbus::arg::messageitem::MessageItemArray::new(vec![], "ay".into())
                .unwrap()
                .signature(),
            &dbus::strings::Signature::from("ay")
        );
    }
}
