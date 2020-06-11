use crate::err::{err, Result};
use dbus::blocking::stdintf::org_freedesktop_dbus::{
    ObjectManager, ObjectManagerInterfacesAdded, ObjectManagerInterfacesRemoved,
    PropertiesPropertiesChanged,
};
use dbus::blocking::Connection;
use dbus::channel::Sender;
use dbus::message::SignalArgs;
use dbus::Message;
use dbus::{arg, Path};

use mqtt::control::variable_header::ConnectReturnCode;
use mqtt::packet::*;
use mqtt::topic_name::TopicName;
use mqtt::{Decodable, Encodable, QualityOfService, TopicFilter};

use std::collections::HashMap;
use std::net::TcpStream;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::dbus_json;
use std::io::Write;

type Properties = HashMap<String, arg::Variant<Box<dyn arg::RefArg>>>;

const TIMEOUT: Duration = Duration::from_secs(10);
const BLUEZ_BUS_NAME: &str = "org.bluez";

#[derive(Debug)]
pub struct DBusMqtt {
    dbus_names: Vec<String>,
    mqtt_prefix: String,
    stream: TcpStream,
}

impl DBusMqtt {
    pub fn new(
        dbus_names: &Vec<String>,
        mqtt_server_addr: &str,
        client_id: &str,
        mqtt_prefix: &str,
    ) -> Result<DBusMqtt> {
        let mut stream = mqtt_connect(mqtt_server_addr, &client_id)?;
        let sub_packet = SubscribePacket::new(
            10,
            vec![(
                TopicFilter::new(format!("{}/#", mqtt_prefix))?,
                QualityOfService::Level0,
            )],
        );
        send_packet(&sub_packet, &mut stream)?;
        Ok(DBusMqtt {
            dbus_names: dbus_names.clone(),
            mqtt_prefix: mqtt_prefix.to_string(),
            stream: stream,
        })
    }
    pub fn dbus_names(&self) -> &Vec<String> {
        &self.dbus_names
    }
    pub fn mqtt_prefix(&self) -> &str {
        &self.mqtt_prefix
    }
    pub fn init_dbus(&self, bus_name: &str, conn: &Connection) -> Result<()> {
        let proxy = conn.with_proxy(bus_name, "/", TIMEOUT);
        let mut cloned_stream = self.stream.try_clone()?;
        let mqtt_prefix = self.mqtt_prefix().to_string();
        let bus_name_copy = bus_name.to_string();
        proxy.match_signal(
            move |h: ObjectManagerInterfacesAdded, _: &Connection, _: &Message| {
                debug!("interfaces added: {:?}", h);
                for (itf_name, properties) in h.interfaces {
                    process_properties(
                        &mqtt_prefix,
                        &bus_name_copy,
                        &h.object,
                        &itf_name,
                        &properties,
                        &mut cloned_stream,
                    )
                    .ok();
                }
                true
            },
        )?;
        proxy.match_signal(
            |h: ObjectManagerInterfacesRemoved, _: &Connection, _: &Message| {
                debug!("interface removed: {:?}", h);
                true
            },
        )?;

        let mqtt_prefix = self.mqtt_prefix().to_string();
        let bus_name_copy = bus_name.to_string();
        let mut cloned_stream = self.stream.try_clone()?;
        let mr =
            PropertiesPropertiesChanged::match_rule(Some(&bus_name.into()), None).static_clone();
        conn.add_match(mr, move |pc: PropertiesPropertiesChanged, _, m| {
            if !(pc.changed_properties.len() == 1 && pc.changed_properties.contains_key("RSSI")) {
                debug!("properties changed {:?} {:?}", pc, m.path());
            }
            if let Some(path) = m.path() {
                process_properties(
                    &mqtt_prefix,
                    &bus_name_copy,
                    &path,
                    &pc.interface_name,
                    &pc.changed_properties,
                    &mut cloned_stream,
                )
                .ok();
            }
            true
        })?;

        let mqtt_prefix = self.mqtt_prefix().to_string();
        let bus_name_copy = bus_name.to_string();
        let mut cloned_stream = self.stream.try_clone()?;
        if let Ok(objects) = proxy.get_managed_objects() {
            for (path, v) in objects {
                for (itf_name, properties) in v {
                    process_properties(
                        &mqtt_prefix,
                        &bus_name_copy,
                        &path,
                        &itf_name,
                        &properties,
                        &mut cloned_stream,
                    )
                    .ok();
                }
            }
        }
        Ok(())
    }
    pub fn run(&self, connection: &mut Connection) -> Result<()> {
        for dbus_name in self.dbus_names() {
            self.init_dbus(dbus_name, connection)?;
        }
        if self.dbus_names.iter().find(|x| *x == BLUEZ_BUS_NAME).is_some() {
            setup_ble_discovery(connection)?;
        }
        let (mqtt_tx, mqtt_rx): (mpsc::Sender<VariablePacket>, mpsc::Receiver<VariablePacket>) =
            mpsc::channel();

        let mut cloned_stream = self.stream.try_clone()?;
        thread::spawn(move || {
            loop {
                let packet = match VariablePacket::decode(&mut cloned_stream) {
                    Ok(pk) => pk,
                    Err(err) => {
                        error!("Error in receiving packet {:?}", err);
                        continue;
                    }
                };
                trace!("PACKET {:?}", packet);

                match packet {
                    VariablePacket::PingreqPacket(..) => {
                        let pingresp = PingrespPacket::new();
                        info!("Sending Ping response {:?}", pingresp);
                        pingresp.encode(&mut cloned_stream).unwrap();
                    }
                    VariablePacket::DisconnectPacket(..) => {
                        break;
                    }
                    _ => {
                        // Ignore other packets in pub client
                        trace!("{:?}", packet);
                        mqtt_tx.send(packet).expect("cant send");
                    }
                }
            }
        });
        loop {
            for mqtt_packet in mqtt_rx.try_iter().take(1) {
                match mqtt_packet {
                    VariablePacket::PublishPacket(packet) => {
                        let topic = packet.topic_name();
                        if topic.ends_with("()") {
                            let (topic, _) = topic.split_at(topic.len() - 2);
                            if let Ok(payload) = std::str::from_utf8(packet.payload_ref()) {
                                self.dbus_method_call(topic, payload, connection).ok();
                            }
                        }
                    }
                    _ => {}
                }
            }
            (1..2)
                .take_while(|_| {
                    connection
                        .process(Duration::from_millis(1))
                        .unwrap_or(false)
                })
                .count();
        }
    }

    fn parse_topic<'a>(&self, topic: &'a str) -> Option<(&'a str, &'a str, &'a str, &'a str)> {
        let prefix_len = self.mqtt_prefix.len();
        if !topic.starts_with(&self.mqtt_prefix)
            || topic.get(prefix_len..prefix_len + 1) != Some("/")
        {
            return None;
        }
        let topic = &topic[prefix_len + 1..];
        let bus_name = topic.split("/").next()?;
        let mut tail = topic.rsplit("/");
        let method = tail.next()?;
        let itf = tail.next()?;
        let path = &topic[bus_name.len()..topic.len() - method.len() - 1 - itf.len() - 1];
        Some((bus_name, path, itf, method))
    }

    fn dbus_method_call(&self, topic: &str, payload: &str, conn: &mut Connection) -> Result<()> {
        /* topic format:
           {mqtt_prefix}/{dbus_name}/path/{interface}/{method}
        */
        let (bus_name, path, itf_name, method) =
            self.parse_topic(topic).ok_or("invalid topic")?;
        info!("method call: {:?} {:?} {:?}", path, itf_name, method);
        let mut msg = dbus::Message::new_method_call(bus_name, path, itf_name, method)?;
        let cmd_args: Option<serde_json::Value> = serde_json::from_str(payload).ok();
        let arg_spec = self.introspect_method_args(conn, bus_name, path, itf_name, method)?;

        info!("command args: {:?} {:?}", arg_spec, cmd_args);

        match cmd_args {
            Some(serde_json::Value::Array(items)) => {
                for (spec, arg) in arg_spec.iter().map(|s| s.as_bytes()).zip(items) {
                    match dbus_json::json_value_to_message_item(&arg, spec) {
                        Some(message_item) => {
                            info!("appending {:?}", message_item);
                            msg.append_items(&[message_item]);
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }

        let r = conn.send(msg);
        info!(
            "BLE command {} {} for {:?}, result: {:?}",
            itf_name, method, path, r
        );
        Ok(())
    }

    fn introspect_method_args(
        &self,
        system_bus: &Connection,
        dbus_name: &str,
        path: &str,
        interface: &str,
        method_name: &str,
    ) -> Result<Vec<String>> {
        let proxy = system_bus.with_proxy(dbus_name, path, TIMEOUT);
        let xml_str: (String,) =
            proxy.method_call("org.freedesktop.DBus.Introspectable", "Introspect", ())?;

        let doc = roxmltree::Document::parse(&xml_str.0)?;
        let intf_node = doc
            .descendants()
            .find(|node| {
                node.has_tag_name("interface") && node.attribute("name") == Some(interface)
            })
            .ok_or(err("interface not found"))?;
        let method_node = intf_node
            .children()
            .find(|node| node.has_tag_name("method") && node.attribute("name") == Some(method_name))
            .ok_or(err("method not found"))?;
        let arg_signatures = method_node
            .children()
            .filter(|node| node.has_tag_name("arg") && node.attribute("direction") == Some("in"))
            .flat_map(|node| node.attribute("type").map(|v| v.to_string()))
            .collect::<Vec<String>>();
        Ok(arg_signatures)
    }
}

fn mqtt_connect(server_addr: &str, client_id: &str) -> Result<TcpStream> {
    info!("Connecting to {:?} ... ", server_addr);
    let mut stream = TcpStream::connect(server_addr).expect("can't connetc to mqtt server");
    info!("Connected!");

    info!("Client identifier {:?}", client_id);
    let mut conn_packet = ConnectPacket::new("MQTT", client_id);
    conn_packet.set_clean_session(true);
    send_packet(&conn_packet, &mut stream).expect("can't initialize mqtt connection");

    let connack = ConnackPacket::decode(&mut stream)?;
    trace!("CONNACK {:?}", connack);

    if connack.connect_return_code() != ConnectReturnCode::ConnectionAccepted {
        return Err(err("Failed to connect to server"));
    }
    Ok(stream)
}

fn process_properties(
    mqtt_prefix: &str,
    bus_name: &str,
    path: &Path,
    itf_name: &str,
    properties: &Properties,
    stream: &mut TcpStream,
) -> Result<()> {
    for key in properties.keys() {
        let packet = create_publish_packet(
            mqtt_prefix,
            bus_name,
            itf_name,
            path,
            properties,
            key,
            false,
        )?;
        send_packet(&packet, stream)?;
    }
    Ok(())
}

fn create_publish_packet(
    mqtt_prefix: &str,
    bus_name: &str,
    itf_name: &str,
    path: &Path,
    properties: &Properties,
    key: &str,
    retain: bool,
) -> Result<PublishPacket> {
    let payload = get_payload(properties, key).ok_or("payload")?;
    let topic = TopicName::new(get_topic_name(mqtt_prefix, bus_name, path, itf_name, key))?;
    info!("mqtt publish, topic: {:?}, payload: {}", &topic, &payload);
    let mut packet = PublishPacket::new(topic, QoSWithPacketIdentifier::Level0, payload);
    packet.set_retain(retain && false);
    Ok(packet)
}

fn send_packet<T: Encodable>(packet: &T, stream: &mut TcpStream) -> Result<()> {
    let mut buf = Vec::new();
    packet.encode(&mut buf).ok();
    stream.write_all(&buf[..])?;
    Ok(())
}

fn get_payload<'a>(properties: &'a Properties, key: &str) -> Option<String> {
    properties
        .get(key)
        .map(dbus_json::variant_to_json)
        .flatten()
}

pub fn get_topic_name(
    mqtt_prefix: &str,
    bus_name: &str,
    path: &Path,
    itf_name: &str,
    suffix: &str,
) -> String {
    format!(
        "{}/{}{}/{}/{}",
        mqtt_prefix, bus_name, path, itf_name, suffix
    )
}

fn setup_ble_discovery(system_bus: &Connection) -> Result<()> {
    let bluez_proxy = system_bus.with_proxy("org.bluez", "/org/bluez/hci0", TIMEOUT);
    let _: () = bluez_proxy.method_call("org.bluez.Adapter1", "StartDiscovery", ())?;

    let mut map: Properties = HashMap::new();
    map.insert(
        "Transport".to_string(),
        arg::Variant(Box::new("le".to_string())),
    );
    map.insert("RSSI".to_string(), arg::Variant(Box::new(-70 as i16)));
    debug!("set_discovery_filter: {:?}", &map);
    let _: () = bluez_proxy.method_call("org.bluez.Adapter1", "SetDiscoveryFilter", (map,))?;
    Ok(())
}
