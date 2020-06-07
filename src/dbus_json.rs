use dbus::arg;
use dbus::arg::messageitem::{MessageItem, MessageItemArray, MessageItemDict};
use dbus::strings::Signature;
use json::Value;
use serde_json as json;

#[derive(Debug, PartialEq)]
pub enum Sig {
    Array(Box<Sig>),
    KV(Box<Sig>, Box<Sig>),
    SimpleType(u8),
}

impl Sig {
    fn get_signature(&self) -> Vec<u8> {
        match self {
            Sig::SimpleType(t) => vec![*t],
            Sig::KV(key, val) => b"{"
                .iter()
                .chain(key.get_signature().iter())
                .chain(val.get_signature().iter())
                .chain(b"}")
                .map(|v| *v)
                .collect(),
            Sig::Array(item_sig) => b"a"
                .iter()
                .chain(item_sig.get_signature().iter())
                .map(|v| *v)
                .collect(),
        }
    }
}

fn parse_signature(sig: &mut std::slice::Iter<u8>) -> Option<Sig> {
    match sig.next() {
        Some(b'a') => match parse_signature(sig) {
            Some(t) => return Some(Sig::Array(Box::new(t))),
            _ => None,
        },
        Some(b'{') => match (parse_signature(sig), parse_signature(sig)) {
            (Some(key_type), Some(val_type)) => match sig.next() {
                Some(b'}') => Some(Sig::KV(Box::new(key_type), Box::new(val_type))),
                _ => None,
            },
            _ => None,
        },
        Some(type_char) => Some(Sig::SimpleType(*type_char)),
        _ => None,
    }
}

pub fn json_value_to_message_item(
    value: &Value,
    signature: &[u8],
) -> Option<dbus::arg::messageitem::MessageItem> {
    let mut sig = signature.iter();
    let parsed_sig = parse_signature(&mut sig);
    match parsed_sig {
        Some(Sig::Array(item_sig)) => match *item_sig {
            Sig::KV(key_type, val_type) => match value {
                Value::Array(items) => {
                    let data: Option<Vec<(MessageItem, MessageItem)>> = items
                        .iter()
                        .map(|item| match item {
                            Value::Array(kv) => match kv.as_slice() {
                                [k, v] => match (
                                    json_value_to_message_item(k, &key_type.get_signature()),
                                    json_value_to_message_item(v, &val_type.get_signature()),
                                ) {
                                    (Some(km), Some(vm)) => Some((km, vm)),
                                    _ => None,
                                },
                                _ => None,
                            },
                            _ => None,
                        })
                        .collect();
                    data.map(|v| {
                        MessageItem::Dict(
                            MessageItemDict::new(
                                v,
                                Signature::new(key_type.get_signature()).unwrap(),
                                Signature::new(val_type.get_signature()).unwrap(),
                            )
                            .unwrap(),
                        )
                    })
                }
                _ => None,
            },
            Sig::SimpleType(_) => match value {
                Value::Array(items) => {
                    let item_sig = item_sig.get_signature();
                    println!("items: {:?}, item_sig: {:?}", items, item_sig);
                    let data = items
                        .iter()
                        .map(|item| json_value_to_message_item(item, item_sig.as_slice()).unwrap())
                        .collect();
                    Some(MessageItem::Array(
                        MessageItemArray::new(data, Signature::new(signature).unwrap()).unwrap(),
                    ))
                }
                _ => None,
            },
            _ => None,
        },
        Some(Sig::SimpleType(t)) => match t {
            b'y' => value.as_u64().map(|v| MessageItem::Byte(v as u8)),
            b'n' => value.as_i64().map(|v| MessageItem::Int16(v as i16)),
            b'q' => value.as_u64().map(|v| MessageItem::UInt16(v as u16)),
            b'i' => value.as_i64().map(|v| MessageItem::Int32(v as i32)),
            b'u' => value.as_u64().map(|v| MessageItem::UInt32(v as u32)),
            b'x' => value.as_i64().map(|v| MessageItem::Int64(v as i64)),
            b't' => value.as_u64().map(|v| MessageItem::UInt64(v)),
            b'd' => value.as_f64().map(|v| MessageItem::Double(v)),
            b's' => value.as_str().map(|v| MessageItem::Str(v.to_string())),
            b'b' => value.as_bool().map(|v| MessageItem::Bool(v)),
            b'o' => value
                .as_str()
                .map(|v| MessageItem::ObjectPath(v.to_string().into())),
            b'v' => json_value_to_message_item(value, b"s").or_else(|| {
                json_value_to_message_item(value, b"b").or_else(|| {
                    json_value_to_message_item(value, b"u").or_else(|| {
                        json_value_to_message_item(value, b"t")
                            .or_else(|| json_value_to_message_item(value, b"d"))
                    })
                })
            }),
            _ => None,
        },
        _ => None,
    }
}

pub fn refarg_to_json(value: &dyn arg::RefArg) -> Option<json::Value> {
    match value.arg_type() {
        arg::ArgType::Array => {
            let iter = value.as_iter()?;
            let items: Option<Vec<json::Value>> = iter.map(|item| refarg_to_json(item)).collect();
            Some(json::Value::Array(items?))
        }
        arg::ArgType::DictEntry => {
            Some(json::Value::Null) // TODO
        },
        arg::ArgType::Variant => {
            let x = value.as_iter()?.next();
            refarg_to_json(x?)
        },
        arg::ArgType::Boolean => Some(json::Value::Bool(value.as_u64()? != 0)),
        arg::ArgType::Invalid => Some(json::Value::Null),
        arg::ArgType::String => Some(json::Value::String(value.as_str()?.to_string())),
        arg::ArgType::ObjectPath => Some(json::Value::String(value.as_str()?.to_string())),
        arg::ArgType::Byte | arg::ArgType::UInt16 | arg::ArgType::UInt32 | arg::ArgType::UInt64 => {
            Some(json::Value::from(value.as_u64()?))
        }
        arg::ArgType::Int16 | arg::ArgType::Int32 | arg::ArgType::Int64 | arg::ArgType::UnixFd => {
            Some(json::Value::from(value.as_i64()?))
        }
        arg::ArgType::Double => Some(json::Value::from(value.as_f64()?)),
        arg::ArgType::Struct => Some(json::Value::Null),
        arg::ArgType::Signature => Some(json::Value::String(value.as_str()?.to_string())),
    }
}

pub fn variant_to_json(value: &arg::Variant<Box<dyn arg::RefArg>>) -> Option<String> {
    Some(refarg_to_json(&value.0)?.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_simple_type() {
        assert_eq!(
            parse_signature(&mut b"y".iter()),
            Some(Sig::SimpleType(b'y'))
        )
    }
    #[test]
    fn parse_array() {
        assert_eq!(
            parse_signature(&mut b"ay".iter()),
            Some(Sig::Array(Box::new(Sig::SimpleType(b'y'))))
        )
    }
    #[test]
    fn parse_nested_array() {
        assert_eq!(
            parse_signature(&mut b"aay".iter()),
            Some(Sig::Array(Box::new(Sig::Array(Box::new(Sig::SimpleType(
                b'y'
            ))))))
        )
    }
    #[test]
    fn parse_dict() {
        assert_eq!(
            parse_signature(&mut b"a{yy}".iter()),
            Some(Sig::Array(Box::new(Sig::KV(
                Box::new(Sig::SimpleType(b'y')),
                Box::new(Sig::SimpleType(b'y'))
            ))))
        )
    }
    #[test]
    fn convert1() {
        assert_eq!(
            json_value_to_message_item(&serde_json::from_str("1").unwrap(), b"y"),
            Some(MessageItem::Byte(1))
        )
    }
    #[test]
    fn convert2() {
        assert_eq!(
            json_value_to_message_item(&serde_json::from_str("[1]").unwrap(), b"ay"),
            Some(MessageItem::Array(
                MessageItemArray::new(
                    vec![MessageItem::Byte(1)],
                    Signature::new("ay".as_bytes()).unwrap()
                )
                .unwrap()
            ))
        )
    }
    #[test]
    fn convert3() {
        assert_eq!(
            json_value_to_message_item(&serde_json::from_str("1").unwrap(), b"ay"),
            None,
        )
    }
    #[test]
    fn convert4() {
        assert_eq!(
            json_value_to_message_item(&serde_json::from_str("[1]").unwrap(), b"y"),
            None,
        )
    }
    #[test]
    fn convert5() {
        assert_eq!(
            json_value_to_message_item(&serde_json::from_str("257").unwrap(), b"y"),
            Some(MessageItem::Byte(1))
        )
    }
    #[test]
    fn test_dict_refarg_to_json() {
        let mut x: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
        x.insert("a".to_string(), 1);
        let dict = Box::new(x) as Box<dyn arg::RefArg>;
        let value = refarg_to_json(&dict);

        assert_eq!(value, Some(Value::Array(vec![Value::from("a"), Value::from(1)])));
        println!("value: {:?}", value);
    }
}
