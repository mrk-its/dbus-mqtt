use std::error::Error;
use std::fmt;
pub type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Debug)]
pub struct DBusMqttErr {
    descr: String
}

impl fmt::Display for DBusMqttErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Customize so only `x` and `y` are denoted.
        write!(f, "{}", self.descr)
    }
}
impl Error for DBusMqttErr {
}

impl DBusMqttErr {
    pub fn new(descr: &str) -> Box<DBusMqttErr> {
        Box::new(DBusMqttErr {
            descr: descr.to_string()
        })
    }
}

pub fn err(descr: &str) -> Box<DBusMqttErr> {
    DBusMqttErr::new(descr)
}
