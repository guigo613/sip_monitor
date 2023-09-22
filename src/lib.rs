mod ami;
mod eframealt;

pub use self::ami::*;
pub use self::eframealt::*;

use std::{
    process::Command,
    thread,
    sync::{
        mpsc,
        Arc,
        Mutex
    },
    fmt::{
        self,
        Display
    },
    time::Duration,
    collections::{
        BTreeMap,
        HashMap
    },
    io::{
        self,
        prelude::*,
        Result
    },
    cmp::Ordering
};
use serde::*;

const WITDH: f32 = 130.;
const HEIGHT: f32 = 70.;

type AllData = Arc<Mutex<BTreeMap<String, SipStatus>>>;

pub fn ami_monitoring() -> Result<()> {
    let mut buf = [0u8; 1024];

    print!("IP: ");
    io::stdout().flush().unwrap();
    let size = io::stdin().read(&mut buf).unwrap();
    let ip = String::from_utf8_lossy(&buf[..size]).trim().parse().unwrap();

    print!("Pass: ");
    io::stdout().flush().unwrap();
    let size = io::stdin().read(&mut buf).unwrap();
    let pass = String::from_utf8_lossy(&buf[..size]).trim().to_owned();

    let ami = AmiConnect::new("Monitor".to_owned(), pass, ip, 5038);
    let mut ami = Ami::new(ami)?;
    let (send, recv) = mpsc::channel();
    let map = Arc::new(Mutex::new(BTreeMap::new()));
    let sync_map = Arc::clone(&map);

    ami.init_treat(move |val| {
        // println!("{val}\n");
        match val.as_bytes() {
            [b'R', b'e', b's', b'p', b'o', b'n', b's', b'e', b':', b' ', b'S', b'u', b'c', b'c', b'e', b's', b's', ..] => {
                let msg = process(&val);

                send.send(msg).unwrap()
            },
            [b'R', b'e', b's', b'p', b'o', b'n', b's', b'e', b':', b' ', ..] => {
                println!("{val}");
                send.send(Message::Unknown).unwrap()
            },
            [b'E', b'v', b'e', b'n', b't', b':', b' ', b'A', b'o', b'r', b'L', b'i', b's', b't', b'C', b'o', b'm', b'p', b'l', b'e', b't', b'e', ..] => send.send(Message::Complete).unwrap(),
            [b'E', b'v', b'e', b'n', b't', b':', b' ', b'A', b'o', b'r', b'L', b'i', b's', b't', ..] => {
                let msg = contact(&val);

                send.send(msg).unwrap()
            },
            [b'E', b'v', b'e', b'n', b't', b':', b' ', b'E', b'x', b't', b'e', b'n', b's', b'i', b'o', b'n', b'S', b't', b'a', b't', b'u', b's', ..] => {
                let Message::Sip(sip, status) = process(&val) else { return };
                sync_map.lock().unwrap()
                    .entry(Contact::from_name(sip))
                    .and_modify(|x| *x = status);

                send.send(Message::Updated).unwrap()
            },
            _ => ()
        }
    })?;

    ami.pjsip_show_aors().unwrap();
    let mut contacts = Vec::new();

    if let Message::Start = recv.recv().unwrap() {
        loop {
            let msg = recv.recv().unwrap();

            match msg {
                Message::Complete => break,
                Message::Contact { contact, name } => {
                    contacts.push(Contact { contact, name });
                }
                _ => ()
            }
        }
    }

    for contact in contacts {
        ami.extension_state(&contact.name, "ext-local").unwrap();

        let Message::Sip(_, status) = recv.recv().unwrap() else { panic!() };
        map.lock().unwrap().insert(contact, status);
    }

    Command::new("cmd").args(["/C", "cls"]).status().unwrap();
    println!("{}", Some(map.lock().unwrap().iter().map(|(k, v)| format!("{k} = {v}")).collect::<Vec<_>>()).map(|mut x| { x.reverse(); x }).unwrap().join("\r\n"));

    loop {
        recv.recv().unwrap();
        Command::new("cmd").args(["/C", "cls"]).status().unwrap();
        println!("{}", Some(map.lock().unwrap().iter().map(|(k, v)| format!("{k} = {v}")).collect::<Vec<_>>()).map(|mut x| { x.reverse(); x }).unwrap().join("\r\n"));

        thread::sleep(Duration::from_millis(1000 / 60));
    }
}


#[derive(Debug, Eq, Hash, Deserialize, Serialize)]
pub struct Contact {
    pub name: String,
    pub contact: String
}

impl Contact {
    pub fn from_name<S: Into<String>>(name: S) -> Self {
        Self {
            contact: Default::default(),
            name: name.into()
        }
    }
}

impl PartialOrd for Contact {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.name.partial_cmp(&other.name)
    }
}

impl PartialOrd<str> for Contact {
    fn partial_cmp(&self, other: &str) -> Option<Ordering> {
        other.partial_cmp(&self.name[..])
    }
}

impl Ord for Contact {
    fn cmp(&self, other: &Self) -> Ordering {
        self.name.cmp(&other.name)
    }
}

impl PartialEq for Contact {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl PartialEq<str> for Contact {
    fn eq(&self, other: &str) -> bool {
        self.name == *other
    }
}

impl Display for Contact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SIP: {}", self.name)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SipStatus {
    pub status: i8,
    pub status_text: String
}

impl Display for SipStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Status: {} - StatusText: {}", self.status, self.status_text)
    }
}

pub enum Message {
    Sip(String, SipStatus),
    Contact {
        contact: String,
        name: String
    },
    Start,
    Complete,
    Updated,
    Unknown
}

pub fn process(val: &str) -> Message {
    if val.contains("EventList: start") {
        Message::Start
    } else {
        sip_status(val)
    }
}

pub fn get_map(val: &str) -> HashMap<&str, &str> {
    val.lines().map(|x| x.split(": "))
        .map(|mut x| (x.next().unwrap_or_default(), x.next().unwrap_or_default()))
        .collect::<HashMap<_, _>>()
}

pub fn sip_status(val: &str) -> Message {
    let v = get_map(val);

    if v.contains_key("Exten") && v.contains_key("Status") && v.contains_key("StatusText") {
        Message::Sip(v.get("Exten").unwrap().to_string(), SipStatus { status: v.get("Status").unwrap().parse().unwrap_or_default(), status_text: v.get("StatusText").unwrap().to_string() })
    } else { Message::Unknown }
}

pub fn contact(val: &str) -> Message {
    let v = get_map(val);

    if v.contains_key("ObjectName") && v.contains_key("Contacts") {
        Message::Contact{ name: v.get("ObjectName").unwrap().parse().unwrap_or_default(), contact: v.get("Contacts").unwrap().to_string() }
    } else { Message::Unknown }
}