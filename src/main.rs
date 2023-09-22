// #![windows_subsystem = "windows"]

use sip_monitor::*;
#[cfg(windows)]
use websocket::{sync::Client, OwnedMessage};
use std::{
    process::Command,
    thread,
    path::Path,
    net::{Ipv4Addr, TcpStream},
    sync::{
        mpsc,
        Arc,
        Mutex
    },
    time::Duration,
    collections::{
        BTreeMap,
        HashMap
    },
    io::{
        self,
        prelude::*,
        Result as IoResult
    }
};
#[cfg(windows)]
use websocket::sync::Server;
#[cfg(windows)]
use ghostemp::{
    Urls,
    ClientHTTP,
    prelude::*
};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

fn main() {
    #[cfg(windows)]
    if eframe().is_none() {
        web().unwrap();
    }
}

/// Call this once from the HTML.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub async fn start(canvas_id: &str) -> Result<(), eframe::wasm_bindgen::JsValue> {
    let mut web_options = eframe::WebOptions::default();
    eframe::start_web(canvas_id, web_options, Box::new(|cc| Box::new(SipMonitor::new(cc)))).await?;
    Ok(())
}

#[cfg(windows)]
fn eframe() -> Option<()> {
    use eframe::Renderer;

    let mut native_options = eframe::NativeOptions::default();
    native_options.maximized = true;
    native_options.renderer = Renderer::Wgpu;
    eframe::run_native("Sip Monitor", native_options, Box::new(|cc| Box::new(SipMonitor::new(cc)))).ok()
}

#[cfg(windows)]
fn web() -> IoResult<()> {
    let mut urls = Urls::new();

    urls.add(|_, _, _| {
        Path::new("web/index.html").render()
    });

    for r in ["js", "css"] {
        urls.append(r, |req, _, _| {
            Path::new(&format!("web{}", req.url())).render()
        })
    }

    Command::new("cmd.exe")
        .arg("/C").arg("start").arg("").arg("http://127.0.0.1:61380").spawn()?;

    let client = ClientHTTP::new(urls)?;
    client.listen_local(61380)?;

    let ws = Server::bind("127.0.0.1:61338")?;

    for stream in ws.filter_map(Result::ok) {
        let Ok(mut stream) = stream.accept() else { continue };
        
        thread::spawn(move || {
            let msg = stream.recv_message().unwrap();

            if let OwnedMessage::Text(ref s) = msg {
                let Cred { user, pass, addr } = serde_json::from_str(s).unwrap();

                ami_web_monitoring(stream, user, pass, addr.parse().unwrap()).unwrap();
            }
        });
    }

    Ok(())
}

#[cfg(windows)]
pub fn ami_web_monitoring(mut stream: Client<TcpStream>, user: String, pass: String, ip: Ipv4Addr) -> IoResult<()> {
    let ami = AmiConnect::new(user, pass, ip, 5038);
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
                    .entry(sip)
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
        map.lock().unwrap().insert(contact.name, status);
    }

    let data = serde_json::to_string(&*map.lock().unwrap())?;
    stream.send_message(&OwnedMessage::Text(data)).unwrap();

    loop {
        recv.recv().unwrap();
        let data = serde_json::to_string(&*map.lock().unwrap())?;
        stream.send_message(&OwnedMessage::Text(data)).unwrap();

        thread::sleep(Duration::from_millis(1000 / 60));
    }
}

pub fn ami_monitoring() -> IoResult<()> {
    let mut buf = [0u8; 1024];

    print!("IP: ");
    io::stdout().flush().unwrap();
    let size = io::stdin().read(&mut buf).unwrap();
    let ip = String::from_utf8_lossy(&buf[..size]).trim().parse().unwrap();

    print!("user ");
    io::stdout().flush().unwrap();
    let size = io::stdin().read(&mut buf).unwrap();
    let user = String::from_utf8_lossy(&buf[..size]).trim().parse().unwrap();

    print!("Pass: ");
    io::stdout().flush().unwrap();
    let size = io::stdin().read(&mut buf).unwrap();
    let pass = String::from_utf8_lossy(&buf[..size]).trim().to_owned();

    let ami = AmiConnect::new(user, pass, ip, 5038);
    let mut ami = Ami::new(ami)?;
    let (send, recv) = mpsc::channel();
    let map = Arc::new(Mutex::new(BTreeMap::new()));
    let sync_map = Arc::clone(&map);

    ami.init_treat(move |val| {
        println!("{val}\n");
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

fn get_map(val: &str) -> HashMap<&str, &str> {
    val.lines().map(|x| x.split(": "))
        .map(|mut x| (x.next().unwrap_or_default(), x.next().unwrap_or_default()))
        .collect::<HashMap<_, _>>()
}

fn sip_status(val: &str) -> Message {
    let v = get_map(val);

    if v.contains_key("Exten") && v.contains_key("Status") && v.contains_key("StatusText") {
        Message::Sip(v.get("Exten").unwrap().to_string(), SipStatus { status: v.get("Status").unwrap().parse().unwrap_or_default(), status_text: v.get("StatusText").unwrap().to_string() })
    } else { Message::Unknown }
}

fn contact(val: &str) -> Message {
    let v = get_map(val);

    if v.contains_key("ObjectName") && v.contains_key("Contacts") {
        Message::Contact{ name: v.get("ObjectName").unwrap().parse().unwrap_or_default(), contact: v.get("Contacts").unwrap().to_string() }
    } else { Message::Unknown }
}