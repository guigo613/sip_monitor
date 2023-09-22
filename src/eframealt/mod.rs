use crate::*;
use std::{
    sync::{
        mpsc,
        Arc,
        Mutex
    },
    collections::{
        BTreeMap
    },
    ops::{
        Deref,
        DerefMut
    },
};
use serde::*;
use eframe::{
    egui::{
        self,
        Vec2,
        Pos2,
        Frame,
        Color32,
        TextEdit, RichText
    },
};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;
#[cfg(target_arch = "wasm32")]
use web_sys::{MessageEvent, WebSocket, BinaryType};

#[cfg(target_arch = "wasm32")]
#[macro_export]
macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[derive(Default)]
pub struct SipMonitor {
    cred: Cred,
    conf: Config,
    state: StateScreen,
    #[cfg(windows)]
    conn: Option<(Ami, Data)>,
    #[cfg(target_arch = "wasm32")]
    data: Option<Data>
}

impl SipMonitor {
    pub fn new(_: &eframe::CreationContext<'_>) -> Self {
        Self::default()
    }
}


impl eframe::App for SipMonitor {
   fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let Cred { user, pass, addr } = &mut self.cred;
        let Config { color, size } = &mut self.conf;
        let pass2 = TextEdit::singleline(pass).password(true);

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("SipMonitor");
                ui.checkbox(color, "Color");
            });
            *size = ui.available_size();
        });


        if let StateScreen::Logged = self.state {
            #[cfg(windows)]
            if let None = self.conn {
                self.conn = Some(login2(&self.cred));
            }

            #[cfg(target_arch = "wasm32")]
            if let None = self.data {
                self.data = Some(login3(&self.cred));
            }

            let mut data: Option<&Data> = None;

            #[cfg(windows)]
            {
                let (_, d) = &self.conn.as_ref().unwrap();
                data = Some(d);
            }

            #[cfg(target_arch = "wasm32")]
            {
                let d = &self.data.as_ref().unwrap();
                data = Some(d);
            }

            let width = WITDH + 20.;
            let len = (size.x / width).floor() * width;

            for (idx, (contact, status)) in data.unwrap().lock().unwrap().iter().enumerate() {
                let frame = Frame::window(&ctx.style()).fill({
                    if !*color {
                        match status.status {
                            0 => Color32::DARK_GREEN,
                            1 | 9 => Color32::DARK_BLUE,
                            2 | 4 => Color32::DARK_RED,
                            8 => Color32::YELLOW,
                            16 | 17 => Color32::BROWN,
                            _ => Color32::DARK_GRAY
                        }
                    } else {
                        match status.status {
                            0 => Color32::DARK_BLUE,
                            1 | 9 => Color32::GOLD,
                            2 | 4 => Color32::DARK_RED,
                            8 => Color32::YELLOW,
                            16 | 17 => Color32::KHAKI,
                            _ => Color32::DARK_GRAY
                        }
                    }
                });

                egui::Window::new(RichText::new(format!("SIP: {}", contact)).color(Color32::WHITE))
                    .current_pos(Pos2::new(idx as f32 * width % len + 20., (idx as f32 * width / len).floor() * HEIGHT + 30.))
                    .frame(frame)
                    .show(ctx, |ui| {
                        // ui.label(format!("Contact: {}", contact.contact));
                        // ui.label(format!("Status: {}", status.status));
                        ui.colored_label(Color32::WHITE, format!("StatusText: {}", status.status_text));
                        // ui.label(format!("x: {} - y: {}", size.x % (idx as f32 * (WITDH + 20.)) + 20., (size.y / (idx as f32 * (WITDH + 20.))).floor() * HEIGHT + 30.));
                        ui.set_width(WITDH);
                });
            }
        } else {
            egui::Window::new("Credentials").show(ctx, |ui| {
                ui.label("Address");
                ui.text_edit_singleline(addr);
                ui.label("User");
                ui.text_edit_singleline(user);
                ui.label("Pass");
                pass2.show(ui);
                if ui.button("Login").clicked() {
                    self.state = StateScreen::Logged;
                }
            });
        }
   }
}

pub struct Data(pub AllData);

impl Deref for Data {
    type Target = AllData;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Data {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct Cred {
    pub addr: String,
    pub user: String,
    pub pass: String
}

#[derive(Default, Clone)]
pub struct Config {
    pub color: bool,
    pub size: Vec2
}

#[derive(Debug, Default, Hash, Eq, PartialEq, Clone, Copy)]
pub enum StateScreen {
    #[default]
    Login,
    Logged
}

fn login2(cred: &Cred) -> (Ami, Data) {
    let ami = AmiConnect::new(cred.user.clone(), cred.pass.clone(), cred.addr.parse().unwrap(), 5038);
    let mut ami = Ami::new(ami).unwrap();
    let (send, recv) = mpsc::channel();
    let map = Data(Arc::new(Mutex::new(BTreeMap::new())));
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

                // send.send(Message::Updated).unwrap()
            },
            _ => ()
        }
    }).unwrap();

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

    (ami, map)
}

#[cfg(target_arch = "wasm32")]
fn login3(cred: &Cred) -> Data {
    let ws = WebSocket::new("ws://127.0.0.1:61338").unwrap();
    let cloned_ws = ws.clone();
    let map = Data(Arc::new(Mutex::new(BTreeMap::new())));
    let sync_map = Arc::clone(&map);
    let cred = cred.clone();
    ws.set_binary_type(BinaryType::Arraybuffer);

    let cb = Closure::<dyn FnMut(_)>::new(move |e: MessageEvent| {
        console_log!("Recv: {}", &e.data().as_string().unwrap());
        *sync_map.lock().unwrap() = serde_json::from_str(&e.data().as_string().unwrap()).unwrap()
    });

    let init = Closure::<dyn FnMut()>::new(move || {
        console_log!("init");
        console_log!("{:?}", cloned_ws.send_with_str(&serde_json::to_string(&cred).unwrap()));
    });

    ws.set_onmessage(Some(cb.as_ref().unchecked_ref()));
    ws.set_onopen(Some(init.as_ref().unchecked_ref()));
    cb.forget();
    init.forget();

    map
}