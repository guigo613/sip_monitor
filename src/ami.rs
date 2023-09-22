use std::{
    thread,
    time::Duration,
    io::{
        self,
        Result as IoResult,
        BufReader,
        prelude::*,
    },
    net::{
        TcpStream,
        SocketAddrV4,
        Ipv4Addr
    },
};

pub struct Ami {
    tcp: TcpStream,
    // treat: Option<FuncTreat>
}

impl Ami {
    pub fn new(connect: AmiConnect) -> IoResult<Self> {
        let tcp = connect.login()?;

        Ok(Self {
            tcp,
            // treat: None
        })
    }

    pub fn pjsip_show_aors(&mut self) -> IoResult<()> {
        println!("Executando comando: PJSIP_ShowAors");

        self.tcp.write(b"Action: PJSIPShowAors\r\n\r\n")?;
        self.tcp.flush()?;

        Ok(())
    }

    pub fn pjsip_show_contacts(&mut self) -> IoResult<()> {
        println!("Executando comando: PJSIP_ShowContacts");

        self.tcp.write(b"Action: PJSIPShowContacts\r\n\r\n")?;
        self.tcp.flush()?;

        Ok(())
    }

    pub fn extension_state(&mut self, sip: &str, ctx: &str) -> IoResult<()> {
        println!("Executando comando: ExtensionState");

        self.tcp.write(format!("Action: ExtensionState\nExten: {sip}\nContext: {ctx}\n\n").as_bytes())?;
        self.tcp.flush()?;

        Ok(())
    }

    pub fn init_treat<F>(&self, func: F) -> IoResult<()>
        where F: Fn(String) + Send + Sized + 'static
    {
        let tcp = self.tcp.try_clone()?;
        thread::spawn(move || {
            let mut read = BufReader::new(&tcp);

            loop {
                let value = AmiConnect::read(&mut read);

                if value.is_empty() {
                    println!("Disconnect?");
                }
                
                func(value);
            }
        });

        Ok(())
    }
}

pub struct AmiConnect {
    user: String,
    pass: String,
    address: Ipv4Addr,
    port: u16,
}

impl AmiConnect {
    pub fn new(user: String, pass: String, address: Ipv4Addr, port: u16) -> Self {
        Self { user, pass, address, port }
    }

    fn connect(&self) -> IoResult<TcpStream> {
        let stream = TcpStream::connect(SocketAddrV4::new(self.address, self.port))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;

        Ok(stream)
    }

    fn login(&self) -> IoResult<TcpStream> {
        let mut stream = self.connect()?;
        stream.write(format!("Action: Login\r\nUsername: {}\r\nSecret: {}\r\nActionID: 1\r\n\r\n", self.user, self.pass).as_bytes())?;
        stream.flush()?;

        let read: String = Self::read(&mut BufReader::new(&mut stream));

        if read.contains("Message: Authentication accepted") {
            println!("Autenticação realizada com sucesso!");

            Ok(stream)
        } else {
            Err(io::Error::from(io::ErrorKind::ConnectionRefused))
        }
    }
    
    fn read(stream: &mut impl BufRead) -> String {
        let mut buffer = String::new();
        
        while let Ok(size) = stream.read_line(&mut buffer) {
            if size <= 2 {
                break
            }
        }

        buffer.trim().to_owned()
    }
}