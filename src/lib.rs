pub mod http;
pub fn dns_query_over_tls(client: &mut Client, dns_package: DnsPacket) -> Result<DnsPacket, Box<dyn std::error::Error>> {
    // let mut client = Client::new();
    let dns_request =
        DnsRequest::new_with_host("cloudflare-dns.com", "1.1.1.1:853".to_string(), dns_package);
     let rt = tokio::runtime::Runtime::new()?;
     rt.block_on(async {
         client.send_dot(dns_request).await
     })
}
pub fn dns_query(dns_package: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let mut client = Client::new();
        let mut headers = HashMap::new();
        headers.insert("accept".to_string(), "application/dns-message".to_string());
        headers.insert(
            "content-type".to_string(),
            "application/dns-message".to_string(),
        );
        let request = Request::new_with_host(
            "dns.google",
            format!(
                "{}?dns={}",
                "https://8.8.8.8/dns-query",
                base64::encode_config(dns_package, base64::URL_SAFE_NO_PAD)
            )
            .parse()
            .unwrap(),
            HttpMethod::Get,
            headers,
            vec![],
        );
        let response = client.send(request).await.unwrap();
        // println!("{:?}", response.status);
        let dns_response = response.body;

        let bytes: Vec<u8> = (&dns_response).to_vec();
        Ok(bytes)
    })
}

#[derive(Clone)]
pub struct LabelString(Vec<Label>, bool);

pub trait FromBytes {
    type Deserialized;
    fn read<R>(bytes: &mut R) -> Result<Self::Deserialized, Box<dyn std::error::Error>>
    where
        R: Read + Seek;
}

pub trait ToBytes {
    fn write<W>(&self, bytes: &mut W) -> Result<(), Box<dyn std::error::Error>>
    where
        W: std::io::Write;
}

#[derive(Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub queries: Vec<Query>,
    pub answers: Vec<Answer>,
    pub authorities: Vec<Answer>,
    pub additional_options: Vec<Answer>,
}

pub struct DnsPacketBuilder(DnsPacket);

impl DnsPacket {
    pub fn get_transaction_id(&self) -> u16 {
        self.header.transaction_id
    }
    pub fn builder() -> DnsPacketBuilder {
        let transaction_id: u16 = rand::random();
        DnsPacketBuilder(DnsPacket {
            header: DnsHeader {
                transaction_id,
                flags: 256,
                number_of_questions: 0,
                number_of_answers: 0,
                number_of_authorities: 0,
                number_of_additional: 0,
            },
            queries: vec![],
            answers: vec![],
            authorities: vec![],
            additional_options: vec![],
        })
    }

    pub fn to_vec(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut bytes = Cursor::new(vec![]);
        self.write(&mut bytes)?;
        Ok(bytes.into_inner())
    }
}

impl DnsPacketBuilder {
    pub fn add_query(mut self, domain_name: &str, ty: RecordType) -> Self {
        let name_parts = domain_name.split(".");
        let mut labels = LabelString::new();
        for name in name_parts {
            let name_bytes = name.as_bytes();
            let number_of_bytes = name_bytes.len();
            let label = Label {
                length_type: number_of_bytes as usize,
                data: name_bytes.to_vec(),
                is_end: false,
                ptr_bytes: None,
            };
            labels.0.push(label);
        }
        labels.0.push(Label {
            length_type: 0,
            data: vec![],
            is_end: true,
            ptr_bytes: None,
        });
        let query = Query {
            name: labels,
            ty: ty.to_short(),
            class: 1,
        };
        self.0.queries.push(query);
        self
    }

    pub fn build(mut self) -> DnsPacket {
        self.0.header.number_of_questions = self.0.queries.len() as u16;
        self.0.header.number_of_answers = self.0.answers.len() as u16;
        self.0.header.number_of_authorities = self.0.authorities.len() as u16;
        self.0.header.number_of_additional = self.0.additional_options.len() as u16;
        self.0
    }
}

impl std::fmt::Debug for LabelString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("LabelString")
            .field(&self.to_string())
            .finish()
    }
}

impl std::fmt::Debug for Answer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Answer")
            .field("name", &self.name)
            .field("ty", &self.ty)
            .field("class", &self.class)
            .field("ttl", &self.ttl)
            .field("rd_length", &self.rd_length)
            .field("data", &self.data)
            .field("parsed_data", &String::from_utf8_lossy(&self.parsed_data))
            .finish()
    }
}

impl ToBytes for DnsPacket {
    fn write<W>(&self, bytes: &mut W) -> Result<(), Box<dyn std::error::Error>>
    where
        W: std::io::Write,
    {
        let start = std::time::Instant::now();
        self.header.write(bytes)?;
        for i in 0..self.header.number_of_questions {
            let q = &self.queries[i as usize];
            q.write(bytes)?;
        }
        for i in 0..self.header.number_of_answers {
            let a = &self.answers[i as usize];
            a.write(bytes)?;
        }
        for i in 0..self.header.number_of_authorities {
            let a = &self.authorities[i as usize];
            a.write(bytes)?;
        }
        for i in 0..self.header.number_of_additional {
            let a = &self.additional_options[i as usize];
            a.write(bytes)?;
        }
        let end = std::time::Instant::now();
        // println!("Writing took {}µs", (end-start).as_micros());
        Ok(())
    }
}

impl FromBytes for DnsPacket {
    type Deserialized = DnsPacket;

    fn read<R>(bytes: &mut R) -> Result<Self::Deserialized, Box<dyn std::error::Error>>
    where
        R: Read + Seek,
    {
        let start = std::time::Instant::now();
        let header = DnsHeader::read(bytes)?;
        let mut queries = vec![];
        let mut answers = vec![];
        let mut authorities = vec![];
        let mut additional_options = vec![];

        for _ in 0..header.number_of_questions {
            let q = Query::read(bytes)?;
            queries.push(q);
        }
        for _ in 0..(header.number_of_answers) {
            let a = Answer::read(bytes)?;
            answers.push(a);
        }

        for _ in 0..header.number_of_authorities {
            let a = Answer::read(bytes)?;
            authorities.push(a);
        }
        for _ in 0..header.number_of_additional {
            let a = Answer::read(bytes)?;
            additional_options.push(a);
        }
        let end = std::time::Instant::now();
        // println!("Parsing took {}µs", (end-start).as_micros());
        Ok(Self {
            header,
            queries,
            answers,
            authorities,
            additional_options,
        })
    }
}

#[derive(Debug)]
pub struct Query {
    pub name: LabelString,
    pub ty: u16,
    class: u16,
}

impl FromBytes for u8 {
    type Deserialized = u8;

    fn read<R>(bytes: &mut R) -> Result<Self::Deserialized, Box<dyn std::error::Error>>
    where
        R: Read + Seek,
    {
        let mut b = [0; 1];
        bytes.read_exact(&mut b)?;
        Ok(b[0])
    }
}

impl FromBytes for u16 {
    type Deserialized = u16;

    fn read<R>(bytes: &mut R) -> Result<Self::Deserialized, Box<dyn std::error::Error>>
    where
        R: Read + Seek,
    {
        let mut b = [0; 2];
        bytes.read_exact(&mut b)?;
        Ok(u16::from_be_bytes(b))
    }
}

impl FromBytes for u32 {
    type Deserialized = u32;

    fn read<R>(bytes: &mut R) -> Result<Self::Deserialized, Box<dyn std::error::Error>>
    where
        R: Read + Seek,
    {
        let mut b = [0; 4];
        bytes.read_exact(&mut b)?;
        Ok(u32::from_be_bytes(b))
    }
}

impl FromBytes for Query {
    type Deserialized = Query;

    fn read<R>(bytes: &mut R) -> Result<Self::Deserialized, Box<dyn std::error::Error>>
    where
        R: Read + Seek,
    {
        let name = LabelString::read(bytes)?;
        let ty = u16::read(bytes)?;
        let class = u16::read(bytes)?;
        Ok(Self { name, ty, class })
    }
}

impl ToBytes for Query {
    fn write<W>(&self, bytes: &mut W) -> Result<(), Box<dyn std::error::Error>>
    where
        W: std::io::Write,
    {
        self.name.write(bytes);
        // bytes.write_all(&[0x00])?;
        bytes.write_all(&self.ty.to_be_bytes())?;
        bytes.write_all(&self.class.to_be_bytes())?;
        Ok(())
    }
}

pub struct Answer {
    pub name: LabelString,
    ty: u16,
    pub class: u16,
    pub ttl: u32,
    rd_length: u16,
    data: Vec<u8>,
    pub parsed_data: Vec<u8>,
}

impl Answer {
    pub fn new(ip_addr: Ipv4Addr, name: LabelString) -> Answer {
        Answer {
            name,
            ty: 1,
            class: 1,
            ttl: 500,
            rd_length: 4,
            data: ip_addr.octets().to_vec(),
            parsed_data: vec![],
        }
    }
}

impl FromBytes for Answer {
    type Deserialized = Answer;

    fn read<R>(bytes: &mut R) -> Result<Self::Deserialized, Box<dyn std::error::Error>>
    where
        R: Read + Seek,
    {
        let name = LabelString::read(bytes)?;
        let ty = u16::read(bytes)?;
        let class = u16::read(bytes)?;
        let ttl = u32::read(bytes)?;
        let rd_length = u16::read(bytes)?;
        let mut data = vec![0; rd_length as usize];

        let mut parsed_data = vec![0; rd_length as usize];
        bytes.read_exact(&mut data)?;
        let mut data = Cursor::new(data);
        // if it is a CNAME parse string instead
        if ty == 5 || ty == 2 {
            let pos = bytes.stream_position()?;
            bytes.seek(SeekFrom::Current(-(rd_length as i64)))?;
            let label_string = LabelString::read(bytes)?;
            parsed_data = label_string.get_string().as_bytes().to_vec();
            bytes.seek(SeekFrom::Start(pos))?;
        } else if ty == 16 {
            let mut pos = 0 as usize;
            let mut number_of_txt_parts = 0 as usize;
            while pos < rd_length as usize {
                let length = u8::read(&mut data)? as usize;
                let mut txt_buffer = vec![0; length];
                data.read_exact(&mut txt_buffer)?;
                parsed_data[pos..(pos + length)].copy_from_slice(&txt_buffer);
                number_of_txt_parts += 1;
                pos += length + 1;
            }
            parsed_data = (&parsed_data[..parsed_data.len() - number_of_txt_parts]).to_vec();
        } else if ty == 15 {
            let preference = u16::read(&mut data)?;
            let label_string = LabelString::read(&mut data)?;
            parsed_data = format!("{} {}", preference, label_string)
                .as_bytes()
                .to_vec();
        }

        Ok(Self {
            name,
            ty,
            class,
            ttl,
            rd_length,
            data: data.into_inner(),
            parsed_data,
        })
    }
}

impl ToBytes for Answer {
    fn write<W>(&self, bytes: &mut W) -> Result<(), Box<dyn std::error::Error>>
    where
        W: std::io::Write,
    {
        self.name.write(bytes)?;
        if !self.name.1 && self.name.to_string() != "" {
            if let Some(last) = self.name.0.last() {
                if last.length_type != 0 {
                    bytes.write_all(&[0x00])?;
                }
            }
        }
        bytes.write_all(&self.ty.to_be_bytes())?;
        bytes.write_all(&self.class.to_be_bytes())?;
        bytes.write_all(&self.ttl.to_be_bytes())?;
        bytes.write_all(&self.rd_length.to_be_bytes())?;
        bytes.write_all(&self.data)?;
        Ok(())
    }
}

impl Query {}
use std::collections::{BTreeSet, HashMap};
use std::fmt::Display;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::net::Ipv4Addr;

use http::DnsRequest;

use crate::http::{Client, HttpMethod, Request};

impl Answer {
    pub fn get_record_type(&self) -> Result<RecordType, Box<dyn std::error::Error>> {
        match self.ty {
            1 => {
                if self.data.len() != 4 {
                    return Err("A record should have 4 bytes".into());
                }
                let mut ip_address = [0; 4];
                Cursor::new(&self.data).read_exact(&mut ip_address)?;
                let ip_address = u32::from_be_bytes(ip_address);
                Ok(RecordType::A(ip_address))
            }
            28 => {
                if self.data.len() != 16 {
                    return Err("AAAA record should have 16 bytes".into());
                }
                let mut ip_address = [0; 16];
                Cursor::new(&self.data).read_exact(&mut ip_address)?;
                let ip_address = u128::from_be_bytes(ip_address);
                Ok(RecordType::AAAA(ip_address))
            }
            5 => Ok(RecordType::CNAME(
                String::from_utf8(self.parsed_data.clone()).unwrap(),
            )),
            15 => Ok(RecordType::MX(
                String::from_utf8(self.parsed_data.clone()).unwrap(),
            )),
            2 => Ok(RecordType::NS(
                String::from_utf8(self.parsed_data.clone()).unwrap(),
            )),
            6 => Ok(RecordType::SOA(self.data.clone())),
            16 => Ok(RecordType::TXT(String::from_utf8(
                self.parsed_data.clone(),
            )?)),
            _ => Err("not implemented".into()),
        }
    }
}

impl FromBytes for LabelString {
    type Deserialized = LabelString;

    fn read<R>(bytes: &mut R) -> Result<Self::Deserialized, Box<dyn std::error::Error>>
    where
        R: Read + Seek,
    {
        let mut labels = LabelString::new();
        loop {
            let label: Label = Label::read(bytes)?;
            let len = label.length_type;
            labels.0.push(label.clone());
            if label.ptr_bytes.is_some() {
                labels.1 = true;
            }
            if label.is_end {
                break;
            }
            match label.get_type() {
                Ok(LabelType::End) => break,
                Ok(LabelType::Label) if len == 0 => break,
                _ => continue,
            }
        }
        Ok(labels)
    }
}
impl ToBytes for LabelString {
    fn write<W>(&self, bytes: &mut W) -> Result<(), Box<dyn std::error::Error>>
    where
        W: std::io::Write,
    {
        for k in &self.0 {
            k.write(bytes)?;
        }
        // bytes.write_all(&[0u8])?;
        Ok(())
    }
}

impl LabelString {
    pub fn new() -> Self {
        Self(Vec::new(), false)
    }
    pub fn get_string(&self) -> String {
        let mut text = "".to_string();
        for val in &self.0 {
            match val.get_type() {
                Ok(LabelType::Label | LabelType::End) => {
                    text.push_str(&val.get_label().unwrap_or("".to_string()))
                }
                Ok(LabelType::Pointer) => unreachable!("We resolved the pointer beforehand"),
                Err(_) => continue,
            }
            text.push_str(".");
        }
        let _ = text.pop();
        text
    }
}

impl Display for LabelString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.get_string())
    }
}

impl FromBytes for Label {
    type Deserialized = Label;

    fn read<R>(bytes: &mut R) -> Result<Self::Deserialized, Box<dyn std::error::Error>>
    where
        R: Read + Seek,
    {
        let mut first = [0u8];
        bytes.read_exact(&mut first)?;
        Ok(
            if (((first[0] as u16) << 8) & (0b1100_0000u16 << 8)) >> 14 == 0b11 {
                let mut second = [0u8];
                bytes.read_exact(&mut second)?;
                let normalized_first =
                    (((first[0] as u16) << 8u16) & (0b0011_1111u16 << 8) >> 8) as u8;
                let ptr: u16 = u16::from_be_bytes([normalized_first, second[0]]);

                let pos = bytes.stream_position()?;
                bytes.seek(SeekFrom::Start(ptr as u64))?;
                let label_string = LabelString::read(bytes)?;

                let label_string = label_string.get_string();

                let label = Label {
                    length_type: label_string.len() as usize,
                    data: label_string.as_bytes().to_vec(),
                    is_end: true,
                    ptr_bytes: Some([first[0], second[0]]),
                };
                bytes.seek(SeekFrom::Start(pos as u64))?;
                label
            } else {
                let length = (first[0] & 0b0011_1111) as usize;
                let mut buf = vec![0; length];
                bytes.read_exact(&mut buf)?;

                Label {
                    length_type: first[0] as usize,
                    data: buf,
                    is_end: false,
                    ptr_bytes: None,
                }
            },
        )
    }
}

impl ToBytes for Label {
    fn write<W>(&self, bytes: &mut W) -> Result<(), Box<dyn std::error::Error>>
    where
        W: std::io::Write,
    {
        if let Some(ptr_data) = self.ptr_bytes {
            bytes.write_all(&ptr_data)?;
        } else {
            bytes.write_all(&[self.length_type as u8])?;
            bytes.write_all(&self.data)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum RecordType {
    A(u32),
    AAAA(u128),
    CNAME(String),
    MX(String),
    NS(String),
    TXT(String),
    SOA(Vec<u8>),
    ANY,
}

impl RecordType {
    pub fn to_short(&self) -> u16 {
        match self {
            RecordType::A(_) => 1,
            RecordType::AAAA(_) => 28,
            RecordType::CNAME(_) => 5,
            RecordType::MX(_) => 15,
            RecordType::NS(_) => 2,
            RecordType::TXT(_) => 16,
            RecordType::SOA(_) => 61,
            RecordType::ANY => 255,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Label {
    length_type: usize,
    data: Vec<u8>,
    is_end: bool,
    ptr_bytes: Option<[u8; 2]>,
}

impl Display for Label {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let data = String::from_utf8(self.data.clone()).unwrap();
        f.write_str(&data)
    }
}

impl Label {
    pub fn get_label(&self) -> Option<String> {
        match self.get_type() {
            Ok(LabelType::Label | LabelType::End) => String::from_utf8(self.data.clone()).ok(),
            Ok(LabelType::Pointer) | Err(_) => None,
        }
    }

    pub fn get_type(&self) -> Result<LabelType, Box<dyn std::error::Error>> {
        match (self.length_type & 0b1100_0000) >> 6 {
            _ if self.is_end => Ok(LabelType::Label),
            0b00 => Ok(LabelType::Label),
            0b11 => Ok(LabelType::Pointer),
            _ => Err(format!(
                "Label can only have two types {:b}",
                (self.length_type & 0b1100_0000) >> 6
            )
            .into()),
        }
    }
}

#[derive(Debug)]
pub enum LabelType {
    Label,
    Pointer,
    End,
}

#[derive(Debug)]
pub struct DnsHeader {
    transaction_id: u16,
    flags: u16,
    pub number_of_questions: u16,
    pub number_of_answers: u16,
    pub number_of_authorities: u16,
    pub number_of_additional: u16,
}

impl ToBytes for DnsHeader {
    fn write<W>(&self, bytes: &mut W) -> Result<(), Box<dyn std::error::Error>>
    where
        W: std::io::Write,
    {
        bytes.write_all(&self.transaction_id.to_be_bytes())?;
        bytes.write_all(&self.flags.to_be_bytes())?;
        bytes.write_all(&self.number_of_questions.to_be_bytes())?;
        bytes.write_all(&self.number_of_answers.to_be_bytes())?;
        bytes.write_all(&self.number_of_authorities.to_be_bytes())?;
        bytes.write_all(&self.number_of_additional.to_be_bytes())?;

        Ok(())
    }
}

impl FromBytes for DnsHeader {
    type Deserialized = DnsHeader;

    fn read<R>(bytes: &mut R) -> Result<Self::Deserialized, Box<dyn std::error::Error>>
    where
        R: Read + Seek,
    {
        let transaction_id = u16::read(bytes)?;
        let flags = u16::read(bytes)?;
        let number_of_questions = u16::read(bytes)?;
        let number_of_answers = u16::read(bytes)?;
        let number_of_authorities = u16::read(bytes)?;
        let number_of_additional = u16::read(bytes)?;
        Ok(Self {
            transaction_id,
            flags,
            number_of_questions,
            number_of_answers,
            number_of_authorities,
            number_of_additional,
        })
    }
}

impl DnsHeader {
    pub fn set_message_type(&mut self, ty: MessageType) {
        match ty {
            MessageType::Query => self.flags &= 0b0111_1111_1111_1111,
            MessageType::Response => self.flags |= 0b1000_0000_0000_0000,
        }
    }
    pub fn get_message_type(&self) -> MessageType {
        match (self.flags & 0b1000_0000_0000_0000) >> 15 {
            0 => MessageType::Query,
            1 => MessageType::Response,
            _ => unreachable!("A bit can only take two values"),
        }
    }
    pub fn get_opcode(&self) -> Opcode {
        match (self.flags & 0b0111_1000_0000_0000) >> 11 {
            0 => Opcode::Query,
            1 => Opcode::IQuery,
            2 => Opcode::Status,
            3 => Opcode::Reserved,
            4 => Opcode::Notify,
            5 => Opcode::Update,
            _ => unreachable!("Opcode not defined"),
        }
    }

    pub fn get_rcode(&self) -> RCode {
        match self.flags & 0b0000_0000_0000_1111 {
            0 => RCode::NoError,
            1 => RCode::FormatError,
            2 => RCode::ServerFailure,
            3 => RCode::NameError,
            4 => RCode::NotImplemented,
            5 => RCode::Refused,
            6 => RCode::YXDomain,
            7 => RCode::YXRRSet,
            8 => RCode::NXRRSet,
            9 => RCode::NotAuth,
            10 => RCode::NotZone,
            _ => unreachable!("Opcode not defined"),
        }
    }
}

#[derive(Debug)]
pub enum MessageType {
    Query,
    Response,
}

#[derive(Debug)]
pub enum Opcode {
    Query,
    IQuery,
    Status,
    Reserved,
    Notify,
    Update,
}
#[derive(Debug)]
pub enum RCode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
    YXDomain,
    YXRRSet,
    NXRRSet,
    NotAuth,
    NotZone,
}
