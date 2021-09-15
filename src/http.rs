// Copyright (c) 2021 Patrick Amrein <amrein@ubique.ch>
//
// This software is released under the MIT License.
// https://opensource.org/licenses/MIT

use std::{collections::HashMap, fmt::Display, ops::Deref, sync::Arc};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufStream},
    net::TcpStream,
};
use tokio_rustls::{
    rustls::{ClientConfig, KeyLogFile},
    webpki::DNSNameRef,
    TlsConnector,
};
use url::Url;



pub struct Client {
    connector: TlsConnector,
}

#[derive(Debug)]
pub struct Body {
    data: Vec<u8>,
}

impl From<Vec<u8>> for Body {
    fn from(data: Vec<u8>) -> Body {
        Body { data }
    }
}

impl From<&[u8]> for Body {
    fn from(data: &[u8]) -> Body {
        Body {
            data: data.to_vec(),
        }
    }
}

impl From<String> for Body {
    fn from(data: String) -> Body {
        Body {
            data: data.into_bytes(),
        }
    }
}

impl From<&str> for Body {
    fn from(data: &str) -> Body {
        Body {
            data: data.as_bytes().to_vec(),
        }
    }
}

pub enum HttpMethod {
    Get,
    Post,
    Delete,
    Put,
    Patch,
}

impl Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpMethod::Get => f.write_str("GET"),
            HttpMethod::Post => f.write_str("POST"),
            HttpMethod::Delete => f.write_str("DELETE"),
            HttpMethod::Put => f.write_str("PUT"),
            HttpMethod::Patch => f.write_str("PATCH"),
        }
    }
}

use std::net::ToSocketAddrs;

pub struct Request<T>
where
    T: Into<Body>,
{
    url: url::Url,
    method: HttpMethod,
    headers: HashMap<String, String>,
    body: T,
}

#[derive(Debug)]
pub struct Response {
    pub status: Status,
    pub headers: HashMap<String, String>,
    pub body: Body,
}

impl Response {
    pub fn is_ok(&self) -> bool {
        if self.status.status_code < 400 {
            true
        } else {
            false
        }
    }
}

#[derive(Debug)]
pub struct Status {
    status_code: u32,
    status_message: String,
}

impl Client {
    pub fn new() -> Self {
        let mut config = ClientConfig::new();
        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        let log_file = KeyLogFile::new();
        config.key_log = Arc::new(log_file);

        let connector = TlsConnector::from(Arc::new(config));
        Self { connector }
    }

    pub async fn send<T>(
        &mut self,
        request: Request<T>,
    ) -> Result<Response, Box<dyn std::error::Error>>
    where
        T: Into<Body>,
    {
        let uri = request.url.host().unwrap().to_string();
        let stream_bytes: Vec<u8> = request.into();
        let addr = (uri.as_str(), 443)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
        let domain = uri;

        let stream = TcpStream::connect(&addr).await?;
        let domain = DNSNameRef::try_from_ascii_str(&domain).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid dnsname")
        })?;
        let mut stream = self.connector.connect(domain, stream).await?;
        stream.write_all(&stream_bytes).await?;


        let mut response = vec![];
        let mut reader = BufStream::new(stream);
        let mut headers = HashMap::new();
        let mut status_line = String::new();
        reader.read_line(&mut status_line).await?;

        let mut parts = status_line.split_ascii_whitespace();
        let _ = parts.next().unwrap();
        let status_code = parts.next().unwrap().trim().parse()?;
        let status_message = parts.next().unwrap().to_string();
        //try read headers
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await?;
            if let Some((header, value)) = line.split_once(":") {
                headers.insert(header.to_ascii_lowercase().to_string(), value.trim().to_string());
            } else {
                let content_length: usize = headers.get("content-length").unwrap().parse().unwrap();
                let mut buffer = vec![0; content_length];
                match reader.read_exact(&mut buffer).await {
                    Ok(len) => {
                        response.extend_from_slice(&buffer[..len]);
                        break;
                    }
                    Err(_) => break,
                }
            }
        }

        Ok(
            Response {
                status: Status { status_code, status_message },
                headers,
                body: response.into(),
            }
        )
    }
}

impl<T> Into<Vec<u8>> for Request<T>
where
    T: Into<Body>,
{
    fn into(self) -> Vec<u8> {
        let query = if let Some(query) = self.url.query() {
            format!("?{}", query)
        } else {
            String::new()
        };
        let path = format!("{}{}", self.url.path(), query);
        let method: String = self.method.to_string();
        let http_version = "HTTP/1.1";
        let mut header_string = format!("{} {} {}\r\n", method, path, http_version);
        header_string.push_str(&format!("Host: {}\r\n", self.url.host_str().unwrap()));
        header_string.push_str("User-Agent: dns-util\r\n");
        let body: Body = self.body.into();
        for (header, value) in self.headers {
            header_string.push_str(&format!("{}: {}\r\n", header, value));
        }
        header_string.push_str("Connection: close\r\n");
        header_string.push_str(&format!("Content-Length: {}\r\n", body.data.len()));
        header_string.push_str("\r\n");

        println!("{}", header_string);
        let mut request_bytes = header_string.into_bytes();

        request_bytes.extend(&body.data);
        request_bytes
    }
}

impl<T> Request<T>
where
    T: Into<Body>,
{
    pub fn new(
        url: Url,
        method: HttpMethod,
        headers: HashMap<String, String>,
        body: T,
    ) -> Request<T> {
        Request {
            url,
            method,
            headers,
            body,
        }
    }
}

impl Deref for Body {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl AsRef<[u8]> for Body {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

#[cfg(test)]
mod test {
    use std::io::Cursor;

    use tokio::runtime::Builder;

    use crate::{DnsPacket, FromBytes, RecordType};

    use super::*;
    #[test]
    fn test_request() {
        std::env::set_var("SSLKEYLOGFILE", "./keylog_file");
        let mut client = Client::new();
        let dns_package = base64::encode_config(
            &DnsPacket::builder()
                .add_query("www.amazon.com", RecordType::A(0))
                .build()
                .to_vec()
                .expect("Invalid DNS"),
            base64::URL_SAFE_NO_PAD,
        );
        let request = Request::new(
            format!("https://dns.google/dns-query?dns={}", dns_package)
                .parse::<url::Url>()
                .unwrap(),
            HttpMethod::Get,
            HashMap::new(),
            vec![],
        );
        let rt = Builder::new_multi_thread().enable_io().build().unwrap();
        rt.block_on(async {
            println!("try sending");
            let response = client.send(request).await.unwrap();
            println!("{:?}", response);
            let mut bytes = Cursor::new(&response.body);
            let package = DnsPacket::read(&mut bytes).unwrap();
            println!("{:?}", package);
        });
    }
}
