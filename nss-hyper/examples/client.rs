extern crate nss_hyper;
extern crate hyper;

use nss_hyper::NssClient;
use hyper::client::Client;
use hyper::net::HttpsConnector;

use std::io::{Read, Write, stdout};

fn main() {
    let client = Client::with_connector(HttpsConnector::new(NssClient::new()));
    let mut resp = client.get("https://www.rfc-editor.org/").send().unwrap();
    let mut body = Vec::new();
    resp.read_to_end(&mut body).unwrap();
    stdout().write_all(&body).unwrap();
}
