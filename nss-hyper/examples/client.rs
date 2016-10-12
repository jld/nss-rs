/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

extern crate nss_hyper;
extern crate hyper;

use nss_hyper::NssClient;
use hyper::client::Client;
use hyper::net::HttpsConnector;

use std::env::args;
use std::error::Error;
use std::io::{Read, Write, stdout, stderr};
use std::process::exit;

fn main() {
    let client = Client::with_connector(HttpsConnector::new(NssClient::new()));
    let urls: Vec<_> = args().skip(1).collect();
    if urls.len() == 0 || urls.iter().any(|u| u == "--help") {
        let me = args().next().unwrap_or_else(|| "client".to_owned());
        writeln!(stderr(), "Usage: {} <URLs>", me).unwrap();
        writeln!(stderr(), "Sends a GET for each of the URLs and prints the responses.").unwrap();
        return;
    }
    for url in urls {
        match client.get(&url).send() {
            Ok(mut resp) => {
                let mut body = Vec::new();
                resp.read_to_end(&mut body).unwrap();
                stdout().write_all(&body).unwrap();
            }
            Err(err) => {
                writeln!(stderr(), "Error retrieving {}: {}", url, err.description()).unwrap();
                exit(1)
            }
        }
    }
}
