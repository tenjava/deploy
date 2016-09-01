#![feature(custom_derive, plugin)]
#![plugin(serde_macros)]

#[macro_use] extern crate hyper;
extern crate crypto;
extern crate pencil;
extern crate serde;
extern crate serde_json;

use crypto::hmac::Hmac;
use crypto::mac::{Mac, MacResult};
use crypto::sha1::Sha1;
use pencil::Request;
use std::io::Read;

header! { (XGitHubEvent, "X-GitHub-Event") => [String] }
header! { (XGitHubDelivery, "X-GitHub-Delivery") => [String] }
header! { (XHubSignature, "X-Hub-Signature") => [String] }

pub type DeployResult<T> = Result<T, String>;

pub enum Branch {
  Master,
  Dev
}

pub fn get_request_bytes(request: &mut Request) -> DeployResult<Vec<u8>> {
  let mut bytes: Vec<u8> = Vec::new();
  match request.read_to_end(&mut bytes) {
    Ok(_) => Ok(bytes),
    Err(e) => Err(format!("could not read request: {}", e))
  }
}

#[derive(Deserialize)]
struct DeployRequest {
  #[serde(rename = "ref")]
  ref_key: String
}

pub fn get_branch(bytes: Vec<u8>) -> DeployResult<Branch> {
  let json_string = match String::from_utf8(bytes) {
    Ok(x) => x,
    Err(e) => return Err(format!("could not convert request to string: {}", e))
  };
  let request: DeployRequest = match serde_json::from_str(&json_string) {
    Ok(x) => x,
    Err(e) => return Err(format!("could not process json from request: {}", e))
  };
  let branch = match request.ref_key.split('/').last() {
    Some(x) => x,
    None => return Err("invalid 'ref' key".into())
  };
  match branch {
    "master" => Ok(Branch::Master),
    "dev" => Ok(Branch::Dev),
    _ => Err("invalid branch".into())
  }
}

pub fn check_signature(bytes: &[u8], signature: &XHubSignature, secret: &str) -> DeployResult<bool> {
  let (method, hash) = {
    let mut split = signature.split('=');
    let method = match split.next() {
      Some(x) => x,
      None => return Err("invalid signature".into())
    };
    let hash = match split.next() {
      Some(x) => x,
      None => return Err("invalid signature".into())
    };
    (method, hash)
  };
  if method != "sha1" {
    return Err("invalid signature method (non-sha1)".into());
  }
  let hash = try!(hex_string_to_bytes(hash));
  let result = build_sha1_hmac(secret, bytes).result();
  let check_against = MacResult::new(&hash);
  Ok(result == check_against)
}

fn build_sha1_hmac(secret: &str, input: &[u8]) -> Hmac<Sha1> {
  let mut hmac = Hmac::new(Sha1::new(), secret.as_bytes());
  hmac.input(input);
  hmac
}

pub fn hex_string_to_bytes(hex_string: &str) -> DeployResult<Vec<u8>> {
  let char_vec = hex_string.chars().collect::<Vec<_>>();
  let chunks = char_vec.chunks(2);
  let parsed: Vec<_> = chunks
    .map(|x| u8::from_str_radix(
        x.into_iter().cloned().collect::<String>().as_str(),
        16
      )
    )
    .collect();
  if parsed.iter().any(|x| x.is_err()) {
    return Err("could not parse hex string".into());
  }
  Ok(parsed.into_iter().flat_map(|x| x).collect())
}
