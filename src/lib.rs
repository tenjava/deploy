extern crate pencil;
#[macro_use] extern crate hyper;
extern crate crypto;

use std::io::Read;
use crypto::hmac::Hmac;
use crypto::sha2::Sha256;
use crypto::mac::{Mac, MacResult};
use hyper::header::Headers;
use pencil::Request;

header! { (XGitHubEvent, "X-GitHub-Event") => [String] }
header! { (XGitHubDelivery, "X-GitHub-Delivery") => [String] }
header! { (XHubSignature, "X-Hub-Signature") => [String] }

pub fn check_signature(request: &mut Request, signature: &XHubSignature, secret: &str) -> bool {
  let mut bytes: Vec<u8> = Vec::new();
  request.read_to_end(&mut bytes);
  let mut hmac = Hmac::new(Sha256::new(), secret.as_bytes());
  hmac.input(&bytes);
  let result = hmac.result();
  let check_against = MacResult::new(signature.as_bytes());
  result == check_against
}
