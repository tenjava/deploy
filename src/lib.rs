extern crate pencil;
#[macro_use] extern crate hyper;
extern crate crypto;

use std::io::Read;
use crypto::hmac::Hmac;
use crypto::sha1::Sha1;
use crypto::mac::{Mac, MacResult};
use hyper::header::Headers;
use pencil::Request;

header! { (XGitHubEvent, "X-GitHub-Event") => [String] }
header! { (XGitHubDelivery, "X-GitHub-Delivery") => [String] }
header! { (XHubSignature, "X-Hub-Signature") => [String] }

pub fn check_signature(request: &mut Request, signature: &XHubSignature, secret: &str) -> bool {
  let (method, hash) = {
    let mut split = signature.split('=');
    (split.next().unwrap(), split.next().unwrap())
  };
  if method != "sha1" {
    return false;
  }
  let hash = hex_string_to_bytes(hash);
  let mut bytes: Vec<u8> = Vec::new();
  request.read_to_end(&mut bytes);
  let result = build_sha1_hmac(secret, &bytes).result();
  let check_against = MacResult::new(&hash);
  result == check_against
}

fn build_sha1_hmac(secret: &str, input: &[u8]) -> Hmac<Sha1> {
  let mut hmac = Hmac::new(Sha1::new(), secret.as_bytes());
  hmac.input(input);
  hmac
}

pub fn hex_string_to_bytes(hex_string: &str) -> Vec<u8> {
  let char_vec = hex_string.chars().collect::<Vec<_>>();
  let chunks = char_vec.chunks(2);
  chunks
    .map(|x| u8::from_str_radix(
        x.into_iter().cloned().collect::<String>().as_str(),
        16
      ).unwrap()
    )
    .collect::<Vec<_>>()
}
