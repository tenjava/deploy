#[macro_use] extern crate hyper;
extern crate crypto;
extern crate pencil;

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

pub fn get_branch(request: &mut Request) -> DeployResult<Branch> {
  let json = match *request.get_json() {
    Some(ref x) => x,
    None => return Err("couldn't read json from the request".into())
  };
  let ref_key = *match json.find("ref") {
    Some(ref x) => x,
    None => return Err("json missing 'ref' key".into())
  };
  let ref_string = match ref_key.as_string() {
    Some(x) => x,
    None => return Err("'ref' key was not a string".into())
  };
  let branch = match ref_string.split('/').last() {
    Some(x) => x,
    None => return Err("invalid 'ref' key".into())
  };
  match branch {
    "master" => Ok(Branch::Master),
    "dev" => Ok(Branch::Dev),
    _ => Err("invalid branch".into())
  }
}

pub fn check_signature(request: &mut Request, signature: &XHubSignature, secret: &str) -> DeployResult<bool> {
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
  let mut bytes: Vec<u8> = Vec::new();
  match request.read_to_end(&mut bytes) {
    Ok(_) => {},
    Err(e) => {
      return Err(format!("could not read request: {}", e));
    }
  }
  let result = build_sha1_hmac(secret, &bytes).result();
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
