#![feature(custom_derive, plugin)]
#![plugin(serde_macros)]

#[macro_use] extern crate hyper;
#[macro_use] extern crate lazy_static;
extern crate crypto;
extern crate pencil;
extern crate serde;
extern crate serde_json;

use crypto::hmac::Hmac;
use crypto::mac::{Mac, MacResult};
use crypto::sha1::Sha1;
use pencil::Request;
use std::env;
use std::io::Read;
use std::path::Path;
use std::process::{Stdio, Command};
use std::thread;

header! { (XGitHubEvent, "X-GitHub-Event") => [String] }
header! { (XGitHubDelivery, "X-GitHub-Delivery") => [String] }
header! { (XHubSignature, "X-Hub-Signature") => [String] }

lazy_static! {
  pub static ref PROD_REPO: String = env::var("TENJAVA_WEBSITE_PROD_REPO").expect("missing TENJAVA_WEBSITE_PROD_REPO");
  pub static ref DEV_REPO: String = env::var("TENJAVA_WEBSITE_DEV_REPO").expect("missing TENJAVA_WEBSITE_DEV_REPO");
}

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

#[derive(Deserialize)]
pub struct CommandFile {
  pub commands: Vec<Vec<String>>
}

impl CommandFile {
  pub fn execute(&self, branch: &Branch) {
    for command in &self.commands {
      self.execute_command(branch, command.clone());
    }
  }

  fn execute_command(&self, branch: &Branch, command: Vec<String>) {
    let repo_path = match *branch {
      Branch::Master => &*PROD_REPO,
      Branch::Dev => &*DEV_REPO
    };
    let handle = thread::spawn(move || {
      if command.is_empty() {
        println!("no command");
        return;
      }
      let command_name = &command[0];
      let args = if command.len() > 1 {
        &command[1..]
      } else {
        &[]
      };
      let status = Command::new(command_name.clone())
        .args(args)
        .stdout(Stdio::null())
        .current_dir(Path::new(repo_path))
        .status();
      let status = match status {
        Ok(r) => r,
        Err(e) => {
          println!("could not start {}: {}", command_name, e);
          return;
        }
      };
      if !status.success() {
        match status.code() {
          Some(code) => {
            println!("{} exited with code {}", command_name, code);
          },
          None => {
            println!("{} exited with an unknown status code", command_name);
          }
        }
      } else {
        println!("{} exited successfully", command_name);
      }
    });
    handle.join().unwrap();
  }
}

fn get_request_from_bytes(bytes: Vec<u8>) -> DeployResult<DeployRequest> {
  let json_string = match String::from_utf8(bytes) {
    Ok(x) => x,
    Err(e) => return Err(format!("could not convert request to string: {}", e))
  };
  serde_json::from_str(&json_string).map_err(|x| format!("could not process json from request: {}", x))
}

pub fn get_branch(bytes: Vec<u8>) -> DeployResult<Branch> {
  let request = try!(get_request_from_bytes(bytes));
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
