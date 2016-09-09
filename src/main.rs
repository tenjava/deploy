#[macro_use] extern crate lazy_static;
extern crate deploy;
extern crate dotenv;
extern crate pencil;
extern crate serde_json;

use deploy::*;
use dotenv::dotenv;
use pencil::{Pencil, Response, Request, PencilResult};
use std::env;
use std::fs::File;
use std::io::Read;

lazy_static! {
  pub static ref SECRET: String = env::var("TENJAVA_DEPLOY_SECRET").expect("missing TENJAVA_DEPLOY_SECRET");
  pub static ref COMMAND_FILE: CommandFile = {
    let mut json = String::new();
    File::open("commands.json").expect("no commands.json").read_to_string(&mut json).unwrap();
    serde_json::from_str(&json).unwrap()
  };
}

fn deploy_webhook(r: &mut Request) -> PencilResult {
  println!("receiving a deploy request");
  let (signature, event) = {
    let headers = r.headers();
    let signature: &XHubSignature = match headers.get() {
      Some(x) => x,
      None => {
        println!("  it was missing a signature header");
        println!("  done");
        let mut res = Response::new("missing a signature header");
        res.status_code = 401;
        return Ok(res);
      }
    };
    let event: &XGitHubEvent = match headers.get() {
      Some(x) => x,
      None => {
        println!("  it was missing an event header");
        println!("  done");
        let mut res = Response::new("missing an event header");
        res.status_code = 401;
        return Ok(res);
      }
    };
    (signature.clone(), event.clone())
  };
  if *event != "push" {
    println!("  it was not a push event");
    println!("  done");
    return Ok("not a push event, but thanks anyway".into());
  }
  let bytes = match deploy::get_request_bytes(r) {
    Ok(x) => x,
    Err(e) => {
      println!("  could not read request: {}", e);
      println!("  done");
      let mut res = Response::new(format!("could not read request: {}", e));
      res.status_code = 500;
      return Ok(res);
    }
  };
  let signature_check = match deploy::check_signature(&bytes, &signature, &SECRET) {
    Ok(x) => x,
    Err(e) => {
      println!("  an error occurred while checking the signature: {}", e);
      println!("  done");
      let mut res = Response::new(format!("an error occurred while checking signature: {}", e));
      res.status_code = 500;
      return Ok(res);
    }
  };
  if !signature_check {
    println!("  it had an invalid signature");
    println!("  done");
    let mut res = Response::new("invalid signature");
    res.status_code = 401;
    return Ok(res);
  }
  println!("  everything checks out");
  println!("  checking branch");
  let branch = match deploy::get_branch(bytes) {
    Ok(b) => b,
    Err(e) => {
      println!("  an error occurred while checking branch: {}", e);
      println!("  done");
      let mut res = Response::new(format!("couldn't get branch: {}", e));
      res.status_code = 500;
      return Ok(res);
    }
  };
  println!("  spawning update thread");
  update_repo(branch);
  println!("  thread spawned");
  println!("  done");
  println!("");
  Ok("deploy initiated".into())
}

fn update_repo(branch: Branch) {
  (&*COMMAND_FILE).clone().execute(branch);
}

fn inner() -> i32 {
  // load up env
  dotenv().ok();

  // check env
  if (&*SECRET).is_empty() {
    println!("oops, no TENJAVA_DEPLOY_SECRET was specified");
    return 1;
  }
  if (&*PROD_REPO).is_empty() {
    println!("oops, no TENJAVA_WEBSITE_PROD_REPO was specified");
    return 1;
  }
  if (&*DEV_REPO).is_empty() {
    println!("oops, no TENJAVA_WEBSITE_DEV_REPO was specified");
    return 1;
  }
  let _ = &*COMMAND_FILE;
  let mut app = Pencil::new("/static");
  app.post("/deploy", "deploy", deploy_webhook);
  app.run("0.0.0.0:32260");
  0
}

fn main() {
  let exit_code = inner();
  std::process::exit(exit_code);
}
