extern crate dotenv;
extern crate deploy;
extern crate pencil;
#[macro_use] extern crate lazy_static;

use dotenv::dotenv;
use std::env;
use std::thread;
use std::process::{Stdio, Command};
use std::path::Path;
use pencil::{Pencil, Response, Request, PencilResult};
use deploy::*;

lazy_static! {
  pub static ref SECRET: String = env::var("TENJAVA_DEPLOY_SECRET").expect("missing TENJAVA_DEPLOY_SECRET");
  pub static ref REPO: String = env::var("TENJAVA_WEBSITE_REPO").expect("mssing TENJAVA_WEBSITE_REPO");
}

fn deploy_webhook(r: &mut Request) -> PencilResult {
  let (signature, event) = {
    let headers = r.headers();
    let signature: &XHubSignature = headers.get().unwrap();
    let event: &XGitHubEvent = headers.get().unwrap();
    (signature.clone(), event.clone())
  };
  if *event != "push" {
    return Ok("not a push event, but thanks anyway".into());
  }
  if !deploy::check_signature(r, &signature, &SECRET) {
    let mut res = Response::new("invalid signature");
    res.status_code = 401;
    return Ok(res);
  }
  update_repo();
  Ok("deploy initiated".into())
}

fn update_repo() {
  thread::spawn(move || {
    let status = Command::new("git")
      .arg("pull")
      .stdout(Stdio::null())
      .current_dir(Path::new(&*REPO))
      .status()
      .expect("could not start git");
    if !status.success() {
      match status.code() {
        Some(code) => {
          println!("git exited with code {}", code);
        },
        None => {
          println!("git exited with an unknown status code");
        }
      }
    }
  });
}

fn inner() -> i32 {
  // load up env
  dotenv().ok();

  // check env
  if (&*SECRET).is_empty() {
    println!("oops, no TENJAVA_DEPLOY_SECRET was specified");
    return 1;
  }
  if (&*REPO).is_empty() {
    println!("oops, no TENJAVA_WEBSITE_REPO was specified");
    return 1;
  }
  let mut app = Pencil::new("/static");
  app.post("/deploy", "deploy", deploy_webhook);
  app.run("0.0.0.0:32260");
  0
}

fn main() {
  let exit_code = inner();
  std::process::exit(exit_code);
}
