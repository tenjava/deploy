extern crate dotenv;
extern crate deploy;
extern crate pencil;
#[macro_use] extern crate lazy_static;

use dotenv::dotenv;
use std::env;
use pencil::{Pencil, Response, Request, PencilResult};
use deploy::*;

lazy_static! {
  pub static ref SECRET: String = env::var("TENJAVA_DEPLOY_SECRET").expect("no deploy secret set");
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
  Ok("okay".into())
}

fn main() {
  dotenv().ok();
  let mut app = Pencil::new("/static");
  app.get("/deploy", "deploy", deploy_webhook);
  app.run("127.0.0.1:32260");
}
