
// Copyright 2022 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

#[macro_use]
extern crate rocket;
#[macro_use]
extern crate lazy_static;

mod helpers;
mod http_api;

use crate::http_api::endpoints;

#[launch]
fn rocket() -> _ {
    rocket::build().mount(
        "/",
        routes![
            endpoints::first,
            endpoints::first_submit,
            endpoints::second,
            endpoints::second_submit,
            endpoints::third,
            endpoints::third_submit
        ],
    )
}

