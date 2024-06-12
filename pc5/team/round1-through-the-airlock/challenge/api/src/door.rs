
// Copyright 2024 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

use serde::Serialize;
use sqlx::FromRow;

#[derive(FromRow, Serialize)]
pub(crate) struct DoorFields {
    pub(crate) id: String,
    pub(crate) open: bool,
}
impl DoorFields {
    pub(crate) fn report(&self) -> String {
        format!(
            "Door {} | {}",
            self.id,
            if self.open { "Open" } else { "Closed" }
        )
    }
}

