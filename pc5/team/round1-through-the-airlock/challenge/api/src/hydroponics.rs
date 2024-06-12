
// Copyright 2024 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

use serde::Serialize;
use sqlx::FromRow;

#[derive(FromRow, Serialize)]
pub(crate) struct HydroponicsFields {
    pub(crate) id: String,
    pub(crate) active: bool,
}
impl HydroponicsFields {
    pub(crate) fn report(&self) -> String {
        format!(
            "Hydroponics System {} | {}",
            self.id,
            if self.active { "Active" } else { "Inactive" }
        )
    }
}

