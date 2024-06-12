
// Copyright 2024 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

use sqlx::FromRow;

use serde::Serialize;
use std::{error::Error, fmt::Display};

#[derive(FromRow, Serialize)]
pub(crate) struct AirlockFields {
    pub(crate) id: String,
    pub(crate) outer_open: bool,
    pub(crate) inner_open: bool,
    pub(crate) pressurized: bool,
}
impl From<Airlock> for AirlockFields {
    fn from(value: Airlock) -> Self {
        let (pressurized, inner_open, outer_open) = match &value.state {
            AirlockState::Valid(v) => match v {
                ValidAirlockState::PressurizedInnerOpen => (true, true, false),
                ValidAirlockState::PressurizedClosed => (true, false, false),
                ValidAirlockState::DepressurizedClosed => (false, false, false),
                ValidAirlockState::DepressurizedOuterOpen => (false, false, true),
            },
            AirlockState::Invalid(i) => match i {
                InvalidAirlockState::DepressurizedInnerOpen => (false, true, false),
                InvalidAirlockState::PressurizedOuterOpen => (true, false, true),
                InvalidAirlockState::DepressurizedBothOpen => (false, true, true),
                InvalidAirlockState::PressurizedBothOpen => (true, true, true),
            },
        };
        let id = value.id;

        Self {
            id,
            outer_open,
            inner_open,
            pressurized,
        }
    }
}

#[derive(Debug)]
pub(crate) struct AirlockStateError {
    pub(crate) error_msg: String,
}
impl Display for AirlockStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error_msg)
    }
}
impl Error for AirlockStateError {}
pub(crate) struct Airlock {
    id: String,
    state: AirlockState,
}
impl Airlock {
    pub(crate) fn report(&self) -> String {
        format!("Airlock {} | {}", self.id, self.state.report())
    }

    fn valid(&self) -> Result<(), AirlockStateError> {
        use AirlockState::*;
        if let Invalid(_) = self.state {
            return Err(AirlockStateError {
                error_msg: self.report(),
            });
        }
        Ok(())
    }

    pub(crate) fn cycle_outward(&mut self) -> Result<(), AirlockStateError> {
        self.valid()?;
        self.state = self.state.cycle_outward();
        Ok(())
    }

    pub(crate) fn cycle_inward(&mut self) -> Result<(), AirlockStateError> {
        self.valid()?;
        self.state = self.state.cycle_inward();
        Ok(())
    }
}
impl From<AirlockFields> for Airlock {
    fn from(value: AirlockFields) -> Self {
        let state = AirlockState::from(&value);
        Self {
            id: value.id,
            state,
        }
    }
}

trait AirlockStateReport {
    fn report(&self) -> &'static str;
}

#[derive(Clone, Copy, Debug)]
enum AirlockState {
    Valid(ValidAirlockState),
    Invalid(InvalidAirlockState),
}
impl AirlockState {
    fn cycle_outward(self) -> Self {
        if let Self::Valid(v) = self {
            return Self::Valid(v.cycle_outward());
        }
        self
    }

    fn cycle_inward(self) -> Self {
        if let Self::Valid(v) = self {
            return Self::Valid(v.cycle_inward());
        }
        self
    }
}
impl From<&AirlockFields> for AirlockState {
    fn from(value: &AirlockFields) -> Self {
        use AirlockState::*;
        match ValidAirlockState::try_from(value) {
            Ok(v) => Valid(v),
            Err(i) => Invalid(i),
        }
    }
}
impl AirlockStateReport for AirlockState {
    fn report(&self) -> &'static str {
        use AirlockState::*;
        match self {
            Valid(v) => v.report(),
            Invalid(i) => i.report(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum ValidAirlockState {
    PressurizedInnerOpen,
    PressurizedClosed,
    DepressurizedClosed,
    DepressurizedOuterOpen,
}
impl ValidAirlockState {
    const DEPRESSURIZED_CLOSED_STR: &str =
        "Outer Door: CLOSED | Inner Door: CLOSED | Depressurized | NOMINAL";
    const PRESSURIZED_CLOSED_STR: &str =
        "Outer Door: CLOSED | Inner Door: CLOSED | Pressurized | NOMINAL";
    const DEPRESSURIZED_OUTER_OPEN_STR: &str =
        "Outer Door: OPEN | Inner Door: CLOSED | Depressurized | NOMINAL";
    const PRESSURIZED_INNER_OPEN_STR: &str =
        "Outer Door: CLOSED | Inner Door: OPEN | Pressurized | NOMINAL";

    fn cycle_outward(self) -> Self {
        use ValidAirlockState::*;
        match self {
            PressurizedInnerOpen => PressurizedClosed,
            PressurizedClosed => DepressurizedClosed,
            DepressurizedClosed => DepressurizedOuterOpen,
            DepressurizedOuterOpen => DepressurizedOuterOpen,
        }
    }

    fn cycle_inward(self) -> Self {
        use ValidAirlockState::*;
        match self {
            PressurizedInnerOpen => PressurizedInnerOpen,
            PressurizedClosed => PressurizedInnerOpen,
            DepressurizedClosed => PressurizedClosed,
            DepressurizedOuterOpen => DepressurizedClosed,
        }
    }
}
impl AirlockStateReport for ValidAirlockState {
    fn report(&self) -> &'static str {
        use ValidAirlockState::*;
        match self {
            PressurizedInnerOpen => Self::PRESSURIZED_INNER_OPEN_STR,
            PressurizedClosed => Self::PRESSURIZED_CLOSED_STR,
            DepressurizedClosed => Self::DEPRESSURIZED_CLOSED_STR,
            DepressurizedOuterOpen => Self::DEPRESSURIZED_OUTER_OPEN_STR,
        }
    }
}
impl TryFrom<&AirlockFields> for ValidAirlockState {
    type Error = InvalidAirlockState;

    fn try_from(value: &AirlockFields) -> Result<Self, Self::Error> {
        Ok(
            match (&value.pressurized, &value.inner_open, &value.outer_open) {
                (false, false, false) => ValidAirlockState::DepressurizedClosed,

                (true, false, false) => ValidAirlockState::PressurizedClosed,
                (false, false, true) => ValidAirlockState::DepressurizedOuterOpen,
                (true, true, false) => ValidAirlockState::PressurizedInnerOpen,
                _ => return Err(InvalidAirlockState::try_from(value).unwrap()),
            },
        )
    }
}

#[derive(Clone, Copy, Debug)]
enum InvalidAirlockState {
    DepressurizedInnerOpen,
    PressurizedOuterOpen,
    DepressurizedBothOpen,
    PressurizedBothOpen,
}
impl InvalidAirlockState {
    const DEPRESSURIZED_INNER_OPEN_STR: &str =
        "Outer Door: CLOSED | Inner Door: OPEN | Depressurized | WARNING";
    const PRESSURIZED_OUTER_OPEN_STR: &str =
        "Outer Door: OPEN | Inner Door: CLOSED | Pressurized | WARNING";
    const DEPRESSURIZED_BOTH_OPEN_STR: &str =
        "Outer Door: OPEN | Inner Door: OPEN | Depressurized | EMERGENCY";
    const PRESSURIZED_BOTH_OPEN_STR: &str =
        "Outer Door: OPEN | Inner Door: OPEN | Pressurized | EMERGENCY";
}
impl AirlockStateReport for InvalidAirlockState {
    fn report(&self) -> &'static str {
        use InvalidAirlockState::*;
        match self {
            DepressurizedInnerOpen => Self::DEPRESSURIZED_INNER_OPEN_STR,
            PressurizedOuterOpen => Self::PRESSURIZED_OUTER_OPEN_STR,
            DepressurizedBothOpen => Self::DEPRESSURIZED_BOTH_OPEN_STR,
            PressurizedBothOpen => Self::PRESSURIZED_BOTH_OPEN_STR,
        }
    }
}
impl TryFrom<&AirlockFields> for InvalidAirlockState {
    type Error = ValidAirlockState;

    fn try_from(value: &AirlockFields) -> Result<Self, Self::Error> {
        use InvalidAirlockState::*;
        Ok(
            match (&value.pressurized, &value.inner_open, &value.outer_open) {
                (false, true, false) => DepressurizedInnerOpen,
                (true, false, true) => PressurizedOuterOpen,
                (false, true, true) => DepressurizedBothOpen,
                (true, true, true) => PressurizedBothOpen,
                _ => return Err(ValidAirlockState::try_from(value).unwrap()),
            },
        )
    }
}

