
// Copyright 2024 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

use sqlx::FromRow;

use serde::Serialize;
use std::{error::Error, fmt::Display};

#[derive(FromRow, Serialize)]
pub(crate) struct CameraFields {
    pub(crate) id: String,
    pub(crate) active: bool,
    pub(crate) recording: bool,
}
impl From<Camera> for CameraFields {
    fn from(value: Camera) -> Self {
        let (active, recording) = match value.state {
            CameraState::Valid(v) => match v {
                ValidCameraState::ActiveRecording => (true, true),
                ValidCameraState::ActiveNotRecording => (true, false),
                ValidCameraState::InactiveNotRecording => (false, false),
            },
            CameraState::Invalid(i) => match i {
                InvalidCameraState::InactiveRecording => (false, true),
            },
        };
        let id = value.id;

        Self {
            id,
            active,
            recording,
        }
    }
}

#[derive(Debug)]
pub(crate) struct CameraStateError {
    pub(crate) error_msg: String,
}
impl Display for CameraStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error_msg)
    }
}
impl Error for CameraStateError {}

pub(crate) struct Camera {
    id: String,
    state: CameraState,
}
impl Camera {
    pub(crate) fn report(&self) -> String {
        format!("Camera {} | {}", self.id, self.state.report())
    }

    fn valid(&self) -> Result<(), CameraStateError> {
        use CameraState::*;
        if let Invalid(_) = self.state {
            return Err(CameraStateError {
                error_msg: self.report(),
            });
        }
        Ok(())
    }

    pub(crate) fn start_recording(&mut self) -> Result<(), CameraStateError> {
        self.valid()?;
        self.state = self.state.start_recording();
        Ok(())
    }

    pub(crate) fn stop_recording(&mut self) -> Result<(), CameraStateError> {
        self.valid()?;
        self.state = self.state.stop_recording();
        Ok(())
    }

    pub(crate) fn activate(&mut self) -> Result<(), CameraStateError> {
        self.valid()?;
        self.state = self.state.activate();
        Ok(())
    }

    pub(crate) fn deactivate(&mut self) -> Result<(), CameraStateError> {
        self.valid()?;
        self.state = self.state.deactivate();
        Ok(())
    }
}
impl From<CameraFields> for Camera {
    fn from(value: CameraFields) -> Self {
        let state = CameraState::from(&value);
        Self {
            id: value.id,
            state,
        }
    }
}

trait CameraReport {
    fn report(&self) -> &'static str;
}

#[derive(Clone, Copy, Debug)]
enum CameraState {
    Valid(ValidCameraState),
    Invalid(InvalidCameraState),
}
impl CameraState {
    fn start_recording(self) -> Self {
        if let Self::Valid(v) = self {
            return Self::Valid(v.start_recording());
        }
        self
    }

    fn stop_recording(self) -> Self {
        if let Self::Valid(v) = self {
            return Self::Valid(v.stop_recording());
        }
        self
    }

    fn activate(self) -> Self {
        if let Self::Valid(v) = self {
            return Self::Valid(v.activate());
        }
        self
    }

    fn deactivate(self) -> Self {
        if let Self::Valid(v) = self {
            return Self::Valid(v.deactivate());
        }
        self
    }
}
impl CameraReport for CameraState {
    fn report(&self) -> &'static str {
        match self {
            Self::Valid(v) => v.report(),
            Self::Invalid(i) => i.report(),
        }
    }
}
impl From<&CameraFields> for CameraState {
    fn from(value: &CameraFields) -> Self {
        match ValidCameraState::try_from(value) {
            Ok(v) => Self::Valid(v),
            Err(i) => Self::Invalid(i),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum ValidCameraState {
    ActiveRecording,
    ActiveNotRecording,
    InactiveNotRecording,
}
impl ValidCameraState {
    const ACTIVE_RECORDING_STR: &str = "Active | Recording | NOMINAL";
    const ACTIVE_NOT_RECORDING_STR: &str = "Active | Not Recording | NOMINAL";
    const INACTIVE_NOT_RECORDING_STR: &str = "Inactive | Not Recording | NOMINAL";

    fn start_recording(self) -> Self {
        match self {
            Self::ActiveNotRecording => Self::ActiveRecording,
            Self::InactiveNotRecording => Self::ActiveRecording,
            _ => self,
        }
    }

    fn stop_recording(self) -> Self {
        match self {
            Self::ActiveRecording => Self::ActiveNotRecording,
            _ => self,
        }
    }

    fn activate(self) -> Self {
        match self {
            Self::InactiveNotRecording => Self::ActiveNotRecording,
            _ => self,
        }
    }

    fn deactivate(self) -> Self {
        Self::InactiveNotRecording
    }
}
impl CameraReport for ValidCameraState {
    fn report(&self) -> &'static str {
        match self {
            Self::ActiveRecording => Self::ACTIVE_RECORDING_STR,
            Self::ActiveNotRecording => Self::ACTIVE_NOT_RECORDING_STR,
            Self::InactiveNotRecording => Self::INACTIVE_NOT_RECORDING_STR,
        }
    }
}
impl TryFrom<&CameraFields> for ValidCameraState {
    type Error = InvalidCameraState;

    fn try_from(value: &CameraFields) -> Result<Self, Self::Error> {
        Ok(match (value.active, value.recording) {
            (true, true) => Self::ActiveRecording,
            (true, false) => Self::ActiveNotRecording,
            (false, false) => Self::InactiveNotRecording,
            (false, true) => return Err(InvalidCameraState::try_from(value).unwrap()),
        })
    }
}

#[derive(Clone, Copy, Debug)]
enum InvalidCameraState {
    InactiveRecording,
}
impl InvalidCameraState {
    const INACTIVE_RECORDING_STR: &str = "Inactive | Recording | WARNING";
}
impl CameraReport for InvalidCameraState {
    fn report(&self) -> &'static str {
        match self {
            Self::InactiveRecording => Self::INACTIVE_RECORDING_STR,
        }
    }
}
impl TryFrom<&CameraFields> for InvalidCameraState {
    type Error = ValidCameraState;

    fn try_from(value: &CameraFields) -> Result<Self, Self::Error> {
        Ok(match (value.active, value.recording) {
            (false, true) => Self::InactiveRecording,
            _ => return Err(ValidCameraState::try_from(value).unwrap()),
        })
    }
}

