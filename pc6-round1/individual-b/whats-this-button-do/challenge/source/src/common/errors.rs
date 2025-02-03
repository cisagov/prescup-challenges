/*
 * Copyright 2025 Carnegie Mellon University.
 *
 * NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
 *
 * Licensed under a MIT (SEI)-style license, please see license.txt or contact permission@sei.cmu.edu for full terms.
 *
 * [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.
 *
 * This Software includes and/or makes use of Third-Party Software each subject to its own license.
 * DM25-0166 */

use std::error::Error;
use std::fmt::Display;

use strum::EnumString;

type BoxedError = Box<dyn Error>;

#[derive(Debug, EnumString)]
pub(crate) enum KeyBytesError {}
impl Display for KeyBytesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_string())
    }
}

#[derive(Debug)]
pub(crate) enum InnerError {
    BoxedError(BoxedError),
    Message(String),
}
impl Display for InnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let err_str = match self {
            Self::BoxedError(e) => &e.to_string(),
            Self::Message(s) => s,
        };
        f.write_str(&err_str)
    }
}

#[derive(Debug)]
pub(crate) enum MessageDeserializeErrorType {
    ReadLength,
    ZeroLength,
    VeryLargeLength,
    ReadMessageBytes,
    FromSlice,
}
#[derive(Debug)]
pub(crate) struct MessageDeserializeError {
    pub(crate) error_type: MessageDeserializeErrorType,
    pub(crate) inner_err: InnerError,
}
impl Display for MessageDeserializeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let fmt_str = format!("{:?}: {}", self.error_type, self.inner_err);
        f.write_str(fmt_str.as_str())
    }
}
impl Error for MessageDeserializeError {}
impl MessageDeserializeError {
    pub(crate) fn new(error_type: MessageDeserializeErrorType, inner_err: BoxedError) -> Self {
        let inner_err = InnerError::BoxedError(inner_err);
        Self {
            error_type,
            inner_err,
        }
    }

    pub(crate) fn new_msg(error_type: MessageDeserializeErrorType, inner_err: &str) -> Self {
        let inner_err = InnerError::Message(inner_err.to_string());
        Self {
            error_type,
            inner_err,
        }
    }
}

#[derive(Debug)]
pub(crate) enum MessageSerializeErrorType {
    WriteLength,
    ToVec,
    WriteMessage,
    Flush,
}
#[derive(Debug)]
pub(crate) struct MessageSerializeError {
    pub(crate) error_type: MessageSerializeErrorType,
    pub(crate) inner_err: BoxedError,
}
impl Display for MessageSerializeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let fmt_str = format!("{:?}: {}", self.error_type, self.inner_err);
        f.write_str(fmt_str.as_str())
    }
}
impl Error for MessageSerializeError {}
impl MessageSerializeError {
    pub(crate) fn new(error_type: MessageSerializeErrorType, inner_err: BoxedError) -> Self {
        Self {
            error_type,
            inner_err,
        }
    }
}

#[derive(Debug)]
pub(crate) enum NegotiationErrorType {
    TheirPubKeyLength,
}
#[derive(Debug)]
pub(crate) struct NegotiationError {
    error_type: NegotiationErrorType,
}
impl Display for NegotiationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let fmt_str = format!("{:?}", self.error_type);
        f.write_str(fmt_str.as_str())
    }
}
impl Error for NegotiationError {}
impl NegotiationError {
    pub(crate) fn new(error_type: NegotiationErrorType) -> Self {
        Self { error_type }
    }
}
