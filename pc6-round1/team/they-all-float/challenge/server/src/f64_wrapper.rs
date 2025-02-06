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

use std::{fmt::Display, ops};

#[derive(Clone, Copy, Debug)]
pub(crate) struct F64(f64);

impl Display for F64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl ops::Neg for F64 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(-self.0)
    }
}

impl<T: Into<f64>> ops::Add<T> for F64 {
    type Output = Self;

    fn add(self, rhs: T) -> Self::Output {
        Self(self.0 + rhs.into())
    }
}

impl<T: Into<f64>> ops::AddAssign<T> for F64 {
    fn add_assign(&mut self, rhs: T) {
        self.0 += rhs.into()
    }
}

impl<T: Into<f64>> ops::Sub<T> for F64 {
    type Output = Self;

    fn sub(self, rhs: T) -> Self::Output {
        Self(self.0 - rhs.into())
    }
}

impl<T: Into<f64>> ops::SubAssign<T> for F64 {
    fn sub_assign(&mut self, rhs: T) {
        self.0 -= rhs.into()
    }
}

impl<T: Into<f64>> ops::Mul<T> for F64 {
    type Output = Self;

    fn mul(self, rhs: T) -> Self::Output {
        Self(self.0 * rhs.into())
    }
}

impl<T: Into<f64>> ops::MulAssign<T> for F64 {
    fn mul_assign(&mut self, rhs: T) {
        self.0 *= rhs.into()
    }
}

impl<T: Into<f64>> ops::Div<T> for F64 {
    type Output = Self;

    fn div(self, rhs: T) -> Self::Output {
        Self(self.0 / rhs.into())
    }
}

impl<T: Into<f64>> ops::DivAssign<T> for F64 {
    fn div_assign(&mut self, rhs: T) {
        self.0 /= rhs.into()
    }
}

impl<T: Into<f64>> ops::Rem<T> for F64 {
    type Output = Self;

    fn rem(self, rhs: T) -> Self::Output {
        Self(self.0 % rhs.into())
    }
}

impl<T: Into<f64>> ops::RemAssign<T> for F64 {
    fn rem_assign(&mut self, rhs: T) {
        self.0 %= rhs.into()
    }
}

impl<T: Into<f64>> ops::BitAnd<T> for F64 {
    type Output = Self;

    fn bitand(self, rhs: T) -> Self::Output {
        Self(f64::from_bits(self.0.to_bits() & rhs.into().to_bits()))
    }
}

impl<T: Into<f64>> ops::BitAndAssign<T> for F64 {
    fn bitand_assign(&mut self, rhs: T) {
        self.0 = f64::from_bits(self.0.to_bits() & rhs.into().to_bits());
    }
}

impl<T: Into<f64>> ops::BitOr<T> for F64 {
    type Output = Self;

    fn bitor(self, rhs: T) -> Self::Output {
        Self(f64::from_bits(self.0.to_bits() | rhs.into().to_bits()))
    }
}

impl<T: Into<f64>> ops::BitOrAssign<T> for F64 {
    fn bitor_assign(&mut self, rhs: T) {
        self.0 = f64::from_bits(self.0.to_bits() | rhs.into().to_bits());
    }
}

impl<T: Into<f64>> ops::BitXor<T> for F64 {
    type Output = Self;

    fn bitxor(self, rhs: T) -> Self::Output {
        Self(f64::from_bits(self.0.to_bits() ^ rhs.into().to_bits()))
    }
}

impl<T: Into<f64>> ops::BitXorAssign<T> for F64 {
    fn bitxor_assign(&mut self, rhs: T) {
        self.0 = f64::from_bits(self.0.to_bits() ^ rhs.into().to_bits());
    }
}

impl<T: Into<f64>> ops::Shl<T> for F64 {
    type Output = Self;

    fn shl(self, rhs: T) -> Self::Output {
        Self(f64::from_bits(self.0.to_bits() << rhs.into().to_bits()))
    }
}

impl<T: Into<f64>> ops::ShlAssign<T> for F64 {
    fn shl_assign(&mut self, rhs: T) {
        self.0 = f64::from_bits(self.0.to_bits() << rhs.into().to_bits());
    }
}

impl<T: Into<f64>> ops::Shr<T> for F64 {
    type Output = Self;

    fn shr(self, rhs: T) -> Self::Output {
        Self(f64::from_bits(self.0.to_bits() >> rhs.into().to_bits()))
    }
}

impl<T: Into<f64>> ops::ShrAssign<T> for F64 {
    fn shr_assign(&mut self, rhs: T) {
        self.0 = f64::from_bits(self.0.to_bits() >> rhs.into().to_bits());
    }
}

impl ops::Deref for F64 {
    type Target = f64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ops::DerefMut for F64 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: Into<f64> + Copy> PartialEq<T> for F64 {
    fn eq(&self, other: &T) -> bool {
        self.0.eq(&(*other).into())
    }
}

impl<T: Into<f64> + Copy> PartialOrd<T> for F64 {
    fn partial_cmp(&self, other: &T) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(&(*other).into())
    }
}

impl From<f64> for F64 {
    fn from(value: f64) -> Self {
        Self(value)
    }
}

impl Into<f64> for F64 {
    fn into(self) -> f64 {
        self.0
    }
}
