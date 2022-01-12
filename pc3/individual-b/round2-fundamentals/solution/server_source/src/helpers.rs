
// Copyright 2022 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

pub mod math_funcs {
    use num::traits::WrappingAdd;
    use num::{One, Zero};

    pub fn fibonacci<T: Zero + One + WrappingAdd + Copy>() -> impl Iterator<Item = T> {
        let (mut a, mut b) = (T::zero(), T::one());
        (0..).map(move |_| {
            let temp = a;
            a = b;
            b = b.wrapping_add(&temp);
            temp
        })
    }

    pub fn shifted_floats() -> impl Iterator<Item = f64> {
        (0..64).map(|n| f64::from_bits(1 << n))
    }
}

pub mod misc {
    fn internal_get_flag(flag_num: usize) -> String {
        format!("Successfully completed sequence {}.", flag_num)
    }

    pub fn get_flag(flag_num: usize) -> String {
        internal_get_flag(flag_num)
    }
}

