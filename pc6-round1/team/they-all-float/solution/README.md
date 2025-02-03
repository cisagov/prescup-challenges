# They All Float Down Here

*Solution Guide*

## Overview

*The All Float Down Here* tests a player's understanding of the IEEE 754 floating-point standard and edge cases involving the conversion between JSON `number` values to the hardware implementation of floating-point values.

Players need to send pairs of test values to the server to determine what operations are being performed on the submitted values. The server then sends back the value it expects to compute from the two values, and competitors need to engineer their test values to arrive at that value.

Much of the challenge difficulty pertains to the server expecting values that are not representable within JSON `number` values: **infinity** and **NaN**. Players need to know how to combine two representable values to get to these non-representable values for each operation.

For each question below, the expected result is posed as the question and a pair of valid inputs is provided along with an explanation.

## Question 1

*0b0111111111110000000000000000000000000000000000000000000000000000 (Value: inf)*

In this part, the server computes `v1 + v2`. Since it's not possible to submit an infinity value, the operation needs to be overflowed. Therefore, a valid pair of inputs for this part is `1e308`, `1e308`. The maximum representable value in double-precision floating-point is approximately `1.8e308`, which means that `2e308` becomes infinity in this representation.

## Question 2

*0b0111111111111000000000000000000000000000000000000000000000000000 (Value: NaN)*

This part involves both division and subtraction. The server computes the value of `abs((v1 / (v2 - 9.785)))`. To get one of the special values out of this computation we can force the denominator to be `0` by specifying the second value as `9.785`. But, to get **NaN** instead of **infinity**, the numerator must be `0.0`. A valid pair of inputs for this part is `0.0`, `9.785`.

## Question 3

*0b0111111111110000000000000000000000000000000000000000000000000000 (Value: inf)*

This part performs the first bitwise operation on the two values. The server computes `v1 << v2` on the *bits* of the input values. This means that we need to engineer floating-point inputs in such a way as to get:

`0b0011111111111000000000000000000000000000000000000000000000000000 << 0b0000000000000000000000000000000000000000000000000000000000000001`

To clarify, `v1` needs to look like the first value and then shift  left so it turns into infinity. A valid pair of inputs is `1.5`, `5e-324`, which evaluate to the exact bit patterns shown.

## Question 4

*0b1111111111110000000000000000000000000000000000000000000000000000 (Value: -inf)*

The server computes `v1 ^ v2` for this part. The two input values need to be engineered. Exactly one of the values must be negative so that the operation result has a `1` in the highest bit. Then, in order to get **infinity** instead of **NaN**, all of the exponent bits must be `1`, and all of the mantissa bits must be `0`. A valid pair of inputs is `-1.0`, `2.0` for this part. The bit pattern for `-1.0` is:

`0b1011111111110000000000000000000000000000000000000000000000000000`

...and the bit pattern for `2.0` is:

`0b0100000000000000000000000000000000000000000000000000000000000000`.

When combined with a bitwise XOR (exclusive OR), it results in the expected bit pattern.
