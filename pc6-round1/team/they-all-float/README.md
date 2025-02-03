# They All Float Down Here

Pick away at several floating-point puzzles. Some are normal floating-point operations and some are bitwise operations.

**NICE Work Roles**

- [Secure Software Development](https://niccs.cisa.gov/workforce-development/nice-framework/)
- [Vulnerability Analysis](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T1117](https://niccs.cisa.gov/workforce-development/nice-framework/): Determine if desired program results are produced.
- [T1197](https://niccs.cisa.gov/workforce-development/nice-framework/): Identify common coding flaws.
- [1118](https://niccs.cisa.gov/workforce-development/nice-framework/): Identify vulnerabilities


## Background

Sometimes integer overflows cause strange software bugs. Sometimes these bugs have security implications. But what about floating-point values and *their* handling in code?

## Getting Started

In the gamespace, navigate to `challenge.us` and download the `curl_command.sh` file. This file offers a convenient option for interacting with the target server in this challenge. The first argument is the challenge part number. The next two arguments are input values. All values are expected to be JSON `number` values. An example submission might be `./curl_command.sh 1 8.5 9e123`, which would attempt to submit the values `8.5` and `9e123` for part 1.

Upon sending a valid request to the server, the server will do a hidden computation. If the server, using your two input values in the computation for each part, computes its expected result, you will receive a token for that part. Otherwise the server will send back the bit string it expects and the value it corresponds to in [IEEE 754](https://en.wikipedia.org/wiki/IEEE_754) double-precision.

As mentioned above, some of these operations are more natural operations on floating-point, while others are bitwise operations and will require engineered inputs.

## Challenge Questions

There are **four** tokens in this challenge, each corresponding to the part number. **All tokens** are printable ASCII hex strings of length 16.

1. float.us:8000/part1 token.
2. float.us:8000/part2 token.
3. float.us:8000/part3 token.
4. float.us:8000/part4 token.
