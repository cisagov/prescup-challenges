<img src="../../../pc1-logo.png" height="250px">

# Python Security Pick 'Em

## func0

UNSAFE - `input` in Python 2 is essentially calling `eval` on a string supplied by the user, which will execute that
string as if it were a Python expression.

## func1

UNSAFE - filename is passed into this function and then passed to `subprocess.call(command, shell=True)` without any
sanitizing. This function can easily be misused and provide arbitrary command execution.

## func2

UNSAFE - The `yaml.load(config_file)` call is inherently unsafe with an untrusted YAML file. See
[here](https://github.com/yaml/pyyaml/wiki/PyYAML-yaml.load(input)-Deprecation).

## func3

UNSAFE - this program is vulnerable to a SQL injection attack because it uses Python's string substitution. See
[here](https://docs.python.org/3/library/sqlite3.html).

## func4

UNSAFE - [Mutable default arguments](https://nikos7am.com/posts/mutable-default-arguments/) can potentially leak
information unintentionally.

## func5

UNSAFE - Using `assert` is not a safe way to check conditions outside of running tests. Using the `-O` (optimize) flag
when running the Python interpreter strips out `assert` statements.

## func6

UNSAFE - The line `ssl.wrap_socket(sock)` returns an instance of ssl.SSLSocket, but is not actually assigned to a
variable. The following socket operations are transmitting data in plaintext.

## func7

UNSAFE - MD5 is notoriously unsafe for hashing passwords. See
[here](https://en.wikipedia.org/wiki/MD5#Collision_vulnerabilities).

## func8

UNSAFE - Making calls with the `requests` library and supplying `verify=False` means that the call skips the SSL
verification check.

## func9

UNSAFE - See [here](https://ajinabraham.com/blog/exploiting-insecure-file-extraction-in-python-for-code-execution).

## func10

SAFE

## func11

SAFE

## func12

SAFE

## func13

SAFE - uses Template substitution to safely do string substitution

## func14

SAFE - The original reasoning that this function was marked safe is that the function does not accept user input and
that the function writes a pickle file, and then immediately loads it, leaving a very tiny window to be exploited.
However, this function is still technically vulnerable to exploitation if an attacker is able to overwrite the
legitimate pickle file with a pickle exploit in between the write and the subsequent read.

We analyzed all submissions for this challenge, and there were no submissions where this was the only wrong answer.

## func15

SAFE

## func16

SAFE

## func17

SAFE

## func18

SAFE

## func19

SAFE

## Solution

The following flag is correct for the ordering of functions in the functions.txt file in this version of the challenge:

xqxbRlyWkQTWrnMiTIBzznxzXNgWWYcRNOmRLfcQ

## License
Copyright 2020 Carnegie Mellon University.  
Released under a MIT (SEI)-style license, please see LICENSE.md in the project root or contact permission@sei.cmu.edu for full terms.
