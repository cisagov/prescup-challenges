<img src="../../../pc1-logo.png" height="250px">

# Python Security Pick 'Em (Individual)

## Solution

You can use the `flaganalysis.py` script to validate a flag from an attempt.

However, here is the reasoning for each function's assessment:

#### `functions/bad/Gw`

This function is using the `eval()` function on a variable that is being passed in from a calling function. Since this
function does no security checking, it can easily be used in a dangerous way.

#### `functions/bad/Oo`

This function is opening a file and calling the `exec()` function on the contents. Since the contents of this file can
be modified outside of the program's control flow, this is dangerous.

#### `functions/bad/tZ`

##### CORRECTION: The line `with open('data.ser') as f:` should be `with open('data.ser', 'rb') as f:`.

This function opens a file with Python's `pickle` module, which can be exploited with the following script:

```
import pickle
import subprocess
import os

class DumpInfo:
    def __reduce__(self):
        return subprocess.Popen, ('echo HAX', -1, None, None, None, None, None, True, True)

def main():
    o = DumpInfo()
    with open('dummy.pickle', 'wb') as f:
        pickle.dump(o, f)

if __name__ == '__main__':
    main()
```

The file that the function tries to open can be replaced with the `dummy.pickle` file that this script creates, and in
the course of loading the pickled object, the __reduce__ method is called and the pickle loader executes the function
it returns with the given arguments.

#### `functions/bad/xC`

This function is opening an XML file with ElementTree. See
[here](https://docs.python.org/3.7/library/xml.html#xml-vulnerabilities) for known vulnerabilities.

#### `functions/good/EZ`

While this function uses `subprocess.call()` with the argument `shell=True`, the actual shell command is hard-coded in
the function and cannot be changed externally.

#### `functions/good/Ja`

Instead of `eval()`, this function uses `ast.literal_eval()` to attempt to convert text into a Python object.
`ast.literal_eval()` is a safe option for loading a Python object, as mentioned in its
[documentation](https://docs.python.org/3.7/library/ast.html#ast.literal_eval).

#### `functions/good/WG`

##### CORRECTION: This function should have specified the use of sqlite3 as the database being used to avoid any
##### possible confusion with third party database libraries. However, sqlite3 is the only SQL database library in the
##### Python standard library at the time of writing.

As shown in the [sqlite3 documentation](https://docs.python.org/3/library/sqlite3.html#module-sqlite3), the proper way
to insert variables into a query in the sqlite3 library is to format the query string with `?` and call the
`cursor.execute()` method with the query string and a tuple of the parameter substitutions.

#### `functions/good/Xv`

While `pickle` can be used in a dangerous way, the data being loaded is hard-coded within the function. The function
does not depend on any external security because of this, and so it's safe to use (even if it's not particularly useful
code).

## License
Copyright 2020 Carnegie Mellon University.  
Released under a MIT (SEI)-style license, please see LICENSE.md in the project root or contact permission@sei.cmu.edu for full terms.
