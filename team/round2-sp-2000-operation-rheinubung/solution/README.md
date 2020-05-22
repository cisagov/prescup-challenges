<img src="../../../logo.png" height="250px">

# Operation Rheinübung

The source code is included for the variant in this repository in the file `bismarck-001.go`. There is also a solver
script that has been adapted from the repository [here](https://github.com/CarveSystems/gostringsr2).

## Solution

If analyzed with R2/Radare2, binary will show that it is not typically compiled. Looking at a Go binary through strings
shows one very long string, as Go does not store null-terminated strings in the compiled binary.

[See this article for more information on reverse engineering Go binaries](https://carvesystems.com/news/reverse-engineering-go-binaries-using-radare-2-and-python/)

So the first step in the solution is to split the strings correctly, using the techniques from this article.

The second step is to simply dump those strings into ascii format, which can be done from python as well.

```
./build.sh
$ python solve.py -f bismarck-001
```

From here we get a dump of all the strings in the file, many of which include numbers. Run the numerical strings through
a hex-to-ascii converter, and you will find the flag.

## Flag

pcupCTF{shecapsizedtoportanddisappearedfromthesurface}

## License
Copyright 2020 Carnegie Mellon University. See the [LICENSE.md](../../../LICENSE.md) file for details.