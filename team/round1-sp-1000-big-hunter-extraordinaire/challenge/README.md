Welcome to the challenge!

1. Identify and correct the secure programming rule violation in program1. The corrected line of source code will be an
argument to program2.
2. Identify and correct the secure programming rule violation in program2. Send the corrected line of source code from
program1 to 10.10.10.100. IE: `./program2 10.10.10.100 'int n = 404;'` The server will return two strings to be used by
program 3.
3. Identify and correct the secure programming rule violation in program3. IE: `./program3 -f /etc/somefile -e somedata`
The output returned by program3 will be used by program4. The sum of the two line numbers corrected and 10000 will be
used as an argument to program4.
4. Use program4 to send the output of program3 to 10.10.10.100. Send the output from program3 as STDIN to program4. Use
the sum of the two line numbers corrected in program3 and 10000 as the port number to which program4 will connect. IE:
`echo -n 'output from program3' | ./program4 10.10.10.100 10065`. Receive a flag for submission to the grading system!

## License
Copyright 2020 Carnegie Mellon University. See the [LICENSE.md](../../../LICENSE.md) file for details.