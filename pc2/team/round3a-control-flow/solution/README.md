# Gotta Go With the Control Flow Solution

## Note

[pyclient.py](./pyclient.py) and [rsclient.py](./rsclient.py) are example solution scripts which retrieve the flags from their respective server. Both servers are designed to require responses within a short enough time frame that manually reacting to the server's prompts is harder than just automating the responses with a script.

Note that in order to run [pyclient.py](./pyclient.py) you may need to install the [requests](https://docs.python-requests.org/en/latest/user/install/) library in your Python environment. Both solution scripts require Python 3.6+.

[pyclient.py](./pyclient.py) imitates the various actions that its corresponding server can take and organizes them in a very similar way to the server. From there, all it has to do is send requests to the server and parse the server's response in order to perform the action the server wants in a loop until the server returns a response that can't be split, which is the flag.

[rsclient.py](./rsclient.py) imitates the codes that the server is expecting the client to send in order to communicate with the server. The server chooses pairs of numbers to multiply within an unsigned 32-bit integer and expects the client to do the calculation and submit it. Knowing the server's opcodes and mirroring the structure of the server data is necessary to solve the challenge, and is how the solution script works. Some opcodes are a single byte, while others are four bytes, and the rest of the message contains whatever data is associated with that code. The single-byte opcodes are defined as constants in [opcodes.rs](../challenge/opcodes.rs), while the four-byte codes are defined in the server's main file in the `prepare_response` function.

As an example, when the server sends a pair of values, the message is always 12 bytes in length - 4 for the opcode to indicate that the message is a value pair, and then 4 for each value (the values are unsigned 32-bit integers). The solution script accomplishes the unpacking in `unpack_values`. Then, after the client completes the calculation, it needs to send the response with the submit code first. This is done in `construct_submit` in an infinite `while` loop. In each loop, there is a check if the server has sent the flag code. If so, the client prints the flag and exits the loop.