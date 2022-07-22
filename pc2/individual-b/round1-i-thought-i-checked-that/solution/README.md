# I thought I checked that... Solution

1. Copy the Challenge.elf into a folder on the desktop that will become your work area.

Before trying to exploit the program, you may want to run the command `sudo /home/user/turn_off_random_va_space.sh` to turn off randomized virtual address space.  

1. Run an object dump on the vulnerable program to see the address of the winning function. You will need this address later. `objdump -d challenge.elf | grep func_1`. The 3 bytes at the end of the address are the important part, ignore the leaning 0's.

1. Create a file called input in the same directory as you copied the vulnerable program to. You want to have the number 2 be the contents of the file `echo 2 > input`.

The number in the input file at the start of the program is used to determine how long the program will sleep. Valid numbers for this are 1 or 2, but 2 will make later steps easier.

1. Run the challenge program and wait for execution to finish. It should take approximately 2 seconds. `./challenge.elf`

Notice the number that the program prints the number must equal. This is the number you must change the input file to contain during the sleep period. This is exploiting a Time Of Check Time Of Use (TOCTOU) vulnerability. During the sleep period, you must change the contents of the input file to be the new number.

To exploit this vulnerability, open a different terminal window and prepare the command to change the contents of input file. `echo {num} > input` -- replace {num} with the number your program says it must be.

1. Start running the vulnerable program in one terminal window with `2` in the input file at the start. While the program is running, switch to the other terminal window and run the above command to change the contents of the input file to be the other number. If you do this correctly, the program will move on to the next step that asks you to enter input. The prompt should look like: `Enter a string >`. End the program for now.

1. Now open the challenge program in GDB `gdb ./challenge.elf`. This will help determine the size of the buffer that is to be overflowed.

Make sure the input file has `2` as the contents. Run the program inside GDB by typing `run` then repeat the same TOCTOU process as before to change the contents of the input file while the program is running.

1. When the program shows the input string prompt, type out the alphabet and a small number of additional characters as input `abcdefghijklmnopqrstuvwxyz123`. This string is long enough to overflow the small buffer and will make it easy to recognize where exactly the buffer overwrites the return address on the stack. Enter this string, and notice the address that GDB reports as the address where a Segmentation Fault occurs.

The last 3 bytes of the address where the Segmentation Fault occurs will be where to place the address of the func_1 function that you found earlier.

1. Look up the 3 bytes of the Seg Fault address mentioned before in an ASCII table to see which letters are on the stack at that location. Remove any characters of the string that are after those 3 letters. You will replace those 3 letters with the bytes of the func_1 function address next.

To create an exploit string, it is easy to write a python program which will correctly print the address as input to the vulnerable program. For this example, we can say that the address of the func_1 function is `0x0A0B0C` and the Seg Fault occurred with the bytes `0x6D6E6F` as the last bytes -- this is letters `mno`. We will write the following command to have python generate an exploit string `python -c "print 'abcdefghijkl\x0C\x0B\x0A'" > exploit`.  This creates a file called exploit which contains the contents `abcdefghijkl` followed by the address of the func_1 function in little endian format.

1. Run the challenge program with the exploit file as input. Make sure to also follow the TOCTOU exploit steps as well. This should print the submission token.
