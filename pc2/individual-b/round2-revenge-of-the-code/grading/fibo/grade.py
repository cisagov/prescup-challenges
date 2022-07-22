
# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import os, sys

def fibo(n):
    minus1 = 1
    minus2 = 0
    curr = 0

    for i in range(2, n+1):
        curr = minus1 + minus2
        minus2 = minus1
        minus1 = curr

    return curr
    
def main():
    tok1 = sys.argv[1]
    tok2 = sys.argv[2]
    submitted = open("./grading/fibo/src/functions.rs", "r")
    print("fibo grader running")
    out = os.popen("cargo run")
    args = [line.rstrip() for line in out.readlines()]
    print(args)
   
    i = 0
    partial = False
    while i < len(args):
        time = args[i]
        n = args[i + 1]
        out = args[i + 2]

        print("time = " + str(int(time)))
        print("n = " + n)
        print("out = " + str(int(out)))
        print("fibo(n) = " + str(fibo(int(n))))

        # Fail if test took longer than 250 us or the output was wrong
        if int(time) > 250 or fibo(int(n)) != int(out):
            print(str(int(time) > 250 ))
            print(str(fibo(int(n))))
            print("Sorry, you did not earn any credit.")
            print("Sorry, no credit was earned.\n\n")
            submitted.close()
            sys.exit(1)
        # Good enough for partial credit
        elif time < 250 and time > 25:
            partial = True
        # If runtime was < 25 us and output was right do nothing
        i += 3
    if partial:
        print("partial credit earned")
        print("Token 4 is:" + tok1 + "\n\n")
    else:
        print("full credit earned")
        print("Token 4 is:" + tok1 + " and Token 5 is:" + tok2 + "\n\n")
    submitted.close()

if __name__ == "__main__":
    main()

