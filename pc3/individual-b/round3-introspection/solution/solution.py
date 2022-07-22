#!/usr/bin/env python

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

# -*- coding: utf-8 -*-

from mainmodule import lookinhere


def main():
    print(f"one: {lookinhere.ExamineMe().one}")

    temp, lookinhere.decode_or_not = lookinhere.decode_or_not, lambda a: True
    print(f"two: {lookinhere.two()}")
    lookinhere.decode_or_not = temp

    d = "8675309"
    a = 2*d
    b = 4*a
    c = 8*b
    print(f"three: {lookinhere.three(a, b, c, d)}")

    print(f"four: {lookinhere.four(329875398726, 'vblvljken', 299792.458)}")


if __name__ == "__main__":
    main()

