/*
Copyright 2022 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

import java.util.*;
import java.io.*;
import java.lang.Math;

public class mapping
{
    public static char map(double num)
    {
        num = num % 26;

        if(num == 23)
        {
            return 'a';
        }
        else if(num == 2)
        {
            return 'b';
        }
        else if(num == 6)
        {
            return 'c';
        }
        else if(num == 10)
        {
            return 'd';
        }
        else if(num == 15)
        {
            return 'e';
        }
        else if(num == 21)
        {
            return 'f';
        }
        else if(num == 0)
        {
            return 'g';
        }
        else if(num == 7)
        {
            return 'h';
        }
        else if(num == 17)
        {
            return 'i';
        }
        else if(num == 3)
        {
            return 'j';
        }
        else if(num == 12)
        {
            return 'k';
        }
        else if(num == 9)
        {
            return 'l';
        }
        else if(num == 20)
        {
            return 'm';
        }
        else if(num == 4)
        {
            return 'n';
        }
        else if(num == 22)
        {
            return 'o';
        }
        else if(num == 13)
        {
            return 'p';
        }
        else if(num == 1)
        {
            return 'q';
        }
        else if(num == 24)
        {
            return 'r';
        }
        else if(num == 16)
        {
            return 's';
        }
        else if(num == 11)
        {
            return 't';
        }
        else if(num == 5)
        {
            return 'u';
        }
        else if(num == 14)
        {
            return 'v';
        }
        else if(num == 19)
        {
            return 'w';
        }
        else if(num == 25)
        {
            return 'x';
        }
        else if(num == 18)
        {
            return 'y';
        }
        else if(num == 8)
        {
            return 'z';
        }
        else
        {
            System.out.println("Unknown character entered, Quitting.");
            System.exit(0);
        }
        return '0';
        
    }
}