/*
Copyright 2022 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

import java.util.*;
import java.io.*;
import java.lang.Math;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.io.IOException;
import java.nio.file.StandardOpenOption;

public class encrypt
{
    public static void main(String[] args) throws IOException
    {
        int c = 0;                                              //global value that increases with each iteration
        if (args.length != 1)
        {
            System.out.println("Please enter one argument");
            System.exit(0);
        }
        

        String s = args[0];
        if(s.charAt(0) == '-')
        {
            System.out.println("Cannot be a negative number");
            System.exit(0);
        }

        if (s.length() % 2 != 0)
        {
            System.out.println("string must be even length");
            System.exit(0);
        }

	if (s.length() < 2 || s.length() > 20)
        {
            System.out.println("string must be between 2 and 20 characters or less");
            System.exit(0);
	}

        for(int t = 0; t < s.length();t++) // check that string is only digits
        {
            if(Character.isDigit(s.charAt(t)))
            {
                continue;
            }
            else
            {
                System.out.println("String must contain numbers only");
                System.exit(0);
            }
        }

        String en = "";
        while ( s.length() > 0 )   
	    {
	        //int i = s.length();
    
     	    int a = Integer.parseInt(s.substring(0,1));
            int b = Integer.parseInt(s.substring(1,2));
           
	        int c1 = mapping.map(a);
            int c2 = mapping.map(b);

            c += a + b;
            char c3 = mapping.map(c);

            int d = c1 + c2;
            String temp = Integer.toString(d);
            
            temp += c3;

            en+=temp;
            
            s = s.substring(2); 
        }

    FileWriter fileWriter = new FileWriter("encryption.txt");
	fileWriter.write(en);
	fileWriter.close();
    }
}
