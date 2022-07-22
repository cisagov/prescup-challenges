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
import java.lang.*;

public class decrypt2 
{
    public static void main(String[] args) throws IOException
    {
        String plain = "";

        if (args.length != 1)
        {
            System.out.println("Please only enter one argument to be decrypted");
            System.exit(0);
        }
        
        StringBuilder s = new StringBuilder(args[0]);     //get encrypted string
	    s.append("-");
        int cnt = 0;        //counts how many letters in a row there are, will take off that many of string to continue loop
        char curr;
        boolean str = false;      //kept false until entire string is read, when done == true
        int strlen = s.length();        //get length of string
        int strcnt = 0;                 //make sure youre never reaching past the end of the string

        while (str == false)
        {   
            String curr1 = "";                 //here for reset
            curr = s.charAt(0);  	    //get first character
	    if (curr =='-')
	    {
		    System.out.println("Decrypted string is complete");
		    str = true;
		    break;
	    }
	    curr1 += curr;               //create string that needs to be mapped and decrypted via the connected class
        cnt = 1;
        strcnt++;
            
        if ((strcnt <= strlen) && (curr != '='))    //see if there is any string left
        {
            if (curr == s.charAt(1))    //if so, see if it has the same character following it
            {
                cnt = 2;
                curr1 += curr;
                strcnt++;
            }
            if (strcnt < strlen)        //check for end of string
            {
                if (curr == s.charAt(2))    //if so, see if there is a 3rd one trailing
                {
                    strcnt++;
                    cnt = 3;
                    curr1 += curr;
                }
		    if ((strcnt+2) <= strlen)  
		    {
		    	if ((curr == s.charAt(3)) && (curr != s.charAt(4)))
		    	{
		    		curr1 = curr1.substring(0,curr1.length() - 1);
				    cnt--;
		    	}
		    }
                }  

            }
            
	        char p = mapping.mapper(curr1);
	    

            if (p == '?')
            {
              	System.out.println("Entered a unknown sequence of characters, please fix your argument and try again");
               	System.exit(0);
            }

            plain += p;
            	
	        while (cnt != 0)
            {
               	s.deleteCharAt(0);
               	cnt--;
            }
	    }
	
	FileWriter fileWriter = new FileWriter("decryption.txt");
	fileWriter.write(plain);
	fileWriter.close();
    }
}
