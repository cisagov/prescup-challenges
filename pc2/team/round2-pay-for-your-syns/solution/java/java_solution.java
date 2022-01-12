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

public class encryptAns
{
    public static void main(String[] args) throws IOException
    {
        String[] strArr = {"!!","@@@","##","$$$","%%","^^","&&","***","00","111","22","333","44","555","66","777","88","999","99","888","77","666","55","444","33","222","11","000","**","&&&","^^","%%%","$$","###","@@","!!!"};
        char[] charArr = {'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','0','1','2','3','4','5','6','7','8','9'};

        String s = args[0];
        //StringBuilder n = new StringBuilder();
        String ans = "";

        for (int i = 0; i < s.length();i++)
        {
            for (int j = 0; j < strArr.length;j++)
            {
                if (s.charAt(i) == charArr[j])
                {
                    ans = ans + strArr[j];
                    j = strArr.length;
                }
            }
        }
        
    FileWriter fileWriter = new FileWriter("encryption.txt");	//your local file here
	fileWriter.write(ans);
	fileWriter.close();

    }
}
