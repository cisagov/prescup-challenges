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
    public static char mapper( String en )
    {
        String[] strArr = {"!!","@@@","##","$$$","%%","^^","&&","***","00","111","22","333","44","555","66","777","88","999","99","888","77","666","55","444","33","222","11","000","**","&&&","^^","%%%","$$","###","@@","!!!"};
        char[] charArr = {'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','0','1','2','3','4','5','6','7','8','9'};


        for (int i = 0; i < strArr.length;i++)
        {
            if (en.equals(strArr[i]))
            {
                return charArr[i];
            }
        }

        return '?';
    }
}
