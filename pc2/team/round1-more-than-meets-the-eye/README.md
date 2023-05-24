# More than Meets the Eye

The team must analyze the provided source code to determine how the four flags can be retrieved.
There are four hidden features within the code that, when used, will cause a flag to be displayed.

**NICE Work Role:** 

- [Software Developer](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks:**

- [T0013](https://niccs.cisa.gov/workforce-development/nice-framework) - Apply coding and testing standards, apply security testing tools including \"'fuzzing\" static-analysis code scanning tools, and conduct code reviews.  
- [T0111](https://niccs.cisa.gov/workforce-development/nice-framework) - Identify basic common coding flaws at a high level.  
- [T0436](https://niccs.cisa.gov/workforce-development/nice-framework) - Conduct trial runs of programs and software applications to ensure that the desired information is produced and instructions and security levels are correct. 

## Getting Started

Inside of the [challenge folder](challenge), there is a script called [setup.sh](challenge/setup.sh). This compiles and runs the program you are tasked with analyzing. Run the script before attempting the challenge by using the command: 

```bash
cd challenge && ./setup.sh
```

The program allows the user to search for statistics on players from the four major sports, as well as compare the statistics of two players. When you run the program, you will see a drop-down menu and three text boxes. To search for an individual player's statistics, select the appropriate sport from the drop-down menu, type the player's name into the leftmost text box, and press search. To compare two players, select the appropriate sport, type the players' names into the two rightmost text boxes, and press compare.

Your job is to determine what hidden functionalities exist and how to trigger them by examining the source code of the program. Triggering said functionalities will produce flags.


## Winning Conditions

There are 4 flags and each is worth a percentage of the total possible points. As such, all four must be found for full completion.

Flags are a 12 character sequence of lowercase letters and numbers.
