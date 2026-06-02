# Golden Gun

"Mr. Bond, POP chains do not kill. It is the unserialize that pulls the trigger." 
Trapped in ScaraMalware's maze, can you build the POP chain needed to break out? 

**NICE Work Roles**

- [Vulnerability Analysis](https://niccs.cisa.gov/tools/nice-framework)
- [Exploitation Analysis](https://niccs.cisa.gov/tools/nice-framework)

**NICE Tasks**

- [T1359](https://niccs.cisa.gov/tools/nice-framework): Perform penetration testing
- [T1118](https://niccs.cisa.gov/tools/nice-framework): Identify vulnerabilities

## Background

The diabolical ScaraMalware has trapped you, Agent `0b00000111`, in a maze of mirrors and deception. Fortunately, unlike that of his more ruthless cousin, the maze
is just a PHP website... Nonetheless, you must craft a POP chain that can navigate the labyrinth and rescue the lovely Mary GoodByte.   

## Getting Started

Use the provided Kali machine to access the Maze Solving site: `http://mazesolver.pccc`. 

A mirror of the site has been provided as well at `mazesolver.local.pccc`, which you can SSH into with the credentials `user:password`. Unfortunately, the mirror's web server is not running correctly outside the production environment; you'll need to do some tinkering to get it running.

## Tokens

There are three tokens to retrieve. The tokens are formatted as `PCCC{some_words_here}`; check the question placeholder for more guidance.

The tokens can be collected in any order, although they are intended to naturally build upon each other.

No grading is required.

- Token 1: Find and review the `firstToken` class in the source code of the site.
- Token 2: Find and review the `secondToken` class in the source code of the site.
- Token 3: Find and review the `thirdToken` class in the source code of the site.


## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|kali-vnc|user|password|
|mazesolver.local.pccc|user|password|