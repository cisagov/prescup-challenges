# Double Agent Orange Solution

**Find the Evidence Disk Image**
Open the evidence.iso disk image using your preferred forensic tools

**Find the Chat Logs**
Locate the xchat chat logs in /home/employee/.xchat2/xchatlogs/PC3-#allnitecafe.log
Find the list of agent names in the chat log.

**Look for Deleted PDF Files**
You can use other tools or techniques to recover deleted files. This demonstrates one way to do so using scalpel.
Open /etc/scalpel/scalpel.conf and uncomment the lines for PDF files
scalpel -c /etc/scalpel/scalpel.conf -o deleted_pdfs evidence.dd
Check the output folder for recovered PDF files
You might have to change the permissions to read the files. You can use a command like this: chmod -R 755 deleted_pdfs
Open all pdfs in output folder until you find the list with agent names
The first line of the correct PDF starts with:
Request Number,Requestor Codename,Request Status
Search this file for each of the nine agent names in the chat logs. Each agent will have two lines. The associated Request Numbers are what you need from this file.

**Find the Agent's Real Names in the Database**
Open the database file located in /home/employee/Documents/database_dump with an application such as DB Browser for SQLite.
Query the requests table with the ids found in the deleted PDF and record the requestor ids.
Query the employees table with the requestor ids to get their real names.
Combine the agent's real names and code names in the following format:
firstname.lastname.codename

**Submit Your Answers**
Run the included grading-script.py python grading script
Submit the answers as a single, comma separated string:

Brittney.Lewis.MachineNatural,Christopher.Garcia.ThatAnswer,Erin.Garza.TvSell,Nathan.Tyler.YetHerself,Carrie.Rodriguez.StarIf,David.Lee.StatementSave,Joseph.Woods.RangeSimilar,Christopher.Boyd.SmileCompare,Benjamin.Brown.HimPrice

Example:  
```
python grading-script.py "Brittney.Lewis.MachineNatural,Christopher.Garcia.ThatAnswer,Erin.Garza.TvSell,Nathan.Tyler.YetHerself,Carrie.Rodriguez.StarIf,David.Lee.StatementSave,Joseph.Woods.RangeSimilar,Christopher.Boyd.SmileCompare,Benjamin.Brown.HimPrice"
```  