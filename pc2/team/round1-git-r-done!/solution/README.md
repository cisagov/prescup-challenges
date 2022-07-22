# Git 'R Done! Solution

Navigate to the client-service repo

From within the repo, use `git log` to view the commit history

Use `git checkout` to load the version of the repository with the commit message "User Improvements"

Browse to `src/main/resources`

Read `application.yml`

Discover the development credentials, `clientdev` and a random password

Browse the source code, specifically `ClientService.java`. Note the switch statement starting at line 45. It checks the length of the submitted contact name and splits it into space-separated words. Then based on the number of words (names) found, it will:
   
    0) no name, return null (possible bug)
   
    1) just save a first name to the database
   
    2) first name and last name saved to database
   
    3+) first name, middle initial, and last names saved to database

The bug is that any name longer than three words is stored incorrectly

Another possible bug is no name, but this case returns null before anything is saved so it won't hit the database

Note that the full name is also stored exactly as it was transmitted to the server. This will help identify the affected row.

Write a query to find a full name consisting of more than three names:
   
    `select full_name from contact order by (LENGTH(full_name) - LENGTH( REPLACE( full_name, ' ', '' ) ) ) DESC limit 1;`

The query will display the element as the last name in the returned value.