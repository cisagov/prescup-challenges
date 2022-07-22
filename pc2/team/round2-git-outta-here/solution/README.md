# Git Outta Here Solution


1. Open a terminal.  Run the following commands:

2. Run the below commands

``` 
git clone http://gitlab.lcl/kowalski/client-service.wiki.git

cd client-service.wiki/
 
git log
```

3. Note the ID of the second commit with a comment about updating Migration.md. Timestamp is Apr 30 6:41:04.


4. Run the following commands:
```
git checkout <commit_id>

cat Migration.md
```
5. Submission token is the password at the bottom of the file.

## Submission

The answer submission for this challenge is the password at the bottom of the Migration.md file. No two instantiations of the challenge are likely to be identical. The answer will be eight hexadecimal digits, all lowercase, like `d0d0caca`.

## Author's Note

The difficult part of this challenge lies in the fact that a gitlab wiki is itself a git repository. The gitlab web application does not make this obvious, nor does its search feature search old versions of files or deleted files. The fictional kowalski user put sensitive data in a wiki page, then deleted it. The only way to recover this information is to know that the wiki is a git repo, clone it, and then scour it for the data. This challenge will probably upset some people, so during QA it will be important to find the right balance of telling them what to look for and how to do so without giving away too much. Some things I think we could say:
*  The password we are looking for is to an old system used before an infrastructure migration
*  The information sought may have been deleted in order to bring the project into compliance with security requirements

Understanding the tools is critical, but understanding what the tools are is more critical. The obvious tool to learn is git. The non-obvious tool to learn is gitlab. They are completely different but both are important. Without knowing that gitlab treats wikis as a git repo, this challenge will be impossible to complete.