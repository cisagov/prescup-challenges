# Imitation Something Something Flattery Solution

## Walkthrough

1. (Optional) Start Wireshark and begin a packet capture.
1. (Optional) Copy the attached executable to the desktop and run it.
1. (Optional) In Wireshark, after about 30 seconds, there will be traffic to port 22 on a remote host, indicating probable SSH traffic. Also note the IP address.
1. (Optional) Knowing that there is SSH traffic, this means that there is either an embedded key string, or a username and password combination being used to log in.
1. Open IDA and navigate to View -> Strings in the menu at the top left. Look through the list for a string fitting the above description.
1. (Optional) As a shortcut for this solution guide, right click and click Quick Filter to start a search for "loggeruser" to narrow the search.
1. The password "ugiefkeys" immediately follows the username "loggeruser".
1. Now, right click on the desktop and click Git Bash.
1. In the Git Bash window, type `ssh loggeruser@10.5.5.10`, and then type the password to log in to the remote host.
1. Type `cat ~/submission.txt` to get the first token.
1. (Optional) Now, open the script in loggeruser's home directory and note that the machine you are logged into is only temporarily holding the logs.
1. Make a copy of the script, and comment out the line that says `main()` at the bottom.
1. (Optional) Add the following function under the existing `push_keys()` function:
    ```
    def list_databases():
        with psycopg2.connect("host=10.10.10.11 dbname=logsdb user=logsuser password=logallthethings") as conn:
            with conn.cursor() as cursor:
                cursor.execute("select * from pg_catalog.pg_database;")
                print(cursor.fetchall())
    ```
1. (Optional) Add the line `list_databases()` below the call to `main()` you commented earlier and run the script with `python3 store_keylogs.py`.
1. The previous step reveals the names of every database in the system. The relevant one is `flagdb`.
1. (Optional) Add the following function under the `list_databases()` function you added (note the connection string change):
    ```
    def list_tables():
        with psycopg2.connect("host=10.10.10.11 dbname=flagdb user=logsuser password=logallthethings") as conn:
            with conn.cursor() as cursor:
                cursor.execute("select table_schema, table_name from information_schema.tables where table_catalog = 'flagdb' and table_schema = 'public'")
                print(cursor.fetchall())
    ```
1. As above, add a call to the `list_tables()` function after the call to `list_databases()`. You can comment out `list_databases()` if you want.
1. Again, run the script and note the output. There is only one record returned with the table name `flagtab`.
1. Finally, add the following function under the `list_tables()` function:
    ```
    def list_tables():
        with psycopg2.connect("host=10.10.10.11 dbname=flagdb user=logsuser password=logallthethings") as conn:
            with conn.cursor() as cursor:
                cursor.execute("select * from flagtab")
                print(cursor.fetchall())
    ```
1. Again, call the above function at the end of your script, and it should return the second flag.

## Source Code Note

The client source code was forked from [this repository](https://github.com/thomaslienbacher/win-keylogger-rs).