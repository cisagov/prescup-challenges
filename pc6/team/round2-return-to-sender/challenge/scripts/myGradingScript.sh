```bash
#!/bin/bash

result=""


# Check malicious user and cronjob
bad_user_check=$(sshpass -p 'tartans' ssh -p 22 -o StrictHostKeyChecking=no user@10.5.5.66 "id 'notme' >/dev/null 2>&1 && sudo crontab -u notme -l | grep -q cp")
bad_user_exit=$?

#check service listenser for port 4444
bad_listener_check=$(sshpass -p 'tartans' ssh -p 22 -o StrictHostKeyChecking=no user@10.5.5.66 "netstat -tuln | grep -q 4444")
bad_listener_exit=$?

#check for persistent file
bad_file_check=$(sshpass -p 'tartans' ssh -p 22 -o StrictHostKeyChecking=no user@10.5.5.66 "find /home/user/Desktop/ -name malicious_file | grep -q "malicious_file"")
bad_file_exit=$?


if [ $bad_user_exit -eq 0 ]; then
    result="$result GradingCheck1: Fail -- Malicious tasks are still running on the machine\n"

else
    result="$result GradingCheck1: Success -- No malicious cronjob found!\n"

fi

if [ $bad_listener_exit -eq 0 ]; then
    result="$result GradingCheck2: Fail -- Malicious listeners are still present on the machine\n"

else
    result="$result GradingCheck2: Success -- Malicious listening ports have been terminated!\n"

fi


if [ $bad_file_exit -eq 0 ]; then
    result="$result GradingCheck3: Fail -- The suspicious file is still found on the Desktop\n"

else
    result="$result GradingCheck3: Success -- The suspicious file has been terminated! Remember to concatenate all tokens when submitting the answer to Question 1!\n"

fi

# Output the grading results
printf "$result"

```