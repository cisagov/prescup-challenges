#!/bin/bash
#vsftp script
vsftp_check_failed=0
for i in 02 03
do
    vsftpdpid=$(ssh -o StrictHostKeyChecking=no root@ubuntu$i pgrep vsftpd)
    if [[ $(ssh -o StrictHostKeyChecking=no root@ubuntu$i ls -la /proc/$vsftpdpid | grep '(deleted)' | wc -l) != 0 ]]
    then
        echo Token1: vsftp check failed > /tmp/results.txt
        vsftp_check_failed=1
        break
    fi
done
if [[ $vsftp_check_failed == 0 ]]
then
    echo Token1: vsftp check passed > /tmp/results.txt
fi

#apache mod
apache_mod_failed=0
for i in 05 07
do
    apachepid=$(ssh -o StrictHostKeyChecking=no root@ubuntu$i pgrep apache2 | head -1)
    if [[ $(ssh -o StrictHostKeyChecking=no root@ubuntu$i cat /proc/$apachepid/maps | grep authx | wc -l) != 0 ]]
    then
        echo Token2: apache mod check failed >> /tmp/results.txt
        apache_mod_failed=1
        break
    fi
done
if [[ $apache_mod_failed == 0 ]]
then
    echo Token2: apache mod check passed >> /tmp/results.txt
fi

#check if dev server has r-x mem region
dev_server_failed=0
for i in 01 05
do
    dev_pid=$(ssh -o StrictHostKeyChecking=no root@ubuntu$i pgrep http_dev_server)
    if [[ $(ssh -o StrictHostKeyChecking=no root@ubuntu$i grep -v vdso /proc/$dev_pid/maps | grep 'r-xp 00000000 00:00 0' | wc -l) != 0 ]]
    then
        echo Token3: dev server injection check failed >> /tmp/results.txt
        dev_server_failed=1
        break
    fi
done
if [[ $dev_server_failed == 0 ]]
then
    echo Token3: dev server check passed >> /tmp/results.txt
fi

#check if eviluser exists and check if service script exists
init_service_failed=0
for i in 04 10
do
    if [[ $(ssh -o StrictHostKeyChecking=no root@ubuntu$i grep eviluser /etc/passwd | wc -l) != 0 || $(ssh -o StrictHostKeyChecking=no root@ubuntu$i ls -la /etc/init.d/ | grep -Ev "apache2|htcache" | grep apache | wc -l) != 0 ]]
    then
        echo Token4: init service check failed >> /tmp/results.txt
        init_service_failed=1
        break
    fi
done
if [[ $init_service_failed == 0 ]]
then
    echo Token4: init service check passed >> /tmp/results.txt
fi

#get login md5sum, should be 810e21e04351963c67ef5f1884b00e3c
login_wrapper_failed=0
for i in 04 06 07
do
    if [[ $(ssh -o StrictHostKeyChecking=no root@ubuntu$i md5sum /usr/bin/login | cut -d ' ' -f 1) != '810e21e04351963c67ef5f1884b00e3c' ]]
    then
        echo Token5: login wrapper check failed >> /tmp/results.txt
        login_wrapper_failed=1
        break
    fi
done
if [[ $login_wrapper_failed == 0 ]]
then
    echo Token5: login wrapper check passed >> /tmp/results.txt
fi

#crypt
crypt_failed=0
#for i in 01 02 03 04 05 06 07 08 09 10
for i in 02 10
do
    for j in $(ssh -o StrictHostKeyChecking=no root@ubuntu$i ls /var/log)
    do
        if [[ $(ssh -o StrictHostKeyChecking=no root@ubuntu$i hexdump -C /var/log/$j 2>/dev/null | grep 'de ad c0 de' 2>/dev/null | wc -l) != 0 ]]
        then
            echo Token6: crypt check failed >> /tmp/results.txt
            crypt_failed=1
            break
        fi
    done
done
if [[ $crypt_failed == 0 ]]
then
    echo Token6: crypt check passed >> /tmp/results.txt
fi

#get vclient md5sum, should be 63f0ffc87458ad4e719d712e170787ef
vclient_failed=0
for i in 09
do
    if [[ $(ssh -o StrictHostKeyChecking=no root@ubuntu$i md5sum /usr/local/bin/velociraptor_client | cut -d ' ' -f 1) != '63f0ffc87458ad4e719d712e170787ef' ]]
    then
        echo Token7: velociraptor client check failed >> /tmp/results.txt
        vclient_failed=1
        break
    fi
done
if [[ $vclient_failed == 0 ]]
then
    echo Token7: velociraptor client check passed >> /tmp/results.txt
fi

#check if attacker can ssh
watchdog_check_failed=0
for i in 09
do
    cmd=$(ssh -o StrictHostKeyChecking=no root@attacker /grade.sh 2>/dev/null)
    count=$(echo $cmd | grep "check passed" | wc -l)
    c=$(echo $count)
    if [[ $c == 0 ]]
    then
        echo Token8: watchdog check failed >> /tmp/results.txt
        watchdog_check_failed=1
        break
    fi
    cmd=$(ssh -o StrictHostKeyChecking=no root@ubuntu$i ps -elf)
    count=$(echo $cmd | grep "sshd: root@pts/0" | grep -v "defunct" | wc -l)
    c=$(echo $count)
    if [[ $c != 0  ]]
    then
        echo Token8: watchdog check failed >> /tmp/results.txt
        watchdog_check_failed=1
        break
    fi
    cmd=$(ssh -o StrictHostKeyChecking=no root@ubuntu$i ps -elf)
    count=$(echo $cmd | grep "watchdog" | grep -v "defunct" | wc -l)
    c=$(echo $count)
    if [[ $c != 0 ]]
    then
        echo Token8: watchdog check failed >> /tmp/results.txt
        watchdog_check_failed=1
        break
    fi
done
if [[ $watchdog_check_failed == 0 ]]
then
    echo Token8: watchdog check passed >> /tmp/results.txt
fi

#grep lib
#/usr/bin/grep md5sum good abe14df35a44efa22ca3f3bf719cc286
grep_lib_failed=0
for i in 09
do
    if [[ $(ssh -o StrictHostKeyChecking=no root@ubuntu$i ldd /usr/bin/grep | grep /lib64/ld-linux-x86-64.so.1 | wc -l ) != 0 || $(ssh -o StrictHostKeyChecking=no root@ubuntu$i ps -elf | grep 'ncat -klp 8080 -e /bin/sh' | grep -v grep | wc -l) != 0 ]]
    then
        echo Token9: grep lib check failed >> /tmp/results.txt
        grep_lib_failed=1
        break
    fi
done
if [[ $grep_lib_failed == 0 ]]
then
    echo Token9: grep lib check passed >> /tmp/results.txt
fi

grep "check passed" /tmp/results.txt > /tmp/passed.txt
count=$(grep "check passed" /tmp/results.txt | wc -l)
echo "$count/9 checks passed"
cat /tmp/passed.txt
if [[ $count == 9 ]]
then
    # echo PCCC{token_10_remediation_grader}
    echo $TOKEN10
fi