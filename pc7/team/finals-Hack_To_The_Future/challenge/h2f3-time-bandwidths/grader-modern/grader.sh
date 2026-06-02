#!/bin/bash
echo 'echo pid: $$;echo ppid: $PPID;echo server: $(pgrep server);echo md5: $(md5sum /proc/$(pgrep server)/exe); echo objects: $(grep "/" /proc/$(pgrep server)/maps | wc -l)' | ncat -vi 2s ubuntu.mod.pccc 8080 > /tmp/results.txt
pid=$(grep -w 'pid:' /tmp/results.txt | cut -d ' ' -f 2)
ppid=$(grep -w 'ppid:' /tmp/results.txt | cut -d ' ' -f 2)
server=$(grep -w 'server:' /tmp/results.txt | cut -d ' ' -f 2)
md5=$(grep -w 'md5:' /tmp/results.txt | cut -d ' ' -f 2)
objects=$(grep -w 'objects:' /tmp/results.txt | cut -d ' ' -f 2)

if [[ ($pid == $server || $ppid == $server) && $md5 == 'a4dbf67e8a94daaa27319cf2e8d08193' ]]
then 
    echo "injection check passed"
else 
    echo "grader check failed: not injected"
    exit 1
fi

if [[ $objects -gt 15 ]]
then 
    echo "grader check failed: no loaded objects allowed"
    exit 1
fi

if [[ $(curl http://ubuntu.mod.pccc:8888/welcome.txt | tr -d '\n\r') == "Welcome All Time Travelers!" ]]
then 
    echo "server still functional"
    echo "All checks passed: $TOKEN3"
else 
    echo "grader check failed: server not functional"
    exit 1
fi
