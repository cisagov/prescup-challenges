#!/bin/bash

SRVR='svcnat'
PORT=31337

SKEY='aaaabbbbccccddddaaaabbbbccccdddd'

exp_response () {
	local SND_STR=${1}
	EXP_STR=$(echo -n "${SND_STR::16}${SKEY}${SND_STR:16}" | /usr/bin/md5sum | /usr/bin/cut -d' ' -f1)
	echo $EXP_STR
}

get_response () {
	local SND_STR=${1}
	RCV_STR=$(echo -n ${SND_STR} | /usr/bin/nc -w 6 $SRVR $PORT 2>/dev/null | tr -d '\0')
	echo $RCV_STR
}

# generate and randomize tests (index \in [1..4] are expected to be filtered, i.e. time out):
TESTS=$(for ((i=0; i<10; i++)); do echo "$(./hexstr_gen_test -g $i):$i"; done | /usr/bin/sort)

let VALID=0
let INVAL=0

for TST in $TESTS; do
	STR=${TST::32}
	let MODE=${TST:33}
	RCV=$(get_response $STR)
	if ((MODE<1 || MODE>4)); then
		# "valid" test case (should return valid response):
		EXP=$(exp_response $STR)
		if [ "$RCV" == "$EXP" ]; then
			let VALID++
		fi
	else
		# "invalid" test case (should timeout rather than return FAIL):
		if [ "$RCV" == "TIMEOUT" ]; then
			let INVAL++
		fi
	fi
done

# no points if blocking valid requests:
if ((VALID<6)); then
	printf "GradingCheck1: Fail -- You are blocking valid requests!\n GradingCheck2: Fail\n GradingCheck3: Fail\n GradingCheck4: Fail\n"
	exit 0
fi

result=""

if ((INVAL>0)); then
	result="$result GradingCheck1: Success\n"
else
	result="$result GradingCheck1: Fail\n"
fi

if ((INVAL>1)); then
	result="$result GradingCheck2: Success\n"
else
	result="$result GradingCheck2: Fail\n"
fi

if ((INVAL>2)); then
	result="$result GradingCheck3: Success\n"
else
	result="$result GradingCheck3: Fail\n"
fi

if ((INVAL>3)); then
	result="$result GradingCheck4: Success\n"
else
	result="$result GradingCheck4: Fail\n"
fi

printf "$result"
