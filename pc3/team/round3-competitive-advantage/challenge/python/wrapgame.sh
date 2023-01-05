#!./

#sleep 1
sleep 90

/home/student/python/setup.py

sleep 5

/home/student/python/wrapbuy.sh&

until ./game.py; do
	echo "python crashed while running game. respawning..." >&2
	sleep 1
done
