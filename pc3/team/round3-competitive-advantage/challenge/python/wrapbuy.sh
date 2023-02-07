#!./

#sleep 95

until ./autobuy.py; do
	echo "python crashed while autobuying. respawning..." >&2
	sleep 1
done
