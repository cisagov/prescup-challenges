import sys, time

DURATION = int(sys.argv[1])
start = time.time()

print("[replay] initialized", flush=True)

while time.time() - start < DURATION:
    print(f"[replay] elapsed: {int(time.time() - start)}s", flush=True)
    time.sleep(5)

print("[replay] completed", flush=True)

