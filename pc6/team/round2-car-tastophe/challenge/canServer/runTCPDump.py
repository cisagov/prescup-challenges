import subprocess
import time
import os

while True:
    try:
        while True:
            subprocess.run("tcpdump -G 120 -W 1 -w /home/user/capt_in_progress/capture-%Y-%m-%d_%H.%M.%S.pcap -i vcan0", shell=True, check=True)
            
            files = sorted(os.listdir("/home/user/capt_in_progress"))

            try:
                src = os.path.join("/home/user/capt_in_progress", files[0])
                dst = os.path.join("/home/user/captures", files[0])
                print(f"Filtering log: {src}")
                # Use tshark to dump dupes (once as sent, once as broadcast; we want to pretend we are only receiving broadcast)
                subprocess.run(f'tshark -Y "!(sll.pkttype == 4)" -r {src} -w {dst}', shell=True, check=True)
                os.remove(src)
            except Exception as e:
                print(f"Error filtering file: {e}")

            # Remove an old pcap, if time 
            files = sorted(os.listdir("/home/user/captures"))
            file_count = len(files)

            if file_count > 5:
                try:
                    first_file = os.path.join("/home/user/captures", files[0])
                    os.remove(first_file)
                    print(f"Deleted log: {first_file}")
                except Exception as e:
                    print(f"Error deleting file: {e}")

            time.sleep(5)

    except subprocess.CalledProcessError as e:
        print("Failed to start due to missing vcan0. Waiting 30 seconds and trying again...")
        time.sleep(30)

