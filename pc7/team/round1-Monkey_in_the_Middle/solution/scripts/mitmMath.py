from mitmproxy import tcp
import re

def tcp_message(flow: tcp.TCPFlow):
    messages = flow.messages
    for message in messages:
        if message.content:
            try:
                text = message.content.decode()
                # Split message into three sections by comma
                parts = text.split(",", 2)
                if len(parts) != 3 or " is " not in parts[2]:
                    continue # Not a packet we want to modify

                # Use regex to pull out the operands and operators
                expr = parts[2]
                match = re.match(r"^(\d+)\s*([+\-*])\s*(\d+)\s+is\s+\d+$", expr.strip())
                if not match:
                    continue # Not a packet we want to modify

                a, op, b = match.groups()
                a, b = int(a), int(b)
                if op == "+":
                    val = a + b
                elif op == "-":
                    val = a - b
                elif op == "*":
                    val = a * b
                else:
                    continue # Unknown expression, shouldn't ever be reached

                new_expr = f"{a} {op} {b} is {val}"  # Recreate expression with right answer
                new_msg = f"{parts[0]},{parts[1]},{new_expr}"  # Rebuild the whole message with new answer
                message.content = new_msg.encode()  # Change the data
            except Exception as e:
                # Just ignore errors for now
                continue