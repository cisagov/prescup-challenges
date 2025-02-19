Hello agent! Thanks to your hard work draining the target's battery, we have successfully installed a malicious CAN bus device on the target's vehicle at 123.45.67.2

You can receive messages from and send messages to the CAN bus using socketcand with the python-can library. The following line demonstrates how to establish a connection.

  with can.interface.Bus(interface='socketcand', host="123.45.67.2", port=29536, channel="vcan0") as bus:

You can then interact with `bus` object to send/receive messages per the python-can documentation.

Alternatively, you can directly download the CAN bus messages as PCAPS for Wireshark at http://123.45.67.2:5000 
This is useful for analyzing messages, but isn't in real-time and won't let you send them.
The pcaps are captured live and made available every two minutes after the malicious device starts.

The attached Twig_canmsgs.xlsx or Twig_canmsgs.pdf provide a list of the messages we were able to identify so far.
The files are equivalent; use whichever application is more convenient for you.
We could not get a warrant for the manufacturer's details in time, so please remember this is our best attempt at reverse engineering their protocol.
Pay special attention to the Discussion, as our engineers put notes they thought would be important to you.
Also note the coloring scheme in the "Time between msgs" column. For example, messages marked in red repeat rapidly, while green is (relatively) slow.
Messages with blue were noticed when the car was started, and white messages with no time were only noticed once or not at all (but are present in the previous/next year model of the car).