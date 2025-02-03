#
# Copyright 2025 Carnegie Mellon University.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
# Licensed under a MIT (SEI)-style license, please see license.txt or contact permission@sei.cmu.edu for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.
#
# This Software includes and/or makes use of Third-Party Software each subject to its own license.
# DM25-0166#

from pymodbus.client import ModbusTcpClient
import time

print("Starting Reactor Client")

client = ModbusTcpClient("10.1.1.125", port=502)
continueChecking = True

while continueChecking:
    try:
        client.connect()

        data = [0]
        data = client.read_holding_registers(0, 1).registers
        print("Read Reactor 1", data)

        data = client.read_holding_registers(1, 1).registers
        print("Read Reactor 1", data)

        data = client.read_holding_registers(2, 1).registers
        print("Read Reactor 1", data)

        client.close()
    except Exception as e:
        print(f"Reactor 1: {e}")

    time.sleep(10.0)


