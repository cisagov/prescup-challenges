#!/usr/bin/env python3
import os
import sys

FILE = "/opt/playbooks/system_check_playbook.yml"

BLOCK = """- name: System Check on Ops Stations
  hosts: all
  vars:
    ansible_ssh_common_args: "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
  tasks:
    - name: Gather Facts
      ansible.builtin.gather_facts:"""

def file_contains_block(path, block):
    #Return True if block exists as contiguous lines in file.
    if not os.path.exists(path):
        return False

    with open(path, "r") as f:
        content = f.read().splitlines()

    block_lines = block.splitlines()
    n = len(block_lines)

    for i in range(len(content) - n + 1):
        if content[i:i+n] == block_lines:
            return True
    return False

def main():
    if file_contains_block(FILE, BLOCK):
        print(f"Success: Block is present in {FILE}")
        sys.exit(0)
    else:
        print(f"Fail: Block does not exist in {FILE}")
        sys.exit(1)

if __name__ == "__main__":
    main()
