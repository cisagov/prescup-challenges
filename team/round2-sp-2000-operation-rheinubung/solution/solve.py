#!/usr/bin/env python3

"""
Operation Rheinubung - President's Cup Cybersecurity Competition 2019
Challenge

Copyright 2020 Carnegie Mellon University.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
INFRINGEMENT.

Released under a MIT (SEI)-style license, please see license.txt or
contact permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public
release and unlimited distribution.  Please see Copyright notice for
non-US Government use and distribution.

This Software includes and/or makes use of the following Third-Party
Software subject to its own license:

1. gostringsr2 (https://github.com/CarveSystems/gostringsr2/blob/master/LICENSE)
   Copyright 2019 Jonathan Wrightsell.

DM20-0377
"""

import sys
import json
import binascii
import re
import base64

import r2pipe
import re
import argparse


class GoStringsR2Error(RuntimeError):
    pass


class GoStringsR2:

    SUPPORTED_ARCHS = ["arm", "x86"]
    SUPPORTED_BINTYPES = ["elf", "pe", "mach0"]

    def __init__(self, _file, _logging=False):
        """
        Initialize GoStringsR2 with a path to a Binary 
        _file is the path to a file.
        If _logging is True, status messages will be output to standard error.
        """

        self.file = _file
        self.logging = _logging
        self.loaded = False
        self.r2 = None

    def kill(self):
        """
        Closes the r2pipe session
        """

        if self.loaded:
            self.r2.quit()
            self.r2 = None
            self.loaded = False

    def runjson(self, cmd):
        """
        Executes an r2 command that returns a JSON dictionary.
        """

        return self.r2.cmdj(cmd)

    def run(self, cmd):
        """
        Executes an r2 command
        """

        return self.r2.cmd(cmd)

    def load(self):
        """
        Opens the r2pipe session.
        GoStringsR2Error may be thrown if there is an error loading.
        """

        self.log("Loading file into r2: {}".format(self.file))
        self.r2 = r2pipe.open(self.file)
        self.data = {}
        self.data["info"] = self.runjson("ij")
        if "bin" not in self.data["info"]:
            raise GoStringsR2Error("r2 could not parse the binary")

        self.arch = self.data["info"]["bin"]["arch"]
        self.bintype = self.data["info"]["bin"]["bintype"]
        self.bits = self.data["info"]["bin"]["bits"]
        self.binos = self.data["info"]["bin"]["os"]

        if self.bintype not in ["elf", "mach0", "pe"]:
            raise GoStringsR2Error(
                "bintype {} not supported by gostringsr2. Supported: {}".format(
                    self.bintype, GoStringsR2.SUPPORTED_BINTYPES
                )
            )
        if self.arch not in ["arm", "x86"]:
            self.log("warning: arch {} may not fully work".format(self.arch))

        self.data["symbols"] = self.runjson("isj")
        self.data["sections"] = self.runjson("iSj")

        self.loaded = True

        self.log(self.file_info())

    def file_info(self):
        """
        Returns a descriptive string of the loaded binary.
        """

        if self.loaded:
            return (
                "file: {}\n"
                "size: {} KB\n"
                "executable: {}\n"
                "language: {}\n"
                "architecture: {}-bit {}\n"
                "os: {}\n"
                "stripped: {}\n".format(
                    self.data["info"]["core"]["file"],
                    self.data["info"]["core"]["size"] // 1024,
                    self.data["info"]["bin"]["bintype"],
                    self.data["info"]["bin"]["lang"],
                    self.data["info"]["bin"]["bits"],
                    self.data["info"]["bin"]["arch"],
                    self.data["info"]["bin"]["os"],
                    self.data["info"]["bin"]["stripped"],
                )
            )

        return "file: <none>"

    def get_string_table_symbols(self, rdata):
        """
        Returns a dictionary with the raw data from the string table, as found by referencing Go symbols in the provided rdata dictionary.
        """

        g_str = self.find_symbol("go.string.*")
        g_func = self.find_symbol("go.func.*")
        if g_str is not None and g_func is not None:
            g_str["tabsize"] = g_func["vaddr"] - g_str["vaddr"]
            startaddr = g_str["vaddr"] - rdata["vaddr"]
            endaddr = startaddr + g_str["tabsize"]
            g_str["table"] = rdata["data"][startaddr:endaddr]
            return g_str

        return None

    def get_rodata_section(self):
        """
        Returns the first read-only data section in the binary.
        """

        if self.bintype == "elf":
            sname = ".rodata"
        elif self.bintype == "mach0":
            sname = ".__TEXT.__rodata"
        elif self.bintype == "pe":
            sname = ".rdata"
        return self.get_section_data(sname)

    def get_code_section(self):
        """
        Returns the first text/code section in the binary.
        """

        if self.bintype in ["elf", "pe"]:
            return self.get_section_info(".text")
        elif self.bintype == "mach0":
            return self.get_section_info(".__TEXT.__text")
        return None

    def get_string_table_search(self, rdata):
        """
        Returns a dictionary with the raw data from the string table, as found via searching in the provided rdata dictionary.
        """

        self.log("Searching for string table")
        if rdata is not None:
            str_start, str_size = self._find_longest_string(rdata["data"])

            if str_size > 0:
                g_str = {"vaddr": rdata["vaddr"] +
                         str_start, "tabsize": str_size}
                startaddr = g_str["vaddr"] - rdata["vaddr"]
                endaddr = startaddr + g_str["tabsize"]
                g_str["table"] = rdata["data"][startaddr:endaddr]

                return g_str

        return None

    def _find_longest_string(self, bindata):
        off = 0
        this_off = 0
        longest_off = 0
        longest_size = 0

        binlength = len(bindata)
        while off < binlength:
            b = bindata[off: off + 2]
            # Basically, terminate a "string" if 2 null bytes are seen. Seems to work for the most part.
            if b == b"\x00\x00":
                this_size = off - this_off
                if this_size > 0:
                    if this_size > longest_size:
                        longest_off = this_off
                        longest_size = this_size
                this_off = off + 2
            else:
                this_size = off - this_off
                if this_size > 0:
                    if this_size > longest_size:
                        longest_off = this_off
                        longest_size = this_size
            off += 2

        if (off - this_off) > longest_size:
            longest_off = this_off
            longest_size = off - this_off

        if longest_size > 0:
            return (longest_off, longest_size)

        return (None, 0)

    def get_string_table(self):
        """
        Returns the string table either via symbols or via searching.
        """

        rodata = self.get_rodata_section()
        stab_sym = self.get_string_table_symbols(rodata)
        stab_sym = (
            stab_sym if stab_sym is not None else self.get_string_table_search(
                rodata)
        )

        if stab_sym is None:
            return None
        else:
            strtab_start = stab_sym["vaddr"]
            strtab_end = strtab_start + stab_sym["tabsize"]
            self.log(
                "String table at 0x{:x} thru 0x{:x}".format(
                    strtab_start, strtab_end)
            )
            strtab = {
                "startaddr": strtab_start,
                "endaddr": strtab_end,
                "data": stab_sym["table"],
            }
            return strtab

    def find_symbol(self, symbol_name):
        """
        Returns a symbol in the binary as a dictionary, as retrieved with r2.
        """

        for sym in self.data["symbols"]:
            if sym.get("name", "") == symbol_name:
                return sym
        return None

    def get_cross_refs(self):
        """
        Performs the cross-references search and returns results in r2 quiet/human-readable format.
        """

        xrefs = None

        # Only check .text; other executable sections may get searched otherwise
        # If more than one .text section exists, changeme
        code_section = self.get_code_section()
        if code_section is not None:
            c_start = code_section["vaddr"]
            c_end = c_start + code_section["size"]
            self.log(
                "Limited cross-ref check from 0x{:x} to 0x{:x}".format(
                    c_start, c_end)
            )
            self.run("e search.from=0x{:x}".format(c_start))
            self.run("e search.to=0x{:x}".format(c_end))

        cross_ref_cmd = "/ra"
        # Use ESIL analysis for non-x86 architectures
        if self.arch != "x86":
            cross_ref_cmd = "aae"
        # send stderr from r2 to /dev/null to hide r2's address progress
        self.run("{} 2>/dev/null".format(cross_ref_cmd))
        xrefs = self.run("axq")
        return xrefs

    def get_section_info(self, section_name):
        """
        Returns the section info of section_name, as retrieved with r2.
        """

        for secobj in self.data["sections"]:
            if secobj["name"].endswith(section_name):
                return secobj
        return None

    def get_section_data(self, section_name):
        """
        Returns a dictionary containing the raw binary data of the requested section.
        """

        secobj = self.get_section_info(section_name)
        if secobj is not None:
            s_base = secobj["vaddr"]
            s_size = secobj["vsize"]
            rdsize = 4096
            i = 0
            sdata = b""
            while s_size > 0:
                c = "p8 {} @0x{:x}".format(
                    min(rdsize, s_size), s_base + i * rdsize)
                sdat = self.run(c).strip()
                sdata += binascii.unhexlify(sdat)
                i += 1
                s_size -= rdsize

            return {"name": section_name, "vaddr": s_base, "data": sdata}
        return None

    def find_strings(self, minlength, encoding, refs, tablebase, tabledata):
        """
        Processes cross-references and returns a list of string objects.
        Each string object in the returned list is a list specifying address, decoded length, decoded string value, string size in bytes, list of code references to this string.
        """

        # refs.keys() = dest address, refs.values() = list of source addresses
        refs_addrs = sorted(refs.keys(), reverse=True)

        all_strings = []
        for r in refs_addrs:
            # r = virtual addr of a string
            # subtract vaddr of section to get offset into
            r_offset = r - tablebase
            if len(all_strings) > 0:
                last_ref = all_strings[len(all_strings) - 1][0] - tablebase
                r_end_offset = last_ref
            else:
                r_end_offset = len(tabledata)

            r_str = tabledata[r_offset:r_end_offset].decode(
                encoding, errors="ignore")
            decoded_len = len(r_str)
            all_strings.append(
                [
                    tablebase + r_offset,
                    decoded_len,
                    r_str,
                    r_end_offset - r_offset,
                    refs[r],
                ]
            )

        # filter all_strings by length requirement, then reverse order
        # since all_strings started at the end
        return list(reversed([s for s in all_strings if s[1] >= minlength]))

    def _is_a_string_ref(
        self, src_addr, dst_addr, strtab_addr, strtab_endaddr, code_section
    ):
        if dst_addr >= strtab_addr and dst_addr < strtab_endaddr:
            if code_section is None:
                return True
            else:
                return src_addr >= code_section["vaddr"] and src_addr < (
                    code_section["vaddr"] + code_section["size"]
                )

        return False

    def process_xrefs(self, xrefs, strtab_start, strtab_end):
        """
        Filters cross-references to only references to the string table.
        xrefs is data returned by r2 from "axq" (quiet/human-readable format), strtab_start/end specify the addresses of the string table.
        """

        str_refs = {}

        code_section = self.get_code_section()

        # 0x01640839 -> 0x016408a9  CALL
        for line in xrefs.split("\n"):
            lparts = line.split(" ")
            # 0 = src, 1= arrow, 2 = dst, 3=empty, 4=type
            if len(lparts) == 5:
                r_src = int(lparts[0], 16)
                r_dst = int(lparts[2], 16)
                if self._is_a_string_ref(
                    r_src, r_dst, strtab_start, strtab_end, code_section
                ):
                    if r_dst in str_refs.keys():
                        str_refs[r_dst].append(r_src)
                    else:
                        str_refs[r_dst] = [r_src]

        return str_refs

    def log(self, log_msg, *args, **kwargs):
        if self.logging:
            print("\033[92m" + log_msg + "\033[0m",
                  *args, **kwargs, file=sys.stderr)

    def get_strings(self, minlength, encoding="ascii"):
        """
        Perform the string search, returning string objects.
        minlength specifies the minimum length of a string that will be returned.
        encoding specifies how bytes should be decoded, with "ascii" being the default.
        """

        ret_strings = []

        self.log("Locating string table...")
        strtab = self.get_string_table()
        if strtab is None:
            raise GoStringsR2Error(
                "couldn't find the Go string table in the binary")

        self.log("Retrieving cross references...")
        xrefs = self.get_cross_refs()
        if xrefs is None:
            raise GoStringsR2Error("r2 returned no cross-references")

        self.log("Locating string references...")
        str_refs = self.process_xrefs(
            xrefs, strtab["startaddr"], strtab["endaddr"])

        self.log("Retrieved {} references to the string table".format(len(str_refs)))
        if len(str_refs):
            ret_strings = self.find_strings(
                minlength, encoding, str_refs, strtab["startaddr"], strtab["data"]
            )

        self.log("Found strings: {}".format(len(ret_strings)))
        return ret_strings


parser = argparse.ArgumentParser(description='Read go binaries like a boss')
parser.add_argument('-f', '--file', help='binary to read...', required=True)

args = parser.parse_args()

if not args.file:
    print("Supply a file name")
    exit(9)

f = args.file

g = GoStringsR2(f, True)
g.load()
encoding = "ascii"

o_strings = g.get_strings(100, encoding)
print(o_strings)
