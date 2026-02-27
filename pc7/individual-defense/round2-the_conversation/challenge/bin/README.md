# clear.vba

The VBA script used in the malicious document

# datasheet.docm

The malicious document provided to the user. This document was designed to not execute under modern version of word, but creating potentially working versions was explored extensively. It is relatively simple to add content to the document, but none was added since competitors will not gain anything by reading the document itself.

# template.docm

The malicious macro enabled document used as a template containing a stomped vba script. The script will trigger under word 2016 on 64-bit architecture.

# raw-shellcode.bin

The shellcode used in the script