# Spec

This service listens on a default port UDP/8081.

1. **Hex Dump Format**:
    - The provided file is a hex dump of encrypted data.
    - Each line of the hex dump contains the offset, the hex representation of the encrypted data, and the ASCII representation of the encrypted data.
2. **XOR Encryption**:
    - The data has been encrypted using XOR encryption with a specific key.
    - Each byte of the original data was XORed with the key to produce the encrypted data.
3. **XOR Key**:
    - The XOR key used for encryption is `0xAA`.
4. **Decoding Process**:
    - To decode the data, you need to XOR each byte of the encrypted data with the key `0xAA`.
    - This will reverse the encryption and reveal the original data.

### Log Data Format

### 26-Bit Wiegand

| **Bit** | **Meaning** | **Notes** |
| --- | --- | --- |
| 1 | Leading Parity Bit | Even parity for bits 2-13 |
| 2-9 | Facility Code | 8 bits for location/organization |
| 10-25 | Card Number | 16 bits for unique ID |
| 26 | Trailing Parity Bit | Odd parity for bits 14-25 |

### Example: 26-bit Wiegand Frame

### Data

- Facility Code: `42` (binary: `00101010`)
- Card Number: `12345` (binary: `0011000000111001`)

### Step-by-Step Encoding

| **Bit #** | **Purpose** | **Value** | **Details** |
| --- | --- | --- | --- |
| 1 | Leading Parity Bit | 1 | Ensures **even parity** for bits 2-13 (6 ones). |
| 2-9 | Facility Code | `00101010` | Binary representation of `42`. |
| 10-25 | Card Number | `0011000000111001` | Binary representation of `12345`. |
| 26 | Trailing Parity Bit | 1 | Ensures **odd parity** for bits 14-25 (5 ones). |

### Combined Transmission

The complete 26-bit frame sequence is:

`10010101000110000001110011`