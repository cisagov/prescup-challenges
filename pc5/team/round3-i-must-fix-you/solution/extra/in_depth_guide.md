# I Must Fix You 

*Detailed Solution Guide*

In *I Must Fix You*, players must perform binary analysis on corrupt files to recover data contained in those files. As with all open-sourced President's Cup challenges, *I Must Fix You* comes with a solution guide. There is so much material to cover related to solving *I Must Fix You* we felt that a supplemental, more in-depth solution guide was warranted. That's what this is.

For any file editing you do, it is recommended you use a **hex editor**. The GNOME Hex Editor, **Ghex**, is used for the purposes of this solution guide. 

Many hex editors start in "overwrite" mode. This means that if you type a character while the editor is in this mode, it will replace (overwrite) the character at the current cursor position with the one you've typed, rather than inserting it. In Ghex, you can switch to "insert mode" by pressing the `insert` key on your keyboard. 

Use the  `apt` package manager to install the Ghex software.

```
sudo apt-get install ghex
```

## Question 1: Repairing the PDF

Question 1 asks: *What is the 8-character hex string found in the PDF after successfully repairing it?*

This section of the solution guide is further divided into four parts. They are:

1. Understanding PDF Syntax and Structure
2. Determining the Cause of Corruption
3. Fixing the PDF
4. Alternate Method

### 1. Understanding PDF Syntax and Structure

To understand how to fix the PDF, you need to understand how it works. Here are some helpful resources. They are referred to in other sections of the solution guide as well.
- [PDF file format: Basic structure](https://resources.infosecinstitute.com/topics/hacking/pdf-file-format-basic-structure/)
- [Basic Structure of Portable Document Format (PDF)](https://medium.com/aia-sg-techblog/basic-structure-of-portable-document-format-pdf-79db682579c9)

### 2. Determining the Cause of Corruption

The content of a PDF is shown on the layout and structure of the **Cross Reference Table** (the xref table) at the end of a PDF. The xref table has multiple entries, where each entry represents an object in the PDF and that entry contains specific information to the object it is mapped too. Objects can include text streams, images, or other multimedia elements. For more information, see the section "xref table" in [this guide](https://resources.infosecinstitute.com/topics/hacking/pdf-file-format-basic-structure/). Note these key concepts:

- xref indicates the start of the xref table
- two numbers after the  xref indicator are the number of entries in the xref table
- offset value and how it is presented
- generation number
- free VS in use entries

Consider how the PDF is read and presented based on the links/pointers from the xref table to the actual objects in the PDF. Then, look at each object location using the xref table entries in the offset location.

To help understand the layout of objects, please read the first two paragraphs under **Indirect objects** in [this guide](https://resources.infosecinstitute.com/topics/hacking/pdf-file-format-basic-structure/).

Objects or *indirect objects* are represented by the keywords obj and endobj. obj is used in the first line to indicate the start of the object and is accompanied by two numbers used as object ID. See the example below.

2 0 obj is the starting indicator of the object where:

- `2` represents the `ID` of this object, also referenced in the xref table
- `0` represents the generation number of this object, as also referenced in the xref table
- `obj` is the last part of this object ID line and indicates the start of the current object's data

Endobj indicates when the current object ends and should stop being read.

If you look through our PDF, you will see there are many references to endobj, but the starting keyword obj seems to be missing from each entry. ***This is why the PDF can't be read and is corrupted!***

### 3. Fixing the PDF

Because of this, you need to write in the correct starting key words for each object. See the example below showing an xref table and the objects it points to.

```
xref
0   5 -- `0` indicates the starting ID of the first object, and the `5` tells us there are `5 entries` that map to 5 objects in the PDF.
0000000000 65535 -- `free` entry with `65535` generation number is often the first entry used to map to other `free` objects that may be listed.
0000000745 00000 n
0000000029 00000 n
0000000574 00000 n
0000000912 00000 n
```

Entries in the xref table don't need to be presented in a specific order nor do they need to map to the objects in the order of how they appear in the PDF.

Reading the above xref table: the first entry, `0000000000 65535 f`, would have an `ID` of `0` because it's the first. But, since it is labeled as `free` (`f`) it does not have an object that it represents in the PDF and so can be skipped.

Next, the line `0000000745 00000 n`: this entry would have an `object ID` of `1` because it is the next entry in the xref table. Its generation number is `00000` or just `0`. So, if you went to the objects location indicated by the offset number `745`, you will see this object ID line shown as: `1 0 obj`.

Following this method, determine what the `Object ID line` should be for each entry in the xref table. Below is the mapping.

```
xref
0   5
0000000000 65535 -- No entry
0000000745 00000 -- 1 0 obj
0000000029 00000 -- 2 0 obj
0000000574 00000 -- 3 0 obj
0000000912 00000 -- 4 0 obj
```

Now that you know where each object is (based on the entry's offset) and the `object ID line` for each entry, add them back into the PDF.

>**Warning!** You can't just add them back in any order; there is a specific process to follow.

Because each object location is based on the offset, and the offset is represented as *the number of bytes from the beginning of the file*, you must add each entry's object ID line starting with the entry with the lowest offset and ending with the largest offset. 

If this order is *not* followed, the offsets won't match up with each object and the PDF  remains corrupted. 

Following the example above, the `object ID line` order for each object is:

1. `2 0 obj`
2. `3 0 obj`
3. `1 0 obj`
4. `4 0 obj`

Follow the same methodology outlined above to fix the PDF manually and retrieve your token from the file.

### 4. Alternate Method

You could create a script to automate reading the xref table and inserting the object ID lines. An exemplar Python script to do this can be found [here](script/fix_pdf.py).

## Question 2: Repairing the ZIP

Question 2 asks: *What is the 8-character hex string found in the ZIP after successfully repairing it?*

This section of the solution guide consists of four parts. They are:

1. Understanding ZIP Syntax and Structure
2. Determining the Cause of Corruption
3. Fixing the ZIP
4. Alternate Method

### 1. Understanding ZIP Syntax and Structure

To understand how to fix the ZIP,  you need to understand how it works. Here are some helpful resources we'll refer to in the solution guide below.

- [FILEFORMAT ZIP Information](https://docs.fileformat.com/compression/zip/)
- [The structure of a PKZip file](https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip-printable.html)

The structure of a ZIP file is relatively straightforward from a high level. The **General structure** image at the beginning of [this article](https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip-printable.html) gives you a basic understanding of how the ZIP is formatted. It consists of three main parts:

1. Local file header records
2. Central directory records
3. End of Central directory record

For both the Local File Header and `Central Directory` sections, the records are created and stored in the same order they are added to the ZIP. So, for example: if the command `zip example.zip file1 file2 file3` was run, then the order the records are stored would be:

- file1
- file2
- file3

#### Local File Header Records

>**Important!** All values are stored in little-endian byte order where the field length counts the length in bytes.

The ZIP starts with the local file header records. For every file in a ZIP, there is a corresponding local file header record. It is possible there are records present for files since removed from a ZIP, but that scenario does not occur in this challenge.

Review **Local file headers** on [this page](https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip-printable.html). There is an image showing the structure of each Local File Header Record in the ZIP. Review the **Local File Header** section in [this article](https://docs.fileformat.com/compression/zip/#local-file-header). It elaborates further on the Local File Header structure. 

The first 30 bytes of every record is the same structurally. The extra field section of the record can change for many reasons. For this challenge, understanding the extra fields is not necessary. Important information, required for solving, from those two resources is:

- The signature used for all local file header records is represented as `0x04034b50`. Represented in hex as: `\x50 \x4b \x03 \x04`.
- The offsets are written relative *to the start of its own record*.
- The offset and number of bytes used for storing the file name length are:
  - offset = 26
  - num. of bytes = 2
- The offset and number of bytes used for storing the file name are:
  - offset = 30
  - num. of bytes = n, where *n* is the length of the file name stored for that record

#### Central Directory Records

>**Important!** All values are stored in little-endian byte order where the field length counts the length in bytes.

Similar to the local file header records, there should be a corresponding central directory record for every file present in the ZIP. Each file's central directory record contains some of the same information as its associated local file header, but it will have more data because it is the main part of the file's storage. 

Review the **Central directory file header** topic on [this page](https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip-printable.html). Here, you will see another image showing the layout of a central directory record. Review the **Central Directory File Header** topic [here](https://docs.fileformat.com/compression/zip/#central-directory-file-header). It elaborates further on the central directory records structure.

The first 46 bytes of every record is structurally the same; the extra field section of the record can change. For *I Must Fix You*, understanding the extra fields isn't necessary. However, it is important to note the `File Comment` part at the very end of the record.

Important information, required for solving, from those two resources is:

- The signature used for all central directory records is represented as `0x02014b50`. Represented in hex as: `\x50 \x4b \x01 \x02`.
- The offsets are written relative *to the start of its own record*.
- The offset and number of bytes used for storing the central directory file header signature are:
  - offset = 0
  - num.  of bytes = 4
- The *offset* and the *number of bytes used for storing relative offset of local header* are as follows. This is the number of bytes between the start of the first disk on which the file occurs and the start of the local file header. This allows software reading the central directory to locate the position of the file inside the ZIP file.
  - offset = 42
  - num. of bytes = 4
- The offset and number of bytes used for storing the file name:
  - offset = 46
  - num. of bytes = n, where *n* is the length of the file name stored for that record.
- The location of a File Comment in the record is always the last entry in a record.

#### End of Central Directory Record

This is always a singular record and doesn't contain a lot of information. It stores information on the start of the central directory so ZIP readers know where to find it.

Additional information can be found in the **End of central directory record topic** on [this page](https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip-printable.html) and [here](https://docs.fileformat.com/compression/zip/#end-of-central-directory-record) under **End of Central Directory Record**.

Important information, required for solving, from those two resources is:

- The signature used for all central directory records is represented as `0x05064b50`. Represented in hex as: `\x50 \x4b \x05 \x06`. 
- The *offset* and *number of bytes* used to store information about the number of central directory records on this disk are:
  - offset = 8
  - num. of bytes = 2
- The *offset* and *number of bytes* used to store information about the offset of start of central directory relative to start of archive are:
  - offset = 16 
  - num. of bytes = 4

### 2. Determining the Cause of Corruption

Prior to analyzing the file, we can run some commands against the ZIP to see what information can be gleaned from it. Run the command:

```
zipinfo corrupt.zip
```
The most notable information you get is:

- missing 70 bytes in zipfile
- start of central directory not found

Remember this as you examine the ZIP file. 

Open the **corrupt.zip** in the hex editor (**ghex** is used in this guide) of your choice. The first step is to look for the signatures used to identify any records in the ZIP. The signatures are present for all the local file header records and the end of central directory record, but it appears there are no signatures present for any central directory records. 

Since you know the filenames that should be present in this ZIP, you should notice that no filenames are present. Seeing all of this missing information means you can start to fix it.

### 3. Fixing the ZIP

#### Reading information.txt

Make sure you have read the **information.txt** file. It has important information about the ZIP file. For instance, it states that the following filenames were added to the ZIP in this order:
1. joyous
2. whimsical
3. bingo
4. sad

This will be useful later on.

#### Fixing Local File Header Records

All information in any record is stored based on offset values, and you've already determined that 70 bytes are missing. Now, you will (re)insert the missing data, starting from the beginning.

At the first byte of the file, you can see the signature matches that of a local file header record. Based on the order the files were added to the ZIP the first record filename should be `joyous`.

Confirm this by looking at the section of the current local file header record that maps to the filename length found at `offset 26`; number of bytes `2`.

Looking at that, you know it isn't the correct value. File name length is represented as the hex value matching the length of the filename. E.g.: 

- the first file name is `joyous`
- the length is `6`
- the hex is: `06 00` because it is read in little endian

Considering this information is incorrect, and there are missing bytes, you know you must insert those hex values mentioned above.

Once you have done so, go to the file name location at offset `30` and insert that filename `joyous`. You can type the text in the ASCII section of the hex editor. It can also be done by inserting the hex equivalent into the editor.

Now that the first local file header record is fixed follow the same procedures for the three remaining local file header records using the corresponding filename for each record.

#### Fixing Central Directory Records

Since the signature bytes to indicate the start of a central directory record are missing, you need to depend on the end of the central directory record to find it. You should have this value from the information found in the end of the central directory record section above.

Once you are in the correct location for the first end of central directory record, insert the corresponding signature: `\x50 \x4b \x01 \x02`.

Reinsert the File name for this record. Using the information found above, go to the location at offset `46` and insert the file name `joyous`. Do this by inserting the hex byte equivalent to the filename into the hex code or inserting the ASCII characters in the ASCII section of the hex editor.

The first central directory record is fixed, but to find the correct starting point of the next record you need to analyze the ASCII text. Above, we noted that for these records "comments" are the final entry, so using this information you should see some strings that are readable. 

You should see the string "little happy icon" which is the comment for this record. Add the signature for the next entry immediately after the comment. 

Following this method, fix the other three central directory records using the corresponding filenames for each record.

#### Verify and Get Token

If you have done everything correctly, you can verify by running the command `zipinfo corrupt.zip`. If it has been repaired correctly, it will present information about the files in the ZIP.

Run the command `unzip corrupt.zip` and open the file `bingo`. The token for this part of the challenge is in this file.

### 4. Alternate Method

An alternate method is to write a script to automate reading the ZIP bytes to insert the missing data. An exemplar Python script to do this can be found [here](script/fix_zip.py).

## Question 3: Repairing the Images

Question 3 asks: *What is the 8-character hex string created by concatenating the contents of each image after successfully reassembling them?*

This section of the solution guide contains five parts. They are:

1. Determining Image Filetypes
2. Understanding PNG Syntax and Structure
3. Fixing the Images
4. Repeating the Procedure
5. Alternate Method

### 1. Determining Image Filetypes

If you go into the image folder and then into any of the `img_#` folders, you will notice a file called **header.txt**. If you open the header.txt file in a hex editor, you will see that it contains the images' file signature. If you view the ASCII-encoded portion of the hex editor, you will see it shows **PNG** as its file type. If you look at each image folder's header.txt you will see that each one has the same one written. Meaning that all eight images you need to repair are **PNG**.

### 2. Understanding PNG Syntax and Structure

To understand what to do to fix the PNG files, you need to understand how they are structured. Here are some links that will help with this. They may be referenced at different parts of the solution guide below.

- [PNG (Portable Network Graphics)](http://www.libpng.org/pub/png/spec/1.2/PNG-Structure.html)
- [FILEFORMAT PNG](https://docs.fileformat.com/image/png/)

#### General Structure

The general structure of the PNG follows this format:

1. PNG signature/header
   - 8 bytes in length
   - always the same 8 bytes
2. IHDR chunk 
   - starting chunk
3. IDAT chunk(s)
    - contains data that makes up majority of image
    - PNG needs to have at least one IDAT chunk, although there can be more
4. IEND chunk
    - ending chunk

#### Chunk Structure

The PNG is structured using *chunks*. Each chunk has its own signature to identify what its use it. The main chunk types you will need to understand are the following:

- IHDR
  - this is the chunk signature always seen first in the file and only once
- IDAT
  - there must be a minimum of one IDAT entry in a PNG but there can be more; these chunk types contain a majority of the main data making up the image
- IEND
  - always the last signature in the PNG and signifies the end of the file

Even though there are different signatures that can be assigned to a chunk, each chunk will always follow the same layout. The layout is:

1. 4 bytes representing the length of the chunk data
2. 4 bytes representing the signature/type of the chunk (IHDR, IDAT, etc.)
3. *n* bytes representing the chunk data. The size *n* can be found in the first 4 bytes
4. 4 bytes representing the CRC (Cyclic Redundancy Check) value from the current chunk

See the section **3.2 Chunk Layout** [here](http://www.libpng.org/pub/png/spec/1.2/PNG-Structure.html) to get more of an explanation.

When you understand the basic structure, you'll see that a PNG file is basically just one chunk after another in the correct order. 

### 3. Fixing the Images

#### Analyzing Corrupted Image Files

If you analyze the ZIP, you'll see that it contains eight folders labeled `img_#` where the order of the value of **#** represents the order the images should be read in. Make sure to keep this in mind when recreating the images.

In each `img_#` folder, there are three sub folders labeled **chunk1**, **chunk2**, and **chunk3**. These folders contain the data that makes up each chunk and the numbering indicates the order in which they need to be concatenated to recreate the image. 

There will also be a **header.txt** file which will contain the PNG header that is required for each image.

If you view the contents of one of the chunk folders, you'll see that it contains four files. Each filename pertains to a subsection of the chunk (length, type, data, crc). 

If you view the length.txt, type.txt, and data.txt files, you will see that each one contains the correct number of bytes that would be represented for its corresponding section.

If you look at the crc.txt file, you will see that it is empty even though it is supposed to be four bytes in length. You will need to calculate the crc value and  insert it into each chunk.

The structure for each chunk folder is identical for all images--the contents of each file will be different because each image is different.

#### Start Putting Images Back Together

The process is the same for putting together each image. You (re)concatenate all the data that has been split up in each `img_#` folder.

Follow the steps below:
1. Recreate *chunk1*.
   -  Concatenate data in the files in this order: length.txt, type.txt, data.txt, crc.txt
   -  Calculate crc value
2. Recreate *chunk2*:
   -  Concatenate data in the files in this order: length.txt, type.txt, data.txt, crc.txt
   -  Calculate crc value
3. Recreate *chunk3*:
   -  Concatenate data in the files in this order: length.txt, type.txt, data.txt, crc.txt
   -  Calculate crc value
4. Concatenate the following data, in this order, and write to a new PNG file:
   - PNG Header in header.txt
   - *chunk1* data
   - *chunk2* data
   - *chunk3* data

All of the above should be straightforward, other than calculating the CRC, which is explained next.

#### Calculate CRC value

Read the CRC subsection in the [PNG Specification](http://www.libpng.org/pub/png/spec/1.2/PNG-Structure.html). It tells you how the CRC value is determined.

>A 4-byte CRC (Cyclic Redundancy Check) calculated on the preceding bytes in the chunk, including the chunk type code and chunk data fields, but not including the length field. The CRC is always present, even for chunks containing no data

The CRC value is created based on the concatenated bytes of the *type + data* of its chunk. If you want, you can examine the CRC algorithm further to learn how it works to calculate it yourself. However, we found that utilizing the function `crc32()` from the `zlib` library in Python was a faster and more efficient way of solving this part. Please refer to the `determine_crc()` function in the `fix_png.py` solution script below to see how that library is used.

### 4. Repeating the Procedure

If done correctly, you should have successfully recreated the PNG and, upon opening it, you will see a single character. Repeat this process for all eight images. Once complete, you can view the hex token by reading them in order based on the original order of the `img_#` folders.

### 5. Alternate Method

An alternate method is to create a script to automate reading all the files, calculating each chunk's CRC value, and concatenating the data. An exemplar Python script to do just that is available [here](script/fix_png.py).

## Question 4: Repairing the PCAP

Question 4 asks: *What is the 8-character hex string found in an image in the packet capture (PCAP) after successfully repairing and extracting it?*

This section of the solution guide contains four parts. They are:

1. Understanding PCAP Syntax and Structure
2. Determining the Cause of Corruption
3. Alternate Method
4. Extracting the Image from Traffic 

### 1. Understanding PCAP Syntax and Structure

To understand how to fix the PCAP files, you need to understand how they are structured. Here are some helpful resources. We'll refer to them in the sections below too. 

- [Libpcap File Format](https://wiki.wireshark.org/Development/LibpcapFileFormat)

- [Link-Layer Header Types](https://www.tcpdump.org/linktypes.html)
- [PCAP Capture File Format](https://www.ietf.org/archive/id/draft-ietf-opsawg-pcap-03.html)

The general structure of a PCAP follows this format:

*The File Header full length is 24 bytes.*

1. File Signature/Magic Number:
   - 4 bytes in length
   - will be `A1 B2 C3 D4` *or* `D4 C3 B2 A1`
   - signature in the file determines the endianess of the file
   - `D4 C3 B2 A1` means file is read in little endian format
2. Major Version:  
   - 2 bytes in length
   - major version number of the PCAP
   - if version is 2.4, this number is the "2"
3. Minor Version:
   - 2 bytes in length
   - Minor version number of the PCAP
   - If version is 2.4, this number is the 4
4. Thiszone:
   - 4 bytes in length
   - Indicates the time zone offset for timestamps in the captured data; represents the offset of the local time from GMT (Greenwich Mean Time) in seconds. A value of zero implies UTC (Coordinated Universal Time).
5. SigFigs:
   - 4 bytes in length
   - Specifies the accuracy of timestamps in the file. In most cases, it is set to zero, indicating that timestamps are not considered accurate to any particular number of significant figures.
6. Snaplen:
   - 4 bytes in length
   - It specifies the maximum number of bytes captured from each packet. Packets longer than this length are truncated to this length.
7. Network:
   - 4 bytes in length
   - Indicates the type of link-layer network technology used for capturing traffic. This value is crucial for interpreting the raw packet data that follows, as it determines the format of the link-layer headers. Examples include Ethernet, Wi-Fi, and other network types.

Below is the structure of one packet in the PCAP. It repeats for each packet captured in the PCAP.

*Packet Info:*

1. Packet Header
   - Timestamp of seconds
      - 4 bytes in length
      - Shows the number of seconds since January 1, 1970
2. Timestamp of microseconds
      - 4 bytes
      - Shows microseconds portion of the time since January 1, 1970
3. Captured packet length
      - 4 bytes in length
      - States the length of the data captured in this packet
4. Original packet length
      - 4 bytes in length
      - Actual length of this packet when it was on the network
5. Packet data
      - Length was specified in the captured packet length portion of the header

*End of the structure for one packet in PCAP.*

You can learn more about the following sections in the links below:

- Global Header format
  - [Link 1](https://wiki.wireshark.org/Development/LibpcapFileFormat#global-header)
  - [Link 2](https://www.ietf.org/archive/id/draft-ietf-opsawg-pcap-03.html#name-file-header)
  - More information on the network aspect of the global header can be found in the Link-Layer section in [this article](https://www.tcpdump.org/linktypes.html).
- Packet Header format
  - [Link 1](https://wiki.wireshark.org/Development/LibpcapFileFormat#record-packet-header)
  - [Link 2](https://www.ietf.org/archive/id/draft-ietf-opsawg-pcap-03.html#name-packet-record)

### 2. Determining the Cause of Corruption

If you attempt to open the PCAP, Wireshark displays an error message:

![](c53/solution/img/pcap1.png)

The screen print above indicates two things:

1. Packets are read as the protocol LIN, which is incorrect, given the information in **instuctions.txt**
2. The error tells us there is an issue with reading the packet bytes

We will walk through each issue below.

#### Fixing Specified Packet Network Type

**Instructions.txt** states the PCAP was captured over an ethernet network--the data shouldn't be out of the ordinary. Wireshark wants to read the packets using the protocol LIN. This *is* out of the ordinary, however, and incorrect.

Review [Link-Layer Header Types](https://www.tcpdump.org/linktypes.html). The protocol LIN has the value `212`; in hex it is represented as `d4`.

You know the network the PCAP is interpreted as is specified in the last four (4) bytes of the global header. You can find it at the offset `20` from the beginning of the PCAP in your hex editor.

The four bytes represented as the network will be shown as `D4 00 00 00`, and because this file is read in little endian, the value of the network is `0xD4` or `212`, which is the LIN protocol.

To fix this, replace the `D4` with `01`. So, the *new* four bytes representing the network portion of the global header should look like `01 00 00 00`.

This fixes the first part of the corrupted PCAP.

#### Fixing Packet Size Error

You need to tackle the error that occurred when attempting to open the PCAP. The error indicates something is amiss where the file has a packet bigger than the maximum size of 262144. Because the error is about size, we'll check two parts of the file first.

1. snaplen section of the global header
2. captured packet length section of the packets

If you look at the snaplen in the global header (four bytes long with an offset of 16 bytes from the beginning of the file) you should see the bytes `00 00 04 00`. When read in little endian, it looks like `0x00040000`. Convert this from hex to decimal and the value you get is 262144. This value is the same value from the error. So, because the error message says the packet is larger than 262144, the problem must be within each packet's header where the captured packet length is specified. To test this, we need to find the captured packet length section of the first packet in the PCAP. 

Go to the offset which specifies the end of the global header section and the start of the first packet header. The offset is 24 bytes.

The offset to the captured packet length section of the packet header is written based on the start of the packet header. The offset is  eight bytes from the packet header's starting location. The next four bytes indicate the size of the data stored for this packet. The bytes for the captured packet length is `00 00 00 00`. This is incorrect, and we can determine what the captured length should be.

Look at the next four bytes representing the original packet length section after the capture packet length. This entry has bytes that do not equal  `0`. For example, using the bytes `45 00 00 00`: if you read this in little endian, the hex value for the original packet length is `0x45`;  when converted to decimal is equivalent to 69. 

This means the length of the original data in the PCAP was 69 bytes and since the max length a packet can capture is specificed in the global header as 262144, we can infer that the captured packet length is the same as the original packet length. Its packet size isn't bigger than the specified max length.

In your hex editor, replace the incorrect captured packet length represented as `00 00 00 00` with the correct length represented as `45 00 00 00`.

To test if this is fixed, save your changes and attempt to open the file again. You will receive that error again, but if you look at the packets in the capture, you should see the first packet is shown. Select the first packet to look at its data. 

Follow the same procedures to fix the captured packet length section in every packet in the file. 

To find the start of the next packet to start the procedure on, follow these steps after you've fixed the current packets' captured packet length.

1. Go to the offset indicated by the end of the original packet capture length: offset of `16` from the beginning of the current packet header.
2. Determine the decimal value of the newly fixed capture packet capture length. In the example above, it is `69`.
3. Because the captured data length is 69 bytes, go to the offset of 85 from the beginning of the current packet: data length of 69 *+ offset* of where the data starts and the current packet header ends, which is 16.

If done correctly, you are at the beginning of the next packet. 

>**Hint:** Packets are stored in order; you can check if you have the correct location for the start of the next packet by comparing the first two sections' timestamp of seconds and timestamp of microseconds  to the timestamp of seconds and the timestamp of microseconds of the previous packet. They should be close.

Fix every packet in the PCAP. When done correctly, you will have a PCAP file containing traffic based on an `HTTP POST` request.

### 3. Alternate Method

An alternate method to fix the PCAP is to write a script to automate reading the bytes and inserting the correct data for each packet entry. An exemplar Python script to do this can be found [here](c53/solution/script/fix_pcap.py).

### 4. Extracting the Image from Traffic

With the PCAP now fixed, you just need to extract the image in the PCAP to solve. Look through the PCAP. You should see one `POST` request. This packet is the largest and has the image we will extract. To extract the image:

1. Click the packet with the `POST` request.
2. In Wireshark, click the arrow next to **MIME Multipart Media Encapsulation** to open.
3. Click the arrow next to **Encapsulated mutlipart part: (image/jpeg)** to open. The data you want is in **JPEG File Interchange Format**. 
4. Select it--some bytes are highlighted. See the screen print below:

![](c53/solution/img/pcap2.png)

5. Right-click the **JPEG File Interchange Format** section, then **Export Packet Bytes**.
6. Save it, making sure the file ends with `.jpg`.
7. Open the newly saved image file and you will be presented with the token for this part.