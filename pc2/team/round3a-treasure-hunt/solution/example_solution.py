
# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import math
import io
import binascii
LAPTOP = 'E:\\laptopimage.dd'
USB = 'E:\\usbimage.dd'
fpos = 0
fbuff = ''
types = ['00000010','00000030','00000080','00000020','00000040','000000c0']
def getbytes(value, start, end, reverse=False):
    '''gets the bytes from the data'''
    ret = ''
    if reverse:
        for i in reversed(range(start, end)): ret += byteme(value, i)
    else:
        for i in range(start, end): ret += byteme(value, i)
    return ret
        
def byteme(value, byte):
    '''gets a single byte from the string'''
    return str(value[byte * 2: (byte * 2) + 2])
    
def parse(hexval, values):
    attr = byteme(hexval, 21) + byteme(hexval, 20)
    attrval = int(attr, 16)
    entry = byteme(hexval, 23) + byteme(hexval, 22)
    typee = ''
    cont = True
    dbugvals = []
    if entry == '0000':
        typee = 'DELETED_FILE'
    elif entry == '0001':
        typee = 'ALLOCATED_FILE'
    elif entry == '0002':
        typee = 'DELETED_DIR'
    elif entry == '0003':
        typee = 'ALLOCATED_DIR'
    if typee != '':
        dbugvals.append(typee)
        filename = ''
        datavalue = ''
        datacnt = 0
        while cont:
            atttypestr = getbytes(hexval, attrval, attrval + 4, True)
            attsizestr = getbytes(hexval, attrval + 4, attrval + 8, True)
            if atttypestr not in types: break
            atttype = int(atttypestr, 16)
            attsize = int(attsizestr, 16)
            res = getbytes(hexval, attrval+8, attrval+9)
            if atttype == 48:
                # this is a filename attribute
                # bytes 20 -> 21: name offset (reversed)
                # bytes offset + 64 -> offset + 65: name length (reversed)
                # bytes offset + 66 -> offset + 66 + name length * 2: file name
                nameoffset = int(getbytes(hexval, attrval+20, attrval+21, True), 16)
                namelen = int(getbytes(hexval, attrval + nameoffset + 64, attrval + nameoffset + 65, True), 16)
                name = getbytes(hexval, attrval + nameoffset + 66, attrval + nameoffset + 66 + (namelen * 2))
                filename = binascii.unhexlify(name).decode('utf-16')
                dbugvals.append("\tfile name: {}".format(filename))
            if atttype == 128:
                # this is a data attribute
                # bytes 16 -> 19: data length (reversed)
                # bytes 20 -> 21: byte offset (reversed)
                # bytes data offset -> data length: data
                datacnt += 1
                datalen = int(getbytes(hexval, attrval+16, attrval+19, True), 16)
                dbugvals.append("\tdata len: {}".format(getbytes(hexval, attrval+16, attrval+19, True)))
                dbugvals.append("\tresident: {}".format(getbytes(hexval, attrval+8, attrval+9)))
                dataoffset = int(getbytes(hexval, attrval+20, attrval+21, True), 16)
                data = getbytes(hexval, attrval + dataoffset, attrval + dataoffset + datalen)
                b = 0
                datavalue = ''
                while b < len(data):
                    c = int(data[b:b+2],16)
                    b += 2
                    if c >= 30 and c <= 127:
                        datavalue += chr(c)
                dbugvals.append("\tdata value: {}".format(datavalue))
            attrval += attsize  # move to the next attribute
        if filename != '' and datavalue != '':
            if "FILE" in typee:
                if datacnt > 1:
                    for s in dbugvals: print(s)
                    print("\tdata count: {}".format(datacnt))
                    return [filename, datavalue.strip()]
            else:
                # only return values if there is a file name and data value
                # files that have multiple data values will have the last data value returned
                for s in dbugvals: print(s)         
                return [filename, datavalue.strip()]
        
        return None
        
def fullread(file):
    values = {}
    with open(file, 'rb') as f:
        hexd = f.read().hex()                   #gets the full binary file as a hex string
        s = 0
        m = hexd.find('46494c4530')             #find the first instance of a msft file header
        values = {}
        while m > 0:                            #loop while there are still msft file headers
            part = parse(hexd[m:m+2048], values)#pull out the full msft header and parse out the values
            if part:                            #if values are parse out, add them to the value tracking
                values[part[0]] = part[1]       #adds the values to the dictionary with filename as lookup
            s = m + 2048                        #set the start of the search to the end of the parsed record
            m = hexd.find('46494c4530',s)       #search again
    result = ''
    for key in sorted(values.keys()):           #loop through all the files returned and create the result
        result += values[key]                   #string sorted by file name
    print("result: {}".format(result))


fullread(USB)


