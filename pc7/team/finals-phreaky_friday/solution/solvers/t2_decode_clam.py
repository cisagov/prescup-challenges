with open('t2_clamstream.bin','rb') as f:
    data=f.read()
i=0
parts=[]
while i<len(data)-4:
    if data[i:i+2]==b'CL':
        mask=data[i+2]
        l=data[i+3]
        payload=data[i+4:i+4+l]
        decoded = bytes([b ^ mask for b in payload])
        if all(32<=c<127 for c in decoded):  # printable
            print("decoded:", decoded)
            parts.append(decoded)
        i += 4 + l
    else:
        i += 1
