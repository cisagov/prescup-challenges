from scapy.all import IP, UDP, Raw, wrpcap
import struct

def make_whisper_pcap(filename, token_fragments, pkt_count=600):
    packets = []
    src='10.10.10.1'; dst='10.10.10.2'; sport=40000; dport=40001
    seq = 1; inserted = 0
    for i in range(pkt_count):
        payload = b'\x00' * 40
        if i in (2, 54, 129, 156, 268) and inserted < len(token_fragments):
            payload = token_fragments[inserted]; inserted += 1
        hdr = b'WHPR' + struct.pack('!H', seq) + struct.pack('!H', len(payload))
        packets.append(IP(src=src,dst=dst)/UDP(sport=sport,dport=dport)/Raw(load=hdr+payload))
        seq += 1
    wrpcap(filename, packets)

def make_hushrtp_pcap(filename, nonces):
    packets = []
    src='10.20.20.1'; dst='10.20.20.2'; sport=50000; dport=50001
    for n in nonces:
        packets.append(IP(src=src,dst=dst)/UDP(sport=sport,dport=dport)/Raw(load=b'HUSHR'+n))
    wrpcap(filename, packets)
    
def write_udp_pcap(path, src_ip, dst_ip, src_port, dst_port, payloads, start_ts, delta):
    """
    Barebones PCAP + IPv4/UDP writer with monotonically increasing timestamps.
    Enough for Wireshark to parse and 'Follow UDP Stream'.
    """
    import struct, socket, time, zlib

    def ip_checksum(hdr):
        s = 0
        for i in range(0, len(hdr), 2):
            w = (hdr[i] << 8) + (hdr[i+1] if i+1 < len(hdr) else 0)
            s = (s + w) & 0xffffffff
        while (s >> 16):
            s = (s & 0xffff) + (s >> 16)
        return (~s) & 0xffff

    with open(path, "wb") as f:
        # PCAP global header (Ethernet, microsecond ts)
        f.write(struct.pack("<IHHIIII",
            0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

        ts = start_ts
        mac_src = b"\xaa\xaa\xaa\xaa\xaa\xaa"
        mac_dst = b"\xbb\xbb\xbb\xbb\xbb\xbb"
        eth_type = b"\x08\x00"

        s_ip = socket.inet_aton(src_ip)
        d_ip = socket.inet_aton(dst_ip)

        for p in payloads:
            # UDP
            udp_len = 8 + len(p)
            udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)

            # IP
            ver_ihl = 0x45
            tos = 0
            tot_len = 20 + udp_len
            ident = 0
            flags_frag = 0x4000
            ttl = 64
            proto = 17
            ip_hdr_wo_csum = struct.pack("!BBHHHBBH4s4s",
                ver_ihl, tos, tot_len, ident, flags_frag, ttl, proto, 0, s_ip, d_ip)
            csum = ip_checksum(ip_hdr_wo_csum)
            ip_hdr = struct.pack("!BBHHHBBH4s4s",
                ver_ihl, tos, tot_len, ident, flags_frag, ttl, proto, csum, s_ip, d_ip)

            # Ethernet payload = IP + UDP + data
            l3l4 = ip_hdr + udp_hdr + p
            frame = mac_dst + mac_src + eth_type + l3l4

            # pcap record header
            sec = int(ts)
            usec = int((ts - sec) * 1_000_000)
            incl_len = orig_len = len(frame)
            f.write(struct.pack("<IIII", sec, usec, incl_len, orig_len))
            f.write(frame)

            ts += delta
