#!/usr/bin/env python

from scapy.all import Ether, IP, UDP, RTP, Raw, wrpcap
import random
import os
import sys


TOKEN4 = os.environ.get('TOKEN4')


def create_robust_rtp_stream(output_pcap_file="suspicious_capture.pcap", secret_token=f"TOKEN4: {TOKEN4}", total_packets=5000, token_embedding_density=50):
    """
    Generates a robust RTP stream with a hidden token, saving it to a pcap file.
    The token is fragmented into 5 identifiable parts and embedded within the payload
    of various RTP packets, interspersed with random data to make it harder to find.

    Args:
        output_pcap_file (str): The name of the output pcap file.
        secret_token (str): The secret token string to embed in the stream.
        total_packets (int): The total number of RTP packets to generate in the stream.
        token_embedding_density (int): On average, how many packets between token parts.
                                      A lower number (e.g., 10) means more frequent token parts,
                                      while a higher number (e.g., 100) means less frequent.
    """
    packets = []
    ssrc = 0x12345678  # Synchronization Source identifier for the RTP stream
    seq_num = 0       # RTP sequence number, increments with each packet
    timestamp = 0     # RTP timestamp, typically increments based on clock rate (e.g., 8000 for 8kHz audio)
    payload_type = 96 # Dynamic payload type (commonly used for custom audio/video codecs)

    # --- Token Fragmentation and Identification ---
    # Divide the secret token into 4 parts.
    # We'll prepend an identifier to each part.
    num_fragments = 5
    token_len = len(secret_token)
    base_fragment_len = token_len // num_fragments
    remaining_bytes = token_len % num_fragments

    token_fragments = []
    start_index = 0
    for i in range(num_fragments):
        # Distribute remaining bytes among the first 'remaining_bytes' fragments
        current_fragment_len = base_fragment_len + (1 if i < remaining_bytes else 0)
        fragment_content = secret_token[start_index : start_index + current_fragment_len]
        # Prepend identifiable string to each fragment
        identifiable_fragment = f"Part {i+1}: {fragment_content}"
        token_fragments.append(identifiable_fragment.encode('utf-8'))
        start_index += current_fragment_len

    # This list will hold the fragments we still need to embed
    # We reverse it so we can pop from the end (more efficient)
    token_fragments_to_embed = list(reversed(token_fragments))
    embedded_fragments_count = 0

    print(f"Generating {total_packets} RTP packets into '{output_pcap_file}'...")
    print(f"Embedding secret token (in 5 identifiable parts): '{secret_token}'")
    for i, frag in enumerate(token_fragments):
        print(f"  Fragment {i+1}: '{frag.decode(errors='ignore')}'")


    for i in range(total_packets):
        # Construct the RTP header
        rtp_header = RTP(
            version=2,
            padding=0,
            extension=0,
            marker=0,
            payload_type=payload_type,
            sequence=seq_num,
            timestamp=timestamp,
        )

        payload_data = b''
        # Decide if we should embed a part of the token in this packet
        # We ensure all fragments are embedded by checking token_fragments_to_embed
        # and then using the density for spacing.
        if token_fragments_to_embed and random.randint(1, token_embedding_density) == 1:
            token_chunk = token_fragments_to_embed.pop() # Get the next fragment to embed
            embedded_fragments_count += 1

            # Mix the token chunk with random bytes at the beginning and end
            random_prefix_len = random.randint(0, 10)
            random_suffix_len = random.randint(0, 10)
            payload_data = os.urandom(random_prefix_len) + token_chunk + os.urandom(random_suffix_len)

            print(f"  -> Embedded fragment '{token_chunk.decode(errors='ignore')}' at packet {i}")
        else:
            # For "normal" packets, fill the payload with random data
            payload_data = os.urandom(random.randint(50, 200)) # Varying payload size for noise

        # Ensure payload is not empty, add some random data if it somehow becomes empty
        if not payload_data:
            payload_data = os.urandom(50)

        # Combine RTP header with the payload (Raw layer for arbitrary data)
        rtp_packet = rtp_header / Raw(load=payload_data)

        # Create UDP, IP, and Ethernet layers for the full packet
        udp_packet = UDP(sport=random.randint(1024, 65535), dport=5004)
        ip_packet = IP(src="192.168.1.100", dst="192.168.1.200")
        ether_packet = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF")

        # Assemble the full packet stack
        full_packet = ether_packet / ip_packet / udp_packet / rtp_packet
        packets.append(full_packet)

        # Increment sequence number and timestamp for the next packet
        seq_num = (seq_num + 1) % 65536
        timestamp += random.randint(800, 1600)

    # Write all generated packets to the specified pcap file
    wrpcap(output_pcap_file, packets)
    print(f"\nSuccessfully created robust RTP stream in '{output_pcap_file}' with {len(packets)} packets.")

    # Report if all fragments were embedded
    if embedded_fragments_count < num_fragments:
        print(f"Warning: Only {embedded_fragments_count} out of {num_fragments} token fragments were embedded.")
    else:
        print(f"All {num_fragments} token fragments were successfully embedded.")

def main():
    output_file = "/challenge/suspicious_capture.pcap"
    secret_token = f"TOKEN4: {TOKEN4}"

    create_robust_rtp_stream(output_pcap_file=output_file, secret_token=secret_token)

if __name__ == "__main__":
    try:
        from scapy.all import Ether
    except ImportError:
        print("Error: Scapy library not found. Please install it using: pip install scapy")
        sys.exit(1)

    main()
