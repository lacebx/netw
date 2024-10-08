import pyshark

# Function to calculate EstimatedRTT
def calculate_estimated_rtt(rtt_values, alpha=0.125):
    estimated_rtt = rtt_values[0]  # Start with the first RTT
    estimated_rtt_values = [estimated_rtt]

    for rtt in rtt_values[1:]:
        estimated_rtt = (1 - alpha) * estimated_rtt + alpha * rtt
        estimated_rtt_values.append(estimated_rtt)
    
    return estimated_rtt_values

def main(pcap_file):
    # Load the capture file
    cap = pyshark.FileCapture(pcap_file, display_filter='tcp')
    
    # Store all packets in a list
    all_packets = list(cap)

    segments = []
    rtt_values = []
    estimated_rtt_values = []
    estimated_rtt = None

    for packet in all_packets:
        try:
            if 'TCP' in packet:
                seq_num = int(packet.tcp.seq)
                time_sent = float(packet.sniff_time.timestamp())
                length = int(packet.tcp.len) if 'len' in packet.tcp.field_names else 0
                
                # Add a check to avoid zero-length segments unless they are critical
                if length > 0 or ('SYN' in packet.tcp.flags_string or 'FIN' in packet.tcp.flags_string):
                    segments.append((seq_num, time_sent, length, packet))
        except AttributeError:
            continue

    # Limit to first 6 relevant segments
    segments = segments[:6]

    for i, (seq_num, time_sent, length, packet) in enumerate(segments):
        # Look for corresponding ACK packets
        for ack_packet in all_packets:
            try:
                if 'TCP' in ack_packet:
                    ack_num = int(ack_packet.tcp.ack)
                    # Check if ACK corresponds to the sent segment
                    if ack_num == seq_num + length:
                        ack_time = float(ack_packet.sniff_time.timestamp())
                        rtt = ack_time - time_sent
                        rtt_values.append(rtt)
                        
                        # Calculate EstimatedRTT
                        if estimated_rtt is None:
                            estimated_rtt = rtt  # First RTT is used to initialize EstimatedRTT
                        else:
                            estimated_rtt = (1 - 0.125) * estimated_rtt + 0.125 * rtt
                        
                        estimated_rtt_values.append(estimated_rtt)

                        # Print formatted output
                        print(f"Segment {i+1}: Seq={seq_num}, Length={length}, "
                              f"ACK Receive Time={ack_time:.6f}, ACK={ack_num}, "
                              f"SampleRTT={rtt:.6f}, EstimatedRTT={estimated_rtt:.6f}")
                        break
            except AttributeError:
                continue

    if not rtt_values:
        print("No RTT values found.")

if __name__ == "__main__":
    pcap_file = '/home/lace/Downloads/wireshark.pcapng'  # Update with your .pcap file path
    main(pcap_file)
