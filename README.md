# TCP RTT Estimator

This Python script estimates the Round-Trip Time (RTT) for TCP segments captured in a pcap file. It leverages the `pyshark` library to analyze TCP packets, calculate sample RTT values, and compute an Estimated RTT using an exponential moving average.

## Features

- Parses TCP packets from a specified pcap file.
- Calculates Sample RTT for each TCP segment and its corresponding ACK.
- Computes Estimated RTT using a configurable alpha value.
- Outputs segment information including sequence number, length, ACK time, Sample RTT, and Estimated RTT.

## Requirements

- Python 3.x
- `pyshark` library

You can install the required library using pip:

```bash
pip install pyshark
```
## Usage

    Ensure you have a valid pcap file. You can capture packets using tools like Wireshark.
    Update the pcap_file variable in the script to the path of your pcap file.
    Run the script:

```bash
python rtt_estimator.py
```
## Example

```python

if __name__ == "__main__":
    pcap_file = '/path/to/your/file.pcap'  # Update with your .pcap file path
    main(pcap_file)
```
## Function Details

calculate_estimated_rtt(rtt_values, alpha=0.125)

Calculates the Estimated RTT using the given RTT values and an alpha value (default is 0.125).

    Parameters:
        rtt_values: A list of RTT sample values.
        alpha: Weight for the most recent RTT value.
    Returns: A list of estimated RTT values.

main(pcap_file)

Processes the given pcap file to extract TCP segments and their corresponding ACK packets.

    Parameters:
        pcap_file: Path to the pcap file to analyze.

## Output

The script will print the following for each relevant TCP segment:

less

Segment X: Seq=Y, Length=Z, ACK Receive Time=A, ACK=B, SampleRTT=C, EstimatedRTT=D

Where:

    X: Segment number
    Y: Sequence number
    Z: Length of the segment
    A: ACK receive time
    B: ACK number
    C: Sample RTT
    D: Estimated RTT

## Troubleshooting

    Ensure that your pcap file contains TCP packets; otherwise, the script will indicate that no RTT values were found.
    Adjust the alpha value in the calculate_estimated_rtt function if you need different sensitivity for the Estimated RTT calculation.

## License

This project is open-source and available under the MIT License. Feel free to modify and use it as needed!