import dpkt
import socket


# Function to extract the ARP packet details
def extract_arp_packet(arp_packet):
    arp_header = {}
    arp_header['Hardware type'] = arp_packet[0:2].hex()
    arp_header['Protocol type'] = arp_packet[2:4].hex()
    arp_header['Hardware size'] = arp_packet[4:5].hex()
    arp_header['Protocol size'] = arp_packet[5:6].hex()
    arp_header['Opcode'] = arp_packet[6:8].hex()
    arp_header['Sender MAC address'] = ':'.join(arp_packet[8:14].hex()[i:i+2] for i in range(0, 12, 2))
    arp_header['Sender IP address'] = socket.inet_ntoa(int(arp_packet[14:18].hex(), 16).to_bytes(4, byteorder='big'))
    arp_header['Target MAC address'] = ':'.join(arp_packet[18:24].hex()[i:i+2] for i in range(0, 12, 2))
    arp_header['Target IP address'] = socket.inet_ntoa(int(arp_packet[24:28].hex(), 16).to_bytes(4, byteorder='big'))
    return arp_header

# Function to read the pcap file and extract ARP packets
def analyze_pcap_arp(pcap_file):
    request = 0
    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            # Check if the packet is an ARP packet
            arp_packet = eth.data

            if eth.type == dpkt.ethernet.ETH_TYPE_ARP :
                # Check if it is an ARP request or response
                if arp_packet.op == dpkt.arp.ARP_OP_REQUEST and request == 0:
                    request = 1
                    print('\nARP Request:')
                    arp_header = extract_arp_packet(arp_packet.pack())
                    for key, value in arp_header.items():
                        print(key + ': ' + value)
                elif arp_packet.op == dpkt.arp.ARP_OP_REPLY:
                    print('\nARP Response:')
                    arp_header = extract_arp_packet(arp_packet.pack())
                    for key, value in arp_header.items():
                        print(key + ': ' + value)
                    exit()
                # Extract and print the ARP packet details
                

# Call the function with pcap file name

def main():

    #filename = r"C:\Users\a1069\Desktop\assignment4\assignment4_my_arp.pcap"
    filename = input("Please enter your path to the pcap file: ")
    analyze_pcap_arp(filename)
        
    
    

if __name__ == "__main__":
    main()