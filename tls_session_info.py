import sys
import datetime
from enum import IntEnum
import csv
import os

class Constant(IntEnum):
    ETH_HDR = 14
    IHL_MASK = int('00001111',2)
    TCP_DATA_OFFSET_MASK = int('11110000',2)
    WORDS_TO_BYTES = 4
    DATA_OFFSET_BITWISE_SHIFT = 4
    TLS_RCD_LYR_LEN_OFFSET = 3
    TLS_RCD_LYR_LEN = 5
    IP_SRC_OFFSET = 12
    IP_DST_OFFSET = 16
    IP_ADDR_LEN = 4
    TCP_DST_OFFSET = 2
    TCP_PORT_LEN = 2
    TLS_HANDSHAKE_VER_OFFSET = 9
    TLS_VER_LEN = 2

class TLSSummary:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, tls_version):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.tls_version = tls_version

    def get_src_ip(self):
        return self.src_ip

    def get_dst_ip(self):
        return self.dst_ip

    def get_src_port(self):
        return self.src_port

    def get_dst_port(self):
        return self.dst_port

    def get_tls_version(self):
        return self.tls_version

    def print_summary(self):
        sum = '''
        Source IP:        {}
        Destination IP:   {}
        Source Port:      {}
        Destination Port: {}
        TLS Version:      {}
        '''.format(self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.tls_version)
        print(sum)

class Packet:
    def __init__(self):
        self.ip_hdr = None
        self.tcp_hdr = None
        self.ssl_hdr = None
        self.summary = None

    def save_ip_hdr(self, ip_hdr):
        self.ip_hdr = ip_hdr

    def save_tcp_hdr(self, tcp_hdr):
        self.tcp_hdr = tcp_hdr

    def save_ssl_hdr(self, ssl_hdr):
        self.ssl_hdr = ssl_hdr
    
    def save_summary(self, src_ip, dst_ip, src_port, dst_port, tls_version):
        self.summary = TLSSummary(src_ip, dst_ip, src_port, dst_port, tls_version)

    def get_ip_hdr(self):
        return self.ip_hdr

    def get_tcp_hdr(self):
        return self.tcp_hdr

    def get_ssl_hdr(self):
        return self.ssl_hdr

    def print_summary(self):
        return self.summary.print_summary()

    def get_summary(self):
        return self.summary
    

def report_global_header(file_ptr):
    # assumes file_ptr is at head
    # of pcap file
    # returns byte order
    #     big
    #     little
    # confirms ethernet frame
    #     true if ethernet frame

    magic_num = file_ptr.read(4)
    magic_test = b'\xa1\xb2\xc3\xd4'
    if magic_num == magic_test:
        order = 'big'
    else:
        order = 'little'

    file_ptr.seek(16,1)
    link_layer_type = file_ptr.read(4)
    ethernet = int.from_bytes(link_layer_type, byteorder = order)
    is_ethernet = ethernet == 1

    return order, is_ethernet


def report_pkt_header(file_ptr, byte_order):
    # returns length of packet in file
    file_ptr.seek(8,1)
    read_bytes = file_ptr.read(4)

    if read_bytes == b'':
        raise Exception('End of File')

    saved_bytes = int.from_bytes(read_bytes, byteorder = byte_order)

    # going to be nice to future me by
    # setting the file pointer to the 
    # start of the frame
    file_ptr.seek(4,1)
    
    return saved_bytes


def bytes_to_ip_str(ip_in_bytes):
    
    first_octet = str(int.from_bytes(ip_in_bytes[0:1], byteorder = 'big'))
    second_octet = str(int.from_bytes(ip_in_bytes[1:2], byteorder = 'big'))
    third_octet = str(int.from_bytes(ip_in_bytes[2:3], byteorder = 'big'))
    fourth_octet = str(int.from_bytes(ip_in_bytes[3:4], byteorder = 'big'))

    return '.'.join([first_octet, second_octet, third_octet, fourth_octet])


def extract_packet(file_ptr, packet_length):
    return file_ptr.read(packet_length)


def get_tls_content_type(packet):

    ip_len = (int.from_bytes(packet[Constant.ETH_HDR: Constant.ETH_HDR + 1], byteorder = 'big') & 
                Constant.IHL_MASK) * Constant.WORDS_TO_BYTES
    tcp_len = ((int.from_bytes(packet[Constant.ETH_HDR + ip_len + 12: Constant.ETH_HDR + ip_len + 12 + 1], byteorder = 'big') & 
                Constant.TCP_DATA_OFFSET_MASK) >> Constant.DATA_OFFSET_BITWISE_SHIFT) * Constant.WORDS_TO_BYTES
    if (packet[Constant.ETH_HDR + ip_len + tcp_len: Constant.ETH_HDR + ip_len + tcp_len + 1]) == b'\x16':
        handshake_type = packet[Constant.ETH_HDR + ip_len + tcp_len + Constant.TLS_RCD_LYR_LEN: Constant.ETH_HDR + ip_len + tcp_len + Constant.TLS_RCD_LYR_LEN + 1]
        if handshake_type == b'\x01' or handshake_type == b'\x02': 
            tls_len = int.from_bytes(packet[Constant.ETH_HDR + ip_len + tcp_len + Constant.TLS_RCD_LYR_LEN_OFFSET: Constant.ETH_HDR + ip_len + tcp_len + Constant.TLS_RCD_LYR_LEN_OFFSET + 2], byteorder = 'big')
            tls_hdr = packet[Constant.ETH_HDR + ip_len + tcp_len: Constant.ETH_HDR + ip_len + tcp_len + tls_len + Constant.TLS_RCD_LYR_LEN]
            return (True, tls_hdr)
    return (False, b'')


def extract_ip_header(packet):
    # In this function, packet is a bytes representation of 
    # a packet. I assume it's already been pulled out of the 
    # pcap and into a variable.

    ver_ihl = int.from_bytes(packet[Constant.ETH_HDR: Constant.ETH_HDR + 1], byteorder = 'big')
    ihl = ver_ihl & Constant.IHL_MASK
    length = ihl * 4

    ip_header = packet[Constant.ETH_HDR: Constant.ETH_HDR + length]

    return ip_header


def extract_tcp_header(packet, ip_hdr_len):
    tcp_len = ((int.from_bytes(packet[Constant.ETH_HDR + ip_hdr_len + 12: Constant.ETH_HDR + ip_hdr_len + 12 + 1], byteorder = 'big') & 
                Constant.TCP_DATA_OFFSET_MASK) >> Constant.DATA_OFFSET_BITWISE_SHIFT) * Constant.WORDS_TO_BYTES
    
    tcp_hdr = packet[Constant.ETH_HDR + ip_hdr_len: Constant.ETH_HDR + ip_hdr_len + tcp_len]

    return tcp_hdr


def ip_hdr_details(ip_hdr):
    src_bytes = ip_hdr[Constant.IP_SRC_OFFSET: Constant.IP_SRC_OFFSET + Constant.IP_ADDR_LEN]
    dst_bytes = ip_hdr[Constant.IP_DST_OFFSET: Constant.IP_DST_OFFSET + Constant.IP_ADDR_LEN]

    src = bytes_to_ip_str(src_bytes)
    dst = bytes_to_ip_str(dst_bytes)

    return (src, dst)


def tcp_hdr_details(tcp_hdr):
    src = int.from_bytes(tcp_hdr[:Constant.TCP_PORT_LEN], byteorder = 'big')
    dst = int.from_bytes(tcp_hdr[Constant.TCP_DST_OFFSET: Constant.TCP_DST_OFFSET + Constant.TCP_PORT_LEN], byteorder = 'big')

    return (src, dst)


def tls_hdr_details(tls_hdr):
    version_bytes = tls_hdr[Constant.TLS_HANDSHAKE_VER_OFFSET: Constant.TLS_HANDSHAKE_VER_OFFSET + Constant.TLS_VER_LEN]

    if version_bytes == b'\x03\x01':
        return "TLS 1.0"
    elif version_bytes == b'\x03\x02':
        return "TLS 1.1"
    elif version_bytes == b'\x03\x03':
        return "TLS 1.2"
    elif version_bytes == b'\x03\x00':
        return "SSL 3.0"
    elif version_bytes == b'\x03\x04':
        return "TLS 1.3"
    else:
        return "Unknown"


def main(f_ptr, output_file):

    byte_order, eth = report_global_header(f_ptr)
    summary_list = []
    index = 0
    while(True):
        # Step 0: Pull a packet from the pcap
        try:
            packet_len = report_pkt_header(f_ptr, byte_order)
        except Exception as e:
            print(e)
            break
        index += 1
        packet_bytes = extract_packet(f_ptr,packet_len)
        packet = Packet()
        # Step 1: Skip past IP and TCP headers and pull TLS content type from record layer
        handshake, ssl_hdr = get_tls_content_type(packet_bytes)
        # Step 2a: If it is a handshake and a client or server hello, save the SSL header in the Packet Class
        if handshake:
            packet.save_ssl_hdr(ssl_hdr)
            # Step 3: Save the IP and TCP headers
            packet.save_ip_hdr(extract_ip_header(packet_bytes))
            packet.save_tcp_hdr(extract_tcp_header(packet_bytes, len(packet.get_ip_hdr())))
        # Step 2b: If it's not a handshake and a client or server hello, go to next packet and back to Step 0
        else:
            continue
        # Step 4: Dissect the headers
        src_ip, dst_ip = ip_hdr_details(packet.get_ip_hdr())
        src_port, dst_port = tcp_hdr_details(packet.get_tcp_hdr())
        tls_ver = tls_hdr_details(packet.get_ssl_hdr())
        packet.save_summary(src_ip, dst_ip, src_port, dst_port, tls_ver)
        # Step 5: Save the resulting TLSSummary into a list
        # Enable the below code if you have too many "Unknown" versions in the output
        '''
        if tls_ver == "Unknown":
            print("For frame " + str(index))
            packet.print_summary()
        '''
        summary_list.append(packet.get_summary())
        # Step 6: go to next packet and back to Step 0
    # Step 7: Save TLSSummary list to a csv
    with open(output_file, 'w', newline='') as output:
        sum_writer = csv.writer(output, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)

        sum_writer.writerow(['Source IP', 'Destination IP', 'Source Port', 'Destination Port', 'TLS Version'])
        for item in summary_list:
            sum_writer.writerow([item.get_src_ip(), item.get_dst_ip(), item.get_src_port(), item.get_dst_port(), item.get_tls_version()])
    pass


if __name__ == "__main__":

    help_text = '''TLS Version Auditor:
        To pass a single file in, use the syntax 'python tls_session_info.py <file path>'
        To pass a directory of pcaps, use        'python tls_session_info.py --bulk <directory path>'
        To display this message, use             'python tls_session_info.py --help
    '''
    file_list = []
    if sys.argv[1] == '--help':
        print(help_text)
        sys.exit()
    if sys.argv[1] == '--bulk':
        dir = sys.argv[2]
        for file in os.listdir(dir):
        if file.endswith(".pcap"):
            file_list.append(f"{dir}\{file}")
            print(f"{file}")
    else:
        file_list.append(sys.argv[1])  
    

    for file in file_list:
        print(f"Starting file {os.path.relpath(file)}")
        f = open(file, 'rb+')
        output_fn = file.replace('.pcap','_summary.csv')

        main(f, output_fn)
        print(f"Output to {os.path.relpath(output_fn)} complete")
        f.close()

    pass