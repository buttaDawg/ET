import scapy
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.sendrecv import sniff, send, sr1, sr, srp1
import hashlib
import socket

ALIEN_IP = "54.71.128.194"
ALIEN_UDP_PORT = 99
SPORT = 0

"""
function that prints source and dest ip of a pakcet
params: packet
returns: -
"""


def print_packet(packet):
    print(packet[IP].src, "-", packet[IP].dst)


"""
function that decodes the encoded message from alienClient
params: text (string) encoded message from alien client
returns: the decoded message
output: the decoded message
shoutout ori alush for writing this function lol
"""


def decode_message(text):
    allowed_letters = (' ', ',', '!', '.', ':', '*', ';', '/', '=')
    key = int(text[3:6])
    result = ''
    for index, letter in enumerate(text[6:]):
        if index % 2 == 1 or letter in allowed_letters or letter.isnumeric():
            result += letter
        else:
            result += chr((ord(letter) - 97 - key) % 26 + 97)
    print(result)
    print("=====================")
    return result


"""
function that makes sniffing stop when there are 10/10 location data packets
params: packets
returns: true if there are 10 location data packets, else, false
"""


def stop(packet):
    location_data_bool = False
    try:
        location_data_bool = "location data 10/10:" in decode_message(packet[Raw].load.decode())
    except Exception:
        pass
    if location_data_bool:
        return True
    return False


"""
function that filters incoming packets to those who come from alien client
params: packets
returns: true if packet ip.src is alien client's ip, false if else
"""


def alien_filter(packet):
    ip_src_bool = False
    try:
        ip_src_bool = packet[IP].src == ALIEN_IP and packet[UDP].sport == ALIEN_UDP_PORT
    except IndexError:
        pass
    if ip_src_bool:
        return True
    return False


"""
function that encodes the message so the server understands it, reverse function of decode_message()
params: text
returns: encoded message
"""


def encode_message(text):
    allowed_letters = (' ', ',', '!', '.', ':', '*', ';', '/', '=', "b'", "'", "_")
    result = ''
    key = 8
    for index, letter in enumerate(text[:len(text)]):
        if index % 2 == 1 or letter in allowed_letters or letter.isnumeric():
            result += letter
        else:
            result += chr((ord(letter) - 97 + key) % 26 + 97)
    return result


"""
function that sends final packet to server
params: final packet and source port(my machine port)
returns: -
"""


def send_final(final_packet, _sport):
    print(final_packet)
    full_msg = Ether() / IP(dst=ALIEN_IP) / UDP(dport=ALIEN_UDP_PORT, sport=_sport) / Raw(load=final_packet)
    ans = srp1(full_msg, verbose=0)


def main():
    big_param_str = ""
    packets = sniff(lfilter=alien_filter, prn=print_packet, stop_filter=stop)
    for packet in packets:
        my_port = packet[UDP].dport
        result = decode_message(packet[Raw].load.decode())
        if "location data" in result:
            big_param_str += result[-10:-1:] + result[-1]  # get the 10 chars location data

    result = hashlib.md5(big_param_str.encode())

    final_packet = "FLY008" + encode_message("location_md5=" + str(result.hexdigest()) + ",airport=nevada25.84,"
                                                                                         "time=15:52,lane=earth.jup,"
                                                                                         "vehicle=2554,fly")
    send_final(final_packet, my_port)


if __name__ == '__main__':
    main()
