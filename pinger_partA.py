import datetime
import os
import sys
import struct
import time
import select
import socket
import binascii

ICMP_ECHO_REQUEST = 8
rtt_min = float('+inf')
rtt_max = float('-inf')
rtt_sum = 0
rtt_cnt = 0



def checksum(string):
    csum = 0
    countTo = (len(string) / 2) * 2

    count = 0
    while count < countTo:
        thisVal = string[count + 1] * 256 + string[count]
        csum = csum + thisVal
        csum = csum & 0xffffffff
        count = count + 2

    if countTo < len(string):
        csum = csum + ord(string[len(str) - 1])
        csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def receiveOnePing(mySocket, ID, timeout, destAddr):
    global rtt_min, rtt_max, rtt_sum, rtt_cnt
    timeLeft = timeout
    while 1:
        startedSelect = time.time()
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = (time.time() - startedSelect)
        if whatReady[0] == []:  # Timeout
            return "Request timed out."

        timeReceived = time.time()
        recPacket, addr = mySocket.recvfrom(1024)

        # TODO
        # Fetch the ICMP header from the IP packet

        icmp_header = recPacket[20:28]  
        icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq = struct.unpack("bbHHh", icmp_header)

        packet_size = struct.pack('!I', len(recPacket))
        size = int.from_bytes(packet_size, byteorder='big')

        if icmp_type == 0 :
            
            timeSent = struct.unpack("d", recPacket[28:36])[0] 
            rtt = (timeReceived - timeSent) * 1000  
            
           
            rtt_cnt += 1
            rtt_sum += rtt
            if rtt < rtt_min:
                rtt_min = rtt
            if rtt > rtt_max:
                rtt_max = rtt
            

            rtt_s = "{:.2f}".format(rtt)
            print(str(size)+" bytes from "+sys.argv[1]+"; time = "+rtt_s+" ms")
            
            return float(rtt_s)
        
        # TODO END

        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return "Request timed out."#and icmp_id == ID


def sendOnePing(mySocket, destAddr, ID):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)

    myChecksum = 0
    # Make a dummy header with a 0 checksum.
    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    data = struct.pack("d", time.time())    # 8 bytes
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)

    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        myChecksum = socket.htons(myChecksum) & 0xffff
        # Convert 16-bit integers from host to network byte order.
    else:
        myChecksum = socket.htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    packet = header + data

    mySocket.sendto(packet, (destAddr, 1))  # AF_INET address must be tuple, not str
    # Both LISTS and TUPLES consist of a number of objects
    # which can be referenced by their position number within the object


def doOnePing(destAddr, timeout):
    icmp = socket.getprotobyname("icmp")
    # SOCK_RAW is a powerful socket type. For more details see: http://sock-raw.org/papers/sock_raw

    # TODO
    # Create Socket here
    
    try:
        mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        mySocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', 64))
    except socket.error as e:
        raise Exception(f"Socket Error: {e}")
    # TODO END

    myID = os.getpid() & 0xFFFF  # Return the current process i
    sendOnePing(mySocket, destAddr, myID)
    delay = receiveOnePing(mySocket, myID, timeout, destAddr)

    mySocket.close()
    return delay


def ping(host, timeout=1):
    global rtt_min, rtt_max, rtt_sum, rtt_cnt
    cnt = 0
    # timeout=1 means: If one second goes by without a reply from the server,
    # the client assumes that either the client's ping or the server's pong is lost
    dest = socket.gethostbyname(host)
    print("Pinging " + dest + " using Python:")
    # Send ping requests to a server separated by approximately one second
    try:
        while True:
            cnt += 1
            doOnePing(dest, timeout)
            time.sleep(1)
    except KeyboardInterrupt:
        # TODO
        # calculate statistic here
        rtt_avg = rtt_sum/rtt_cnt
        rtt_min_s = f"{rtt_min:.3f}"
        rtt_avg_s = f"{rtt_avg:.3f}"
        rtt_max_s = f"{rtt_max:.3f}"
        print("round-trip min/avg/max "+rtt_min_s+"/"+rtt_avg_s+"/"+rtt_max_s+"ms")
        # TODO END

if __name__ == '__main__':
    ping(sys.argv[1])
