'''
Created on 2013-3-14

Raw sockets on Linux

@author: Hao
'''


# some imports
import socket, sys
import fcntl
from struct import *
import select
import random
ERR_ADDR = -1
CORRUPT_PKG = -1
RECV_ACK = 0
RECV_SUC = 1
RECV_COMPLETE = 2
CLOSE = 3
timeout_in_seconds = 5
def getip(ethname):
    if ethname=="":
        ethname="eth0"
    try:
        s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ip=socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0X8915, pack('256s', ethname[:15]))[20:24])
    except:
        ip=""
    return ip

class Rawhttpget:
    seq_num = random.randint(100000000,1000000000)
    ack_num = 0
    # save the user data received from the server (app level)
    data = ""
    flag = 0
    # initialize the host, port and raw socket
    def __init__(self,url):
        # retrieval the host, page, and filename from the url
        url = url[url.find('http://')+len('http://'):]
        if url.find('/') >= 0:
            self.host = url[:url.find('/')]
            self.page = url[url.find('/'):]
        else:
            self.host = url
            self.page = '/'
            url = ''
        
        while url.find('/') >= 0:
            url = url[url.find('/')+1:]
        self.file = url
        if self.file == '':
            self.file = 'index.html'

        self.src_ip = getip("eth0")
        print self.src_ip
        self.dst_ip = socket.gethostbyname(self.host) 
        self.srcport = 57890
        self.dstport = 80
        # create a raw socket
        try:
            self.send_fd = socket.socket(socket.AF_INET,socket.SOCK_RAW, socket.IPPROTO_RAW)
            self.recv_fd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            # Include IP headers
            self.recv_fd.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self.recv_fd.bind(("0.0.0.0", self.srcport))
            
        except socket.error , msg:
            print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
            sys.exit()
        print self.host, self.page, self.file
    # checksum functions needed for calculation checksum
    def checksum(self,msg):
        s = 0
        # loop taking 2 characters at a time
        for i in range(0, len(msg), 2):
            w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
            s = s + w
        
        s = (s>>16) + (s & 0xffff);
        s = s + (s >> 16);
        
        # complement and mask to 4 byte short
        s = ~s & 0xffff
        
        return s
    def construct_pkg(self,flag,data):
        # the packet used to send
        packet = ''   
        #---------------------------------------------------------------------------------------------
        # ip header fields
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 40 + len(data)     # kernel will fill the correct total length
        ip_id = 54321                   # Id of this packet
        ip_frag_off = 0
        ip_ttl = 255
        ip_proto = socket.IPPROTO_TCP
        ip_check = 0                    # kernel will fill the correct checksum
        ip_saddr = socket.inet_aton (self.src_ip)
        ip_daddr = socket.inet_aton (self.dst_ip)
        ip_ihl_ver = (ip_ver << 4) + ip_ihl
        
        # the ! in the pack format string means network order
        ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, \
                         ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
        ip_check = self.checksum(ip_header)
        # pack again, fill the correct ip check sum, but the kernel will also fill the correct checksum.
        ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, \
                         ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
        #--------------------------------------------------------------------------------------------
        # tcp header fields
        tcp_source = self.srcport       # source port
        tcp_dest = self.dstport         # destination port
        tcp_seq = self.seq_num
        tcp_ack_seq = self.ack_num
        tcp_doff = 5                    # 4 bit field, size of tcp header, 5 * 4 = 20 bytes
        # tcp flags
        tcp_fin = flag[0]
        tcp_syn = flag[1]
        tcp_rst = flag[2]
        tcp_psh = flag[3]
        tcp_ack = flag[4]
        tcp_urg = flag[5]
        tcp_window = 65535              # maximum allowed window size
        tcp_check = 0                   # calculate it later
        tcp_urg_ptr = 0
        tcp_offset_res = (tcp_doff << 4) + 0
        tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + \
                    (tcp_ack << 4) + (tcp_urg << 5)
        
        # test use
        print "seq num:",tcp_seq
        print "ack num:",tcp_ack_seq
#        print "tcp flag:",tcp_flags

        # the ! in the pack format string means network order
        tcp_header = pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, \
                          tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)
                
        # pseudo header fields
        source_address = socket.inet_aton(self.src_ip)
        dest_address = socket.inet_aton(self.dst_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header) + len(data)
        
        psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
        psh = psh + tcp_header + data;
        tcp_check = self.checksum(psh)
        #print data
        # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
        tcp_header = pack('!HHLLBBH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, \
                          tcp_flags,  tcp_window) + pack('H' , tcp_check) + pack('!H' , tcp_urg_ptr)
        #---------------------------------------------------------------------------------------------------
        # final full packet - syn packets dont have any data
        packet = ip_header + tcp_header + data
        return packet
    def process_pkt(self,pkt,addr):
        # we don't process the pkt from the other addrs
        if addr != self.dst_ip:
            return ERR_ADDR
        #---------------------------------------------------------------------------------------------------
        # take first 20 characters for the ip header
        ip_header = pkt[0:20]
        
        # now unpack them :)
        iph = unpack('!BBHHHBBH4s4s' , ip_header)
        
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);
        
        
#        print 'Version : ' + str(version) + \
#                    ' IP Header Length : ' + str(ihl) + \
#                    ' TTL : ' + str(ttl) + \
#                    ' Protocol : ' + str(protocol) + \
#                    ' Source Address : ' + str(s_addr) + \
#                    ' Destination Address : ' + str(d_addr)
        #---------------------------------------------------------------------------------------------------
        # take second 20 characters for the tcp header
        tcp_header = pkt[iph_length:iph_length+20]
        
        # now unpack them :)
        tcph = unpack('!HHLLBBHHH' , tcp_header)
        
        source_port = tcph[0]
        dest_port = tcph[1]
        sequence = tcph[2]
        acknowledgement = tcph[3]
        doff_reserved = tcph[4]
        tcph_length = doff_reserved >> 4
        tcp_flag = tcph[5]
        tcp_check = tcph[7]

#        print 'Source Port : ' + str(source_port) + \
#            ' Dest Port : ' + str(dest_port) + \
#            ' Sequence Number : ' + str(sequence) + \
#            ' Acknowledgement : ' + str(acknowledgement) + \
#            ' TCP header length : ' + str(tcph_length) + \
#            ' tcp_flag : ' + str(tcp_flag)
        #---------------------------------------------------------------------------------------------------
        # take the rest characters for the user data
        # get data from the packet
        h_size = iph_length + tcph_length * 4
        data_size = len(pkt) - h_size

        self.data += pkt[h_size:]
       
        
        #---------------------------------------------------------------------------------------------------
        # don't care ACK packet
        if tcp_flag == 16 and data_size == 0:
            return RECV_ACK
        if self.seq_num > acknowledgement or self.ack_num > sequence:
            return CORRUPT_PKG
#        check_sum = self.checksum(tcp_header)
#        if check_sum != tcp_check:
#            return CORRUPT_PKG
        # calculate the seq num and ack num for the next move
        if data_size == 0:
            self.seq_num = acknowledgement
            self.ack_num = sequence + 1
        else:
            self.seq_num = acknowledgement
            self.ack_num = sequence + data_size
            
        # that means we successful received the whole package
        if tcp_flag == 24:
            return RECV_COMPLETE
        
        return RECV_SUC
    def connect(self):
        
        flag = (0,1,0,0,0,0)
        packet = self.construct_pkg(flag, '')    
        #Send the packet finally - the port specified has no effect
        self.send_fd.sendto(packet, (self.dst_ip , 0 ))

        # receive a package
        while 1:
            ready = select.select([self.recv_fd], [], [], timeout_in_seconds)
            if ready[0]:
                rec_packet,addr = self.recv_fd.recvfrom(2048)
                ret = self.process_pkt(rec_packet,addr[0])
                if ret == RECV_SUC :
                    flag = (0,0,0,0,1,0)
                    packet = self.construct_pkg(flag,'')
                    self.send_fd.sendto(packet, (self.dst_ip , 0 ))
                    break
                else:
                    print 'error'
                    flag = (0,1,0,0,0,0)
                    packet = self.construct_pkg(flag,'')
                    self.send_fd.sendto(packet, (self.dst_ip , 0 ))
                    sys.exit()
            else:
                self.send_fd.sendto(packet, (self.dst_ip , 0 ))
        
        return True
                
    def http_request(self):
        request = ''.join(("GET %s HTTP/1.1\r\n" % self.page) 
                          + ("Host: %s\r\n" % self.host) 
                          +"User-Agent:Mozilla/4.0\r\n"
                          +"Accept: */*\r\n"
                          +"Connection: keep-alive\r\n\r\n"
                          )
        flag = (0,0,0,1,1,0)
        packet = self.construct_pkg(flag, request)
        #Send the packet finally - the port specified has no effect
        self.send_fd.sendto(packet, (self.dst_ip , 0 ))    
    def http_reponse(self):
        packets = []
        while 1:
            ready = select.select([self.recv_fd], [], [], timeout_in_seconds)
            if ready[0]:
                rec_packet,addr = self.recv_fd.recvfrom(2048)
                ret = self.process_pkt(rec_packet,addr[0])
                if ret == RECV_SUC or ret == RECV_COMPLETE or ret == CLOSE:
                    flag = (0,0,0,0,1,0)
                    packet = self.construct_pkg(flag,'')
                    packets.append(packet)
                if ret == RECV_COMPLETE:
                    break
                if ret == ERR_ADDR or ret == CORRUPT_PKG:
                    print "error"
                    flag = (0,0,1,0,0,0)
                    packet = self.construct_pkg(flag,'')
                    self.send_fd.sendto(packet, (self.dst_ip , 0 ))
                    sys.exit()
            else:
                self.http_request()
           
        for packet in packets:
            self.send_fd.sendto(packet, (self.dst_ip , 0 ))
            packets = []
        
        self.data = self.data[self.data.find('\r\n\r\n')+4:]
        #self.data = self.data[self.data.find('<html>'):self.data.find('</html>')+len('</html>')]
#        print self.data
    def close_connection(self):
        flag = (1,0,0,0,1,0)
        packet = self.construct_pkg(flag,'')
        self.send_fd.sendto(packet, (self.dst_ip , 0 ))
        while 1:
            ready = select.select([self.recv_fd], [], [], timeout_in_seconds)
            if ready[0]:
                rec_packet,addr = self.recv_fd.recvfrom(2048)
                ret = self.process_pkt(rec_packet,addr[0])
                if ret == RECV_SUC or ret == CLOSE:
                    flag = (0,0,0,0,1,0)
                    packet = self.construct_pkg(flag,'')
                    self.send_fd.sendto(packet, (self.dst_ip , 0 ))
                    break
                if ret == ERR_ADDR or ret == CORRUPT_PKG:
                    print "error"
                    flag = (0,0,1,0,0,0)
                    packet = self.construct_pkg(flag,'')
                    self.send_fd.sendto(packet, (self.dst_ip , 0 ))
                    sys.exit()
            else:
                self.send_fd.sendto(packet, (self.dst_ip , 0 ))
                
        self.send_fd.close()
        self.recv_fd.close()
    def save_to_file(self):
        fd = open(self.file,'w')
        fd.write(self.data)
        fd.close()
    def get_content(self):
        print "------------connect----------------"
        self.connect()
        print "------------request----------------"
        self.http_request()
        print "------------response---------------"
        self.http_reponse()
        print "------------close------------------"
        self.close_connection()
        self.save_to_file()
        
        
def run():
    if len(sys.argv) < 2:
        print "use: %s <Address>\n" % (sys.argv[0])
        quit()
    else:
        address = sys.argv[1]
        
    crawler  = Rawhttpget(address)
    crawler.get_content()

if __name__ == '__main__':

    run()
