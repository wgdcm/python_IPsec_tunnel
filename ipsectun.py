import struct
from ctypes import *
import os
from fcntl import ioctl
import socket
import threading
import signal
import hashlib
import sys
import re
from random import randint
try:
   from Crypto.Cipher import AES
except ModuleNotFoundError:
   print ("Install pycrypto using 'sudo pip install pycrypto'" )
   sys.exit()

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
ex_event = threading.Event()

def tun_open(devname):
   fd = os.open("/dev/net/tun", os.O_RDWR)
   ifr = struct.pack("16sH", devname.encode("utf-8"), IFF_TUN | IFF_NO_PI)
   ifs = ioctl(fd, TUNSETIFF, ifr)
   return fd

hostname = socket.gethostname()
src_ip = socket.gethostbyname(hostname)
try:
   dst_ip = input('Type the correct destination IP address on the PC: ')
   regex = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
   result = regex.match(dst_ip)
   if not result:
      print ('Please Type the correct destination IP')
      sys.exit()
except KeyboardInterrupt:
   print ('Exit Tunnel Program.')
   sys.exit()
except Exception:
   print ('There was an error fetching the destination IP.')
   sys.exit()

try:
   sndsock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
   sndsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
   sndsock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL,1)
   
   inter = input("Type the name of your computer's interface: ")
   rcvsock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
   rcvsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
   rcvsock.bind((inter, 0))

   interv = input('Type the tunnel interface name: ')
   fd = tun_open(interv)
except OSError:
   print ('No such interface')
   sys.exit()
except Exception:
   print ('Error capturing or sending packets.')
   sys.exit()
except KeyboardInterrupt:
   print ('Exit.')
   sys.exit()

def ip_header(len):
   ip_version = 4
   ip_ihl = 5
   ip_tos = 0
   ip_len = len
   ip_id = 23564
   ip_offset = 0
   ip_ttl = 64
   ip_protocal = 50
   ip_sum = 0
   ip_src = socket.inet_aton (src_ip)
   ip_dst = socket.inet_aton (dst_ip)

   ip_verihl = (ip_version << 4) + ip_ihl

   ip_hgen = struct.pack('!BBHHHBBH4s4s', ip_verihl, ip_tos, ip_len, ip_id, ip_offset, ip_ttl, ip_protocal, ip_sum, ip_src, ip_dst)
   return ip_hgen

def esp(spino, seqno, len):
    spi = spino
    esp_seq = seqno
    esp_plen = len
    esp_nhead = 0
    esp_head = struct.pack('!LL', spi, esp_seq)
    esp_tail = struct.pack('!BB', esp_plen, esp_nhead)
    return esp_head, esp_tail

def encrypt_decrypt(ende, data):
   try:
      key = 'qqqqwwwweeeerrrr'
      if ende == 1:
         aes = AES.new(key)
         cipher = aes.encrypt(data)
         return (cipher)
      elif ende == 0:
         aes = AES.new(key)
         writedata = aes.decrypt(data)
         return (writedata)
   except ValueError:
      pass
   except Exception:
      pass

def signal_handler(signum, frame):
     os.close(fd)
     print("\nExit Tunnel Program. Please Press 'Ctrl+Z' to exit.")
     ex_event.set()
     sndsock.close()

signal.signal(signal.SIGINT, signal_handler)
print ('Start IPsec Tunnel')
print('Packets Sending And Receiving', end='', flush=True)

def snd_data():
   while True:
      sqno = randint(0, 0xFFFF)
      spi = randint(0, 0xFFFF)
      asapack = os.read(fd, 1600)
      if (len(asapack)+2) % 16 == 0:
         espp = esp(spi, sqno, 0)
         hashs = hashlib.md5(espp[0] + asapack + espp[1]).hexdigest()
         encrypted = encrypt_decrypt(1, (asapack + espp[1]))
         senddata = ip_header(len(asapack)) + espp[0] + encrypted  + hashs.encode('utf-8') + len(asapack).to_bytes(2, 'big')
      else:
         padlen = 14 - (len(asapack) % 16)
         paddata = ('0' * padlen).encode('utf-8')
         espp = esp(spi, sqno, padlen)
         hashs = hashlib.md5(espp[0] + asapack + paddata + espp[1]).hexdigest()
         encrypted = encrypt_decrypt(1, (asapack + paddata + espp[1]))
         senddata = ip_header(len(asapack+paddata)) + espp[0] + encrypted  + hashs.encode('utf-8') + len(asapack+paddata).to_bytes(2, 'big')
      try:
         sndsock.sendto(senddata, (dst_ip, 0))
      except OSError:
         pass
      if ex_event.is_set():
         break

def rcv_data():
   while True:
      data = rcvsock.recvfrom(65536)[0]
      ipverihl, iptos, iplen, ipid, ipoffset, ipttl, ipprotocal, ipsum, ipsrc, ipdst = struct.unpack('!BBHHHBBH4s4s', data[14:34])
      iplen1 = int.from_bytes(data[-2:], "big")
      decrypted = encrypt_decrypt(0, (data[42:44+iplen1]))
      if decrypted == None:
         continue
      else:
         hashr = hashlib.md5(data[34:42]+decrypted).hexdigest()
         try:
            if hashr == (data[44+iplen1:-2]).decode('utf-8') and ipprotocal == 50:
               os.write(fd, decrypted[:iplen1])
         except Exception:
            pass
      print ('.', end='', flush=True)
      if ex_event.is_set():
         break

snd_data = threading.Thread(target = snd_data)
rcv_data = threading.Thread(target = rcv_data)
snd_data.start()
rcv_data.start()

