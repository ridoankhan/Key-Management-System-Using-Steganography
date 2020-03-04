import socket
import select
import sys
import hashlib
import struct
import numpy
import matplotlib.pyplot as plt

from PIL import Image
from Crypto import Random
from Crypto.Cipher import AES

class AESCipher:

            def __init__(self, key): 
                self.bs = 32	# Block size
                self.key = hashlib.sha256(key.encode()).digest()	# 32 bit digest

            def encrypt(self, raw):
                raw = self._pad(raw)
                iv = Random.new().read(AES.block_size)
                cipher = AES.new(self.key, AES.MODE_CBC, iv)
                return iv + cipher.encrypt(raw)

            def decrypt(self, enc):
                iv = enc[:AES.block_size]
                cipher = AES.new(self.key, AES.MODE_CBC, iv)
                return self._unpad(cipher.decrypt(enc[AES.block_size:]))

            def _pad(self, s):
                return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

            @staticmethod
            def _unpad(s):
                return s[:-ord(s[len(s)-1:])]

# Decompose a binary file into an array of bits
def decompose(data):
        v = []

        # Pack file len in 4 bytes
        fSize = len(data)
        bytes = [ord(b) for b in struct.pack("i", fSize)]

        bytes += [ord(b) for b in data]

        for b in bytes:
	        for i in range(7, -1, -1):
		        v.append((b >> i) & 0x1)

        return v

# Assemble an array of bits into a binary file
def assemble(v):    
        bytes = ""

        length = len(v)
        for idx in range(0, len(v)/8):
	        byte = 0
	        for i in range(0, 8):
		        if (idx*8+i < length):
			        byte = (byte<<1) + v[idx*8+i]                
	        bytes = bytes + chr(byte)

        data_size = struct.unpack("i", bytes[:4])[0]

        return bytes[4: data_size + 4]

# Set the i-th bit of v to x
def set_bit(n, i, x):
        mask = 1 << i
        n &= ~mask
        if x:
                n |= mask
        return n

# Embed data file into LSB bits of an image
def embed(imgFile, data, password):
        # Process source image
        img = Image.open(imgFile)
        (width, height) = img.size
        conv = img.convert("RGBA").getdata()
        print "[*] Input image size: %dx%d pixels." % (width, height)
        max_size = width*height*3.0/8/1024		# max data size
        print "[*] Usable data size: %.2f KB." % (max_size)

        f = open(data, "rb")
        data = f.read()
        f.close()
        print "[+] data size: %.3f KB " % (len(data)/1024.0)

        # Encypt
        cipher = AESCipher(password)
        data_enc = cipher.encrypt(data)

        # Process data from data file
        v = decompose(data_enc)

        # Add until multiple of 3
        while(len(v)%3):
	        v.append(0)

        data_size = len(v)/8/1024.0
        print "[+] Encrypted data size: %.3f KB " % (data_size)
        if (data_size > max_size - 4):
	        print "[-] Cannot embed. File too large"
	        sys.exit()
	
        # Create output image
        steg_img = Image.new('RGBA',(width, height))
        data_img = steg_img.getdata()

        idx = 0

        for h in range(height):
	        for w in range(width):
		        (r, g, b, a) = conv.getpixel((w, h))
		        if idx < len(v):
			        r = set_bit(r, 0, v[idx])
			        g = set_bit(g, 0, v[idx+1])
			        b = set_bit(b, 0, v[idx+2])
		        data_img.putpixel((w,h), (r, g, b, a))
		        idx = idx + 3
            
        steg_img.save(imgFile + "-stego.png", "PNG")
        savingstr="imgFile" + "-stego.png", "PNG"
        print "[+] %s embedded successfully!"
        print "The password has been saved successfully"


# Extract data embedded into LSB of the input file
def extract(in_file, out_file, password):
        # Process source image
        img = Image.open(in_file)
        (width, height) = img.size
        conv = img.convert("RGBA").getdata()
        print "[+] Image size: %dx%d pixels." % (width, height)

        # Extract LSBs
        v = []
        for h in range(height):
	        for w in range(width):
		        (r, g, b, a) = conv.getpixel((w, h))
		        v.append(r & 1)
		        v.append(g & 1)
		        v.append(b & 1)
		
        data_out = assemble(v)

        # Decrypt
        cipher = AESCipher(password)
        data_dec = cipher.decrypt(data_out)

        # Write decrypted data
        out_f = open(out_file, "wb")
        out_f.write(data_dec)
        out_f.close()

        print "[+] Written extracted data to %s." % out_file

def find(str):
        f=open("hello.txt")
        text = f.read().strip().split() 
        while True:
                if str == "": 
                        continue
                if str in text: 
                        return 1
                        break
                else:
                        return 2
                        continue
                f.close()
def main():
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if len(sys.argv) != 3:
	        print "Correct usage: script, IP address, port number"
	        exit()
        IP_address = str(sys.argv[1])
        Port = int(sys.argv[2])
        server.connect((IP_address, Port))

        while True:
	        sockets_list = [sys.stdin, server]
	        read_sockets,write_socket, error_socket = select.select(sockets_list,[],[])

	        for socks in read_sockets:
		        if socks == server:
			        message = socks.recv(2048)
			        print message
		        else:
			        message = sys.stdin.readline()
			        server.send(message)
			        sys.stdout.write("Server: ")
			        sys.stdout.write(message)
			        sys.stdout.flush()
                                
                i=1
                print"Welcome to the Decentralized Cloud Management System"
                print"1- Register or 2 - Login"
                while i<3:
                        se=int(raw_input("Enter Your Choice: "))
                        j=0
                        if se == 1:
                                name=str(raw_input('Enter Your Name: '))
                                usr1=raw_input("Enter Login Username: ")
                                email=raw_input("Enter Your Email Address: ")
                                pwd1=raw_input("Enter Your Password: ")
                                print "Successfully Registered"
                                f= open("hello.txt","a+")
                                f.write("Name: " + name + '\n' + "Username: " + usr1 + '\n' + "Email: " + email + '\n' + "Password: " + pwd1 + '\n\n\n\n'+ "**************************" + '\n\n\n')
                                f.close()
                        elif se == 2: 
                                usr2=raw_input("Enter Username: ")
                                pwd2=raw_input("Enter Password: ")
                                                
                                result1=find(usr2)
                                result2=find(pwd2)
                                if result1==1 and result2==1:
                                        print "Successfully Logged-In"
                                        print"Choose a Your Service: "
	                                print"1 - Hide    2 - Extract    3 - Seacrh Key"
	                                choice1=int(raw_input("Enter Your Choice: "))
                                        if choice1 ==1:
	                                        imageFile=raw_input("Enter Image File Name: ")
                                                dataFile=raw_input("Enter the Data File Containing Secret Message: ")
                                                ek=raw_input("Enter The Encryption Key to Encode the Data: ")
	                                        embed(imageFile,dataFile,ek)
                                        elif choice1 ==2:
                	                        encFile=raw_input("Enter Encrypted Image File Name: ")
	                                        outFile=raw_input("Enter the Output File to Show Plain Text: ")
	                                        ek2=raw_input("Enter the Encryption Key: ")
	                                        extract(encFile,outFile,ek2)
                                        elif choice1 ==3:
                                                fname=raw_input("Enter the Encrypted Image File Name")
                                else:
                                        print "Wrong Username or password"
                                        print "Enter your choice(1|2)"
                        elif se==3:
                                print"Thank You for using Decentralized KMS"
                        break
                break
                
if __name__=="__main__":
        main()
