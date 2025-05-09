import socket
import time
import random
import sys
from hashlib import sha256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

time.sleep(0.1)
key = RSA.generate(2048)
publickey2send = key.publickey()

# Creating a TCP connection with the personal server (PS)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = socket.gethostname()
port = 40192

# Data generated by the Sensor
num1 = 'HEART :: Systole value: ' + str(random.randint(1, 101))
num2 = 'HEART :: Distole value: ' + str(random.randint(109, 700))
num3 = 'HEART :: Beats per min: ' + str(random.randint(60, 71))
bye = "BYE"

# Connecting with the PS
s.connect((host, port))

# Key Exchange
ServersPubkey = RSA.import_key(s.recv(2048))
print('Client :: Received the servers public key')
s.send(publickey2send.export_key())
time.sleep(2)
print('Sending our public key!')
time.sleep(1)
print('Key exchange successful!\n')

# Authenticating Identity
data = s.recv(1024)
cipher = PKCS1_OAEP.new(key)
decrypted = cipher.decrypt(data).decode()
print(decrypted)
nonce = str(random.randint(0, 10000))
print('Nonce sent = ' + nonce)
time.sleep(2)
cipher = PKCS1_OAEP.new(ServersPubkey)
E_nonce = cipher.encrypt(nonce.encode())
s.sendall(E_nonce)
temp = s.recv(2049)
cipher = PKCS1_OAEP.new(key)  # Sửa ở đây: Dùng khóa riêng của client
R_nonce = cipher.decrypt(temp).decode()
print('Nonce received back = ' + R_nonce)
if str(R_nonce) == str(nonce):
    print('Authentication successful!!')
else:
    print('Authentication failed')
    s.close()
    sys.exit()

s.send(b' ')
temp2 = s.recv(2049)
cipher = PKCS1_OAEP.new(key)
d_nonce2 = cipher.decrypt(temp2).decode()
cipher = PKCS1_OAEP.new(ServersPubkey)
E_d_nonce2 = cipher.encrypt(d_nonce2.encode())
s.sendall(E_d_nonce2)

# Authentication completion

# Sending num1
print('Message to be sent :: ')
time.sleep(1)
print(num1)

h = sha256(num1.encode('utf-8'))
print('Generating Digest!')
time.sleep(2)
print(h.hexdigest())
cipher = PKCS1_OAEP.new(ServersPubkey)
Tencypted = cipher.encrypt(num1.encode())
print('Encrypted message looks like this ::')
time.sleep(2)
print(str(Tencypted))
print('\n')
s.sendall(Tencypted)
s.recv(16)  # Dummy recv
s.send(h.hexdigest().encode())
time.sleep(1)
print('Sending all data to Personal server')

# Sending num2
print('Message to be sent :: ')
time.sleep(1)
print(num2)

h = sha256(num2.encode('utf-8'))
print('Generating Digest!')
time.sleep(2)
print(h.hexdigest())
cipher = PKCS1_OAEP.new(ServersPubkey)
Tencypted = cipher.encrypt(num2.encode())
print('Encrypted message looks like this ::')
time.sleep(2)
print(str(Tencypted))
print('\n')
s.sendall(Tencypted)
s.recv(16)  # Dummy recv
s.send(h.hexdigest().encode())
time.sleep(1)
print('Sending all data to Personal server')

# Sending num3
print('Message to be sent :: ')
time.sleep(1)
print(num3)

h = sha256(num3.encode('utf-8'))
print('Generating Digest!')
time.sleep(2)
print(h.hexdigest())
cipher = PKCS1_OAEP.new(ServersPubkey)
Tencypted = cipher.encrypt(num3.encode())
print('Encrypted message looks like this ::')
time.sleep(2)
print(str(Tencypted))
print('\n')
s.sendall(Tencypted)
s.recv(16)  # Dummy recv
s.send(h.hexdigest().encode())
time.sleep(1)
print('Sending all data to Personal server')

# Sending BYE message
print('Message to be sent :: ')
time.sleep(1)
print(bye)

h = sha256(bye.encode('utf-8'))
print('Generating Digest!')
time.sleep(2)
print(h.hexdigest())
cipher = PKCS1_OAEP.new(ServersPubkey)
Tencypted = cipher.encrypt(bye.encode())
print('Encrypted message looks like this ::')
time.sleep(2)
print(str(Tencypted))
print('\n')
s.sendall(Tencypted)
s.recv(16)  # Dummy recv
s.send(h.hexdigest().encode())
time.sleep(1)
print('Sent all data to Personal server')

# Closing connection
s.close()