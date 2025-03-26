import socket
import threading
import time
import datetime
import random
from hashlib import sha256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

time.sleep(0.1)

# PS Socket creation
def Main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = socket.gethostname()
    port = 40192
    s.bind((host, port))
    s.listen(10)
    print('Server up and running!!')
    print('Waiting for Sensors')
    while True:
        c, addr = s.accept()
        threading.Thread(target=myfun, args=(c, addr)).start()

def myfun(c, addr):
    # Generating Keys using RSA algorithm
    print('Generating Keys!')
    time.sleep(2)
    key = RSA.generate(2048)
    publickey2send = key.publickey()
    print('Keys generated!... Exchanging public keys')
    # Exchanging public key
    c.send(publickey2send.export_key())
    ClientsPubKey = RSA.import_key(c.recv(2048))
    time.sleep(2)
    print('Keys exchange successful!')

    # Authentication of the sensor
    dummy = 'Pls authenticate yourself '
    cipher = PKCS1_OAEP.new(ClientsPubKey)
    Tencypted = cipher.encrypt(dummy.encode())
    c.sendall(Tencypted)
    # Sensor replies back with a nonce
    temp = c.recv(2049)
    if not temp:  # Kiểm tra kết nối bị ngắt
        print("Connection closed by client during authentication")
        c.close()
        return
    cipher = PKCS1_OAEP.new(key)
    d_nonce = cipher.decrypt(temp)
    time.sleep(2)
    print('Nonce received from sensor side')
    time.sleep(1)
    print('nonce received -> ' + d_nonce.decode())
    cipher = PKCS1_OAEP.new(ClientsPubKey)
    E_d_nonce = cipher.encrypt(d_nonce)
    c.sendall(E_d_nonce)

    c.recv(10)  # Dummy
    nonce2 = str(random.randint(0, 10000))
    print('Nonce sent = ' + nonce2)
    cipher = PKCS1_OAEP.new(ClientsPubKey)
    E_nonce2 = cipher.encrypt(nonce2.encode())
    c.sendall(E_nonce2)
    temp2 = c.recv(2049)
    if not temp2:  # Kiểm tra kết nối bị ngắt
        print("Connection closed by client during authentication")
        c.close()
        return
    cipher = PKCS1_OAEP.new(key)
    R_nonce2 = cipher.decrypt(temp2)
    print('Nonce received back = ' + R_nonce2.decode())
    if R_nonce2.decode() == nonce2:
        print('Authentication successful!!')
    else:
        print('Authentication failed')
        c.close()
        return

    # Authentication complete
    time.sleep(2)

    # Open file to store the contents
    with open("DataFile.txt", "ab") as f:
        time2 = str(datetime.datetime.now())
        f.write(time2.encode())
        f.write(b'\n')

        while True:
            print('Data received! Decryption in process')
            data = c.recv(2048)
            if not data:
                break
            time.sleep(1)
            print('msg decrypted')
            cipher = PKCS1_OAEP.new(key)
            msg = cipher.decrypt(data).decode()
            print('Decrypted msg = ' + msg)
            c.send(b"a")

            # Checking message authenticity
            hashrecv = c.recv(256).decode()
            print('hash received = ' + hashrecv)
            h = sha256(msg.encode('utf-8'))
            if h.hexdigest() != hashrecv:
                print('hashes dont match!')
                break
            else:
                print('Matching hashes ...')
                time.sleep(2)
                print('hashes match! msg unhampered!')
                f.write(msg.encode())
                f.write(b'\n')

            if msg == "BYE":
                break

    c.close()

if __name__ == "__main__":
    Main()