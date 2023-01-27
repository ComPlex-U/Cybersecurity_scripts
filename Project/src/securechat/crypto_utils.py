import struct
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
import time
import os


class crypto_utils():
    PRIV_KEY = ""
    PUB_KEY = ""
    PRIV_KEY_FILE = "/priv.key"
    PUB_KEY_FILE = "/pub.key"
    DEBUG = True

    def generateKeyPair(self):
        key = RSA.generate(2048)
        self.PUB_KEY = key.publickey().exportKey()
        self.PRIV_KEY = key.exportKey()
        file_name = str(time.time())+".priv"
        print("Storing private key in file {}".format(file_name))
        key_file = open(str(time.time())+"priv", 'wb')
        key_file.write(self.PRIV_KEY)
        
        return self.PUB_KEY, self.PRIV_KEY
        
    def encrypt_message(self, message, key):
        rsa_key = RSA.importKey(key)
        encryptor = PKCS1_OAEP.new(rsa_key)
        encrypted_msg = encryptor.encrypt(message)
        return encrypted_msg
    
    def decrypt_message(self, message, key):
        if len(self.PRIV_KEY) > 0:
            key = self.PRIV_KEY
        rsa_key = RSA.importKey(key)
        decriptor = PKCS1_OAEP.new(rsa_key)
        decripted_message = decriptor.decrypt(message)
        return decripted_message
    
    def decrypt_messages_file(self):
        mFolder = input("Messages folder: ")
        kFilename = input("Key filename: ")        
        try:
            keyFile = open(kFilename, "rb")
        except:
            print("Error, please make sure you have specified the correct filepath {}".format(kFilename))
            self.decrypt_messages_file()
        rsa_key = RSA.importKey(keyFile.read())
        decriptor = PKCS1_OAEP.new(rsa_key)
        for item in os.walk(mFolder):
            for index,file in enumerate(item[2]):
                try:
                    mfile = open(item[0]+'/'+file, "rb")
                except:
                    print("Error, please make sure you have specified the correct filepath {}".format(kFilename))
                    self.decrypt_messages_file()

                fileContent = bytearray(mfile.read())
                decripted_message = decriptor.decrypt(bytes(fileContent))
                print("Message "+str(index + 1)+": "+ decripted_message.decode('utf-8'))
        keyFile.close()

    
    