from crypto.PublicKey import DSA
from crypto.Signature import DSS
from crypto.Hash import SHA256

key = DSA.generate(2048)
f = open("public_key.pem", "w")
f.write(key.publickey().export_key())
f.close()

message = b"Hello"
hash_obj = SHA256.new(message)
signer = DSS.new(key, 'fips-186-3')
signature = signer.sign(hash_obj)

f = open("public_key.pem", "r")
hash_obj = SHA256.new(message)
pub_key = DSA.import_key(f.read())
verifier = DSS.new(pub_key, 'fips-186-3')

try:
    verifier.verify(hash_obj, signature)
    print ("The message is authentic.")
except ValueError:
    print ("The message is not authentic.")