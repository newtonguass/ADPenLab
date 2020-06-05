import hashlib, binascii, argparse
parser = argparse.ArgumentParser()
parser.add_argument("-p", "--passwd", required=True, help="input the password to trainsform to NTLM hash")

args = parser.parse_args()
hash_ = hashlib.new('md4',args.passwd.encode('utf-16le')).digest()
print(binascii.hexlify(hash_))
