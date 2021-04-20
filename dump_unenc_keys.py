import binascii
import hashlib
import codecs
import mmap
import sys

# Define base58
def base58(address_hex):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    b58_string = ''
    # Get the number of leading zeros
    leading_zeros = len(address_hex) - len(address_hex.lstrip('0'))
    # Convert hex to decimal
    address_int = int(address_hex, 16)
    # Append digits to the start of string
    while address_int > 0:
        digit = address_int % 58
        digit_char = alphabet[digit]
        b58_string = digit_char + b58_string
        address_int //= 58
    # Add ‘1’ for each 2 leading zeros
    ones = leading_zeros // 2
    for one in range(ones):
        b58_string = '1' + b58_string
    return b58_string


def main():

    f = open(sys.argv[1], "rb")
    mm = mmap.mmap(f.fileno(),0,prot=mmap.PROT_READ)
    currindex = mm.find(b'\x02\x01\x01\x04\x20')
    privkeyList = set()
    while(currindex > -1):
        mm.seek(currindex+5)
        #print(binascii.hexlify(mm.read(32)))
        privkeyList.add(mm.read(32))
        currindex = mm.find(b'\x02\x01\x01\x04\x20')

    f.close()
    #print(privkeyList)
    print("Found [" + str(len(privkeyList)) + "] possible keys")

    for key in privkeyList:
        
        PKuncomp = b'80'+ binascii.hexlify(key)
        PKcomp = PKuncomp + b'01'
        
        PKuncomp_sha256_1 = hashlib.sha256(codecs.decode(PKuncomp, 'hex'))
        PKuncomp_sha256_2 = hashlib.sha256(PKuncomp_sha256_1.digest())
        
        checksum_uncomp = codecs.encode(PKuncomp_sha256_2.digest(), 'hex')[0:8]
        uncomp_PK = PKuncomp + checksum_uncomp
        #print(uncomp_PK)
        
        PKcomp_sha256_1 = hashlib.sha256(codecs.decode(PKcomp, 'hex'))
        PKcomp_sha256_2 = hashlib.sha256(PKcomp_sha256_1.digest())
        
        checksum_comp = codecs.encode(PKcomp_sha256_2.digest(), 'hex')[0:8]
        comp_PK = PKcomp + checksum_comp
        #print(comp_PK)
        
        WIF_uncomp = base58(uncomp_PK.decode("utf-8"))
        WIF_comp = base58(comp_PK.decode("utf-8"))
        
        print(WIF_uncomp)
        print(WIF_comp)

if __name__ == "__main__":
    main()