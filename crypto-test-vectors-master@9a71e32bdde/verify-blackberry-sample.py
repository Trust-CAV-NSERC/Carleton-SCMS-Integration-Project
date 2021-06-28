from ecc import *
from hashlib import sha256

secp256r1 = ECurve(
   "secp256r1",
   "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",  # p
   "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",  # a
   "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",  # b
   "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",  # gx
   "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",  # gy
   "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",  # n
   1                                                                    # h
   )

# generator point
genP256 = ECPoint(secp256r1.gx, secp256r1.gy, secp256r1)

####################################################################################
# input
pubKeyStr = 'C0908F60CCE4A42A9E3D48B03BAAD6FB347A6E49DB176C0378096FA9626F6E08' # compressed-y-1 0x03
rStr = '6DEE89FB57BE191B35E36DF330752519EA5A4D938885AC72B86E08C6DC070D12' # compressed-y-1 0x03
sStr = 'F96BF61FF83878CE20E5058869A22E4D88B543A84FA12501C432C9FEA0C76B12'
data_oer = '03 83 81 A3 00 01 81 80 00 01 20 5E FE 63 44 81\
09 54 65 73 74 31 32 33 57 4C 00 00 00 00 04 20\
5D E3 85 86 00 02 83 01 01 80 03 48 01 01 80 80\
01 03 00 01 82 00 03 20 40 95 00 03 20 40 97 01\
00 80 80 83 C0 90 8F 60 CC E4 A4 2A 9E 3D 48 B0\
3B AA D6 FB 34 7A 6E 49 DB 17 6C 03 78 09 6F A9\
62 6F 6E 08 82'
data_oer = data_oer.replace(' ', '')

print(data_oer)
#############################################################

pubKey = ECPoint("compressed-y-1", pubKeyStr)
r = ECPoint("compressed-y-1", rStr)
s = sStr
digest = sha256(data_oer.decode('hex')).hexdigest()
to_verify = ECDSA(256, pubKey)
if (not to_verify.verify(digest, r, s)):
  raise Exception("ECDSA verify failed!")


