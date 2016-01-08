# Challenge 1

import exceptions
import base64 as b64
import unittest

#Hex to char conversion

def Hex2char(hexStr):

    byte_list = []
    hexStr = ''.join(hexStr.split(" "))
    for i in range(0, len(hexStr), 2):
        byte_list.append(chr(int(hexStr[i:i+2], 16)))

    return ''.join(byte_list)

def hex2bytearray(hexStr):

    byte_list = []
    hexStr = ''.join(hexStr.split(" "))
    for i in range(0, len(hexStr), 2):
        byte_list.append(int(hexStr[i:i+2],16))

    return bytearray(byte_list)

def fixedxor(bytearray1, bytearray2):
    # return "746865206b696420646f6e277420706c6179"
    if len(bytearray1) != len(bytearray2):
        raise exceptions.IndexError

    r = []
    for i in range(0, len(bytearray1)):
        r.append(bytearray1[i] ^ bytearray2[i])

    return bytearray(r)

def bytearray2hexstr(_bytearray):
    hexlist = []
    for b in _bytearray:
        hexlist.append(hex(b)[2:])

    return ''.join(hexlist)

def key1char_xorcipher_decrypt(mesg, key):
    dmsg = []
    for byte in hex2bytearray(mesg):
        dmsg.append(chr(byte ^ ord(key)))
    
    return ''.join(dmsg)

def find60char_hexstrs(enc_file):
    dmsg = []
    with open(enc_file, 'r') as encfile:
        cryptotex = encfile.readlines()

    for line in cryptotex:
        dmsg.append(line[:-1]) 

    cryptotex = ''.join(dmsg)
    dmsg = []
    for idx in range(0, len(cryptotex) % 120):
        dmsg.append(cryptotex[idx:idx+120])

    return dmsg
    
def count_hexchars_string(string):
    count = {}
    for idx in range(0, len(string), 2):
        if count.has_key(string[idx:idx+2]):
            count[string[idx:idx+2]] += 1
        else:
            count[string[idx:idx+2]] = 1

    return count

def most_frequent_char_hexstr(hex_frec_dict):
    return max(hex_frec_dict.iterkeys(), key=lambda k: hex_frec_dict[k])

class Testcryptopals_set1(unittest.TestCase):
    def setUp(self):
        pass

    def test_ch1_hex2Char(self):
        hexStr = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        hexchar = Hex2char(hexStr)
        self.assertEqual(hexchar, "I'm killing your brain like a poisonous mushroom")
                
    def test_ch1_hex2b64(self):
        hexStr = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        b64str = b64.b64encode(Hex2char(hexStr))
        self.assertEqual(b64str, "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")

    def test_ch2_fixedXOR(self):
        barr1 = hex2bytearray("686974207468652062756c6c277320657965")
        barr2 = hex2bytearray("1c0111001f010100061a024b53535009181c")
        xored = bytearray2hexstr(fixedxor(barr1, barr2))
        self.assertEqual(xored, "746865206b696420646f6e277420706c6179")

    def test_ch3_findkey(self):
        key = 'X'
        cryptotex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
        message = key1char_xorcipher_decrypt(cryptotex, key)
        self.assertEqual(message, "Cooking MC's like a pound of bacon")

    def test_ch4_find60char_strs(self):
        enc_file = "4.txt"
        lines = find60char_hexstrs(enc_file)
        self.assertEqual(len(lines[1]), 120)

    def test_ch4_find_encstr(self):
        enc_file = "4.txt"
        lines = find60char_hexstrs(enc_file)
        self.assertEqual(1,1)

if __name__ == '__main__':
    unittest.main()
