'''
* ms32_recrypt by twistedsymphony
* 2023-08-05
* Based on the excellent Jaleco Mega System 32 decryption algorithm in MAME
* This code can decrypt a ROM and is also able to re-encrypt a decrypted ROM.
* the result is that a any game ROM can be decrypted and then re-encrypted for
* any other known ROM board encryption variant.
'''

import argparse
import struct

keys = {
  'SS91022-10': { #SS91022-10: desertwr, gametngk, gratiaa, tp2m32
    'tx':{ #gfx4
      'addr_xor': 0x00000,
      'data_xor': 0x35,
      'header_byte': 0x05
    },
    'bg':{ #gfx3
      'addr_xor': 0x00000,
      'data_xor': 0xa3,
      'header_byte': 0x16
    }
  },
  'SS92046-01': { #SS92046-01: bbbxing, bnstars, f1superb, hayaosi2, hayaosi3, hayaosi3a, tetrisp, wpksocv2
    'tx':{ #gfx4
      'addr_xor': 0x00020,
      'data_xor': 0x7e,
      'header_byte': 0x49
    },
    'bg':{ #gfx3
      'addr_xor': 0x00001,
      'data_xor': 0x9b,
      'header_byte': 0x3E
    }
  },
  'SS92047-01': { #SS92047-01: akiss, gratia, kirarast
    'tx':{ #gfx4
      'addr_xor': 0x24000,
      'data_xor': 0x18,
      'header_byte': 0xD2
    },
    'bg':{ #gfx3
      'addr_xor': 0x24000,
      'data_xor': 0x55,
      'header_byte': 0x27
    }
  },
  'SS92048-01': { #SS92048-01: p47aces, p47acesa, suchie2, suchie2o
    'tx':{ #gfx4
      'addr_xor': 0x20400,
      'data_xor': 0xd6,
      'header_byte': 0x38
    },
    'bg':{ #gfx3
      'addr_xor': 0x20400,
      'data_xor': 0xd4,
      'header_byte': 0x03
    }
  }
}


#decrypt tx ROM
def decrypt_ms32_tx(enc_data, addr_xor, data_xor):
  data_size = len(enc_data)
  dec_data = bytearray(data_size)
  addr_xor ^= 0x1005d

  for i in range(data_size):
    #determine the scrambled address j from the unscrambled address i
    j = 0
    i ^= addr_xor

    if (i >> 18) & 1: j ^= 0x40000    # 18
    if (i >> 17) & 1: j ^= 0x60000    # 17
    if (i >>  7) & 1: j ^= 0x70000    # 16
    if (i >>  3) & 1: j ^= 0x78000    # 15
    if (i >> 14) & 1: j ^= 0x7c000    # 14
    if (i >> 13) & 1: j ^= 0x7e000    # 13
    if (i >>  0) & 1: j ^= 0x7f000    # 12
    if (i >> 11) & 1: j ^= 0x7f800    # 11
    if (i >> 10) & 1: j ^= 0x7fc00    # 10

    if (i >>  9) & 1: j ^= 0x00200     # 9
    if (i >>  8) & 1: j ^= 0x00300     # 8
    if (i >> 16) & 1: j ^= 0x00380     # 7
    if (i >>  6) & 1: j ^= 0x003c0     # 6
    if (i >> 12) & 1: j ^= 0x003e0     # 5
    if (i >>  4) & 1: j ^= 0x003f0     # 4
    if (i >> 15) & 1: j ^= 0x003f8     # 3
    if (i >>  2) & 1: j ^= 0x003fc     # 2
    if (i >>  1) & 1: j ^= 0x003fe     # 1
    if (i >>  5) & 1: j ^= 0x003ff     # 0

    i ^= addr_xor

    # decrypt the data at the address
    dec_data[i] = enc_data[j] ^ (i & 0xff) ^ data_xor
    
  return dec_data
  


#encrypt tx ROM
def encrypt_ms32_tx(dec_data, addr_xor, data_xor, header_byte):
  data_size = len(dec_data)
  enc_data = bytearray(data_size)
  addr_xor ^= 0x1005d
  tx_header_length = 0x40

  for i in range(data_size):
    #determine the scrambled address j from the unscrambled address i
    j = 0
    i ^= addr_xor
    
    if (i >> 18) & 1: j ^= 0x40000    # 18
    if (i >> 17) & 1: j ^= 0x60000    # 17
    if (i >>  7) & 1: j ^= 0x70000    # 16
    if (i >>  3) & 1: j ^= 0x78000    # 15
    if (i >> 14) & 1: j ^= 0x7c000    # 14
    if (i >> 13) & 1: j ^= 0x7e000    # 13
    if (i >>  0) & 1: j ^= 0x7f000    # 12
    if (i >> 11) & 1: j ^= 0x7f800    # 11
    if (i >> 10) & 1: j ^= 0x7fc00    # 10

    if (i >>  9) & 1: j ^= 0x00200     # 9
    if (i >>  8) & 1: j ^= 0x00300     # 8
    if (i >> 16) & 1: j ^= 0x00380     # 7
    if (i >>  6) & 1: j ^= 0x003c0     # 6
    if (i >> 12) & 1: j ^= 0x003e0     # 5
    if (i >>  4) & 1: j ^= 0x003f0     # 4
    if (i >> 15) & 1: j ^= 0x003f8     # 3
    if (i >>  2) & 1: j ^= 0x003fc     # 2
    if (i >>  1) & 1: j ^= 0x003fe     # 1
    if (i >>  5) & 1: j ^= 0x003ff     # 0
    
    i ^= addr_xor
    
    #encrypt the data at the address
    data_byte = dec_data[i]
    if i < tx_header_length: #if this is a header byte
      data_byte = header_byte #set the new header byte value
    enc_data[j] = data_byte ^ (i & 0xff) ^ data_xor
    
  return enc_data



#decrypt bg ROM
def decrypt_ms32_bg(enc_data, addr_xor, data_xor):
  data_size = len(enc_data)
  dec_data = bytearray(data_size)
  addr_xor ^= 0xc1c5b

  for i in range(data_size):
    #determine the scrambled address j from the unscrambled address i
    j = (i & ~0xfffff)  # top bits are not affected
    i ^= addr_xor

    if (i >> 19) & 1: j ^= 0x80000    # 19
    if (i >>  8) & 1: j ^= 0xc0000    # 18
    if (i >> 17) & 1: j ^= 0xe0000    # 17
    if (i >>  2) & 1: j ^= 0xf0000    # 16
    if (i >> 15) & 1: j ^= 0xf8000    # 15
    if (i >> 14) & 1: j ^= 0xfc000    # 14
    if (i >> 13) & 1: j ^= 0xfe000    # 13
    if (i >> 12) & 1: j ^= 0xff000    # 12
    if (i >>  1) & 1: j ^= 0xff800    # 11
    if (i >> 10) & 1: j ^= 0xffc00    # 10

    if (i >>  9) & 1: j ^= 0x00200     # 9
    if (i >>  3) & 1: j ^= 0x00300     # 8
    if (i >>  7) & 1: j ^= 0x00380     # 7
    if (i >>  6) & 1: j ^= 0x003c0     # 6
    if (i >>  5) & 1: j ^= 0x003e0     # 5
    if (i >>  4) & 1: j ^= 0x003f0     # 4
    if (i >> 18) & 1: j ^= 0x003f8     # 3
    if (i >> 16) & 1: j ^= 0x003fc     # 2
    if (i >> 11) & 1: j ^= 0x003fe     # 1
    if (i >>  0) & 1: j ^= 0x003ff     # 0

    i ^= addr_xor

    #decrypt the data at the address
    dec_data[i] = enc_data[j] ^ (i & 0xff) ^ data_xor

  return dec_data



#encrypt bg ROM
def encrypt_ms32_bg(dec_data, addr_xor, data_xor, header_byte):
  data_size = len(dec_data)
  enc_data = bytearray(data_size)
  addr_xor ^= 0xc1c5b
  bg_header_length = 0x100
  
  for i in range(data_size):
    #determine the scrambled address j from the unscrambled address i
    j = (i & ~0xfffff)  # top bits are not affected
    i ^= addr_xor

    if (i >> 19) & 1: j ^= 0x80000    # 19
    if (i >>  8) & 1: j ^= 0xc0000    # 18
    if (i >> 17) & 1: j ^= 0xe0000    # 17
    if (i >>  2) & 1: j ^= 0xf0000    # 16
    if (i >> 15) & 1: j ^= 0xf8000    # 15
    if (i >> 14) & 1: j ^= 0xfc000    # 14
    if (i >> 13) & 1: j ^= 0xfe000    # 13
    if (i >> 12) & 1: j ^= 0xff000    # 12
    if (i >>  1) & 1: j ^= 0xff800    # 11
    if (i >> 10) & 1: j ^= 0xffc00    # 10

    if (i >>  9) & 1: j ^= 0x00200     # 9
    if (i >>  3) & 1: j ^= 0x00300     # 8
    if (i >>  7) & 1: j ^= 0x00380     # 7
    if (i >>  6) & 1: j ^= 0x003c0     # 6
    if (i >>  5) & 1: j ^= 0x003e0     # 5
    if (i >>  4) & 1: j ^= 0x003f0     # 4
    if (i >> 18) & 1: j ^= 0x003f8     # 3
    if (i >> 16) & 1: j ^= 0x003fc     # 2
    if (i >> 11) & 1: j ^= 0x003fe     # 1
    if (i >>  0) & 1: j ^= 0x003ff     # 0
    
    i ^= addr_xor

    #encrypt the data at the address
    data_byte = dec_data[i]
    if i < bg_header_length: #if this is a header byte
      data_byte = header_byte #set the new header byte value
    enc_data[j] = data_byte ^ (i & 0xff) ^ data_xor

  return enc_data



parser = argparse.ArgumentParser(description='Re-encrypt data using the ms32_bg encryption algorithm.')
parser.add_argument('input_file', type=str, help='input binary file')
parser.add_argument('output_file', type=str, help='output binary file')
parser.add_argument('--gfx', type=str, default='', help='gfx rom: tx or bg')
parser.add_argument('--ic_in', type=str, default='', help='decrypt from protection chip: SS91022-10, SS92046-01, SS92047-01, SS92048-01, or blank')
parser.add_argument('--ic_out', type=str, default='', help='encrypt to protection chip: SS91022-10, SS92046-01, SS92047-01, SS92048-01, or blank')
args = parser.parse_args()

# read input file
with open(args.input_file, 'rb') as f:
  source_data = f.read()

if args.ic_in == '': #skip decrypt
  dec_data = source_data
  print('No Decryption')
else: # decrypt
  dec_addr_xor = keys[args.ic_in][args.gfx]['addr_xor']
  print('Decryption ADDR_XOR: '+hex(dec_addr_xor))
  dec_data_xor = keys[args.ic_in][args.gfx]['data_xor']
  print('Decryption DATA_XOR: '+hex(dec_data_xor))
  if args.gfx == 'bg':
    dec_data = decrypt_ms32_bg(source_data, dec_addr_xor, dec_data_xor)
    print('Decrypting BG GFX')
  elif args.gfx == 'tx':
    dec_data = decrypt_ms32_tx(source_data, dec_addr_xor, dec_data_xor)
    print('Decrypting TX GFX')

if args.ic_out == '': #skip encrypt
  out_data = dec_data
  print('No Encryption')
else: # encrypt
  enc_addr_xor = keys[args.ic_out][args.gfx]['addr_xor']
  print('Encryption ADDR_XOR: '+hex(enc_addr_xor))
  enc_data_xor = keys[args.ic_out][args.gfx]['data_xor']
  print('Encryption DATA_XOR: '+hex(enc_data_xor))
  header_byte = keys[args.ic_out][args.gfx]['header_byte']
  print('Encryption HEADER_BYTE: '+hex(header_byte))
  if args.gfx == 'bg':
    print('Encrypting BG GFX')
    out_data = encrypt_ms32_bg(dec_data, enc_addr_xor, enc_data_xor, header_byte)
  elif args.gfx == 'tx':
    print('Encrypting TX GFX')
    out_data = encrypt_ms32_tx(dec_data, enc_addr_xor, enc_data_xor, header_byte)

with open(args.output_file, 'wb') as f:
  f.write(bytes(out_data))
