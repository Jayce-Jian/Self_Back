import sys 
import binascii


if len(sys.argv) > 1:
	hex_str = sys.argv[1]
	print([byte if byte <= 127 else (256-byte) * (-1) for byte in binascii.unhexlify(hex_str)])

else:
	# cs4.4
	hex_str = "5e98194a01c6b48fa582a6a9fcbb92d6"
	print([byte if byte <= 127 else (256-byte) * (-1) for byte in binascii.unhexlify(hex_str)])

