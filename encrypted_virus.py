import re
import os
import sys
from itertools import cycle


class Encrypted:
    def __init__(self, payload, payload_address, len_payload):
        
        self.add_more_space(payload, payload_address)
        self.add_more_space(payload_address, len_payload)
        
        self.temp = self.byte_xor(payload_address, len_payload)
        self.encrypted_payload = self.byte_xor(
            payload, self.temp)

    # Get the encrypted payload
    def get_encrypted_payload(self):
        return self.encrypted_payload
    
    # Get encrypted_payload len
    def get_len_encrypted_payload(self):
        return len(self.encrypted_payload)

    # Add more space for zip()
    def add_more_space(self, a, b):
        while (len(a) < len(b)):
            a.insert(0, 0)
        while (len(b) < len(a)):
            b.insert(0, 0)

    # Byte XOR function
    def byte_xor(self, ba1, ba2):
        return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


payload = bytearray(b'\xBB')
payload_address = bytearray(b'\x49\x00\x6e\x00\x66\x00\x6f\x00')
len_payload = bytearray(len(payload))

payload = Encrypted(payload, payload_address, len_payload)

print(payload.get_encrypted_payload())
