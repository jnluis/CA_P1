from array import array
from hashlib import sha256
from collections import Counter

block_size = 16
key_size = 16


def new(key, skey=None):
    if skey is None:
        return ECBMode(AES(key))
    else:
        return ECBMode(AES(key, skey))


#### AES cipher implementation
class AES(object):
    block_size = 16

    def __init__(self, key, skey=None):
        self.setkey(key)
        self.setshufflekey(skey)
        self.expand_key()

    def setkey(self, key: bytes | str):
        """Sets the key and performs key expansion."""

        self.key: bytes = key if isinstance(key, bytes) else key.encode()
        self.key_size = len(key)
        self.rounds = 10

    def setshufflekey(self, skey: bytes | str | None):
        """Sets the shuffle key and performs key expansion."""

        if skey is None:
            self.skey = None
            self.permutation_indices = None
            self.round_key_order = None
            self.modified_round_number = None
            return None

        self.skey = skey# if isinstance(skey, bytes) else skey.encode()
        self.skey_size = len(skey)

        self.permutation_skey = skey.encode()[:16:2]
        self.modified_round_skey = skey.encode()[1:16:2]

        self.permutation_indices = self.generate_bytes_permutation_indices(self.permutation_skey)
        self.round_key_order = self.round_key_order_permutation(self.permutation_skey)
        self.modified_round_number = self.select_modified_round_number(self.skey.encode())
        self.saes_sbox = self.create_saes_sbox(self.modified_round_skey)
        self.saes_inv_sbox = self.create_saes_inverse_sbox()
    


    def generate_bytes_permutation_indices(self, skey):
        """Generates a list of deterministic permutation indices for round keys."""
        num_round_keys = self.rounds + 1  # Total rounds + final key
        permutation_indices = []

        for round_idx in range(num_round_keys):
            # Hash the skey with the round index for deterministic bytes
            hash_input = skey + round_idx.to_bytes(1, 'big')
            hash_output = sha256(hash_input).digest()

            # Use the hash output to generate a permutation for this round key
            indices = list(range(16))
            for i in range(15, 0, -1):
                swap_idx = hash_output[i] % (i + 1)
                indices[i], indices[swap_idx] = indices[swap_idx], indices[i]

            permutation_indices.append(indices)

        return permutation_indices
    
    def round_key_order_permutation(self, skey):
        """Generates a deterministic permutation of round key order based on SK."""
        num_round_keys = self.rounds + 1  # Total rounds + final key
        order_indices = list(range(num_round_keys))

        # Generate pseudo-random bytes for shuffling
        hash_output = sha256(skey).digest()
        for i in range(num_round_keys - 1, 0, -1):
            swap_idx = hash_output[i % len(hash_output)] % (i + 1)
            order_indices[i], order_indices[swap_idx] = order_indices[swap_idx], order_indices[i]

        return order_indices
    

    def select_modified_round_number(self, skey):
        # Create a hash of the secret key
        hashed_key = sha256(skey).hexdigest()  # Using SHA-256

        # Convert the hash to an integer
        hash_value = int(hashed_key, 16)  # Convert hex to integer

        # Generate a round number based on the hash value
        round_number = (hash_value % (self.rounds - 1)) + 1  # Can't be on last round
        
        return round_number

    
    def create_saes_sbox(self, modified_round_skey):
        """
        Creates a shuffled S-Box based on the provided secret key (skey).
        :param skey: The secret key used for creating the S-Box.
        :return: A shuffled S-Box.
        """
        def generate_shuffled_sbox():
            # Initial SHA-256 hash of the key
            hashed_key = sha256(modified_round_skey).digest()


            # Create a list of indices [0, 1, ..., 255]
            indices = list(range(256))
            
            # Use the hash to shuffle the indices
            for i in range(len(indices)):
                # The current byte from the hash to modify the index
                byte = hashed_key[i % len(hashed_key)]
                
                # Calculate the new position for this index
                swap_index = (i + byte) % 256
                
                # Swap the current index with the calculated index
                indices[i], indices[swap_index] = indices[swap_index], indices[i]
            
            # Create a shuffled S-Box using the shuffled indices
            shuffled_sbox = [aes_sbox[index] for index in indices]
            return shuffled_sbox

        def validate_and_shuffle(sbox):
            # Ensure at least 50% of the S-Box bytes have changed their position
            changed_positions = set()
            for i in range(256):
                if sbox[i] != aes_sbox[i]:
                    changed_positions.add(i)
    
            # If less than 50% have changed, recursively shuffle again
            if len(changed_positions) < 128:  # Less than half
                return self.create_saes_sbox(modified_round_skey)  # Recurse with the same key
            return sbox

        shuffled_sbox = generate_shuffled_sbox()
        return array('B', validate_and_shuffle(shuffled_sbox))

        
    def create_saes_inverse_sbox(self):
        """
        Calculate the inverse S-box from the given S-box.
        The inverse S-box maps each substituted value back to its original value.

        Args:
            sbox (array): Original S-box array

        Returns:
            array: Inverse S-box array
        """
        # Create an empty inverse s-box of the same size (256 bytes)
        saes_inv_sbox = array('B', [0] * 256)

        # For each position and value in the original s-box
        for position in range(256):
            value = self.saes_sbox[position]
            # In the inverse s-box, map the value back to its position
            saes_inv_sbox[value] = position
        return saes_inv_sbox

    def expand_key(self):
        """Performs AES key expansion on self.key and stores in self.exkey"""

        # The key schedule specifies how parts of the key are fed into the
        # cipher's round functions. "Key expansion" means performing this
        # schedule in advance. Almost all implementations do this.
        #
        # Here's a description of AES key schedule:
        # http://en.wikipedia.org/wiki/Rijndael_key_schedule

        key = self.key

        # The expanded key starts with the actual key itself
        exkey = array('B', key)

        # 4-byte temporary variable for key expansion
        word = exkey[-4:]
        # Each expansion cycle uses 'i' once for Rcon table lookup
        for i in range(1, 11):

            #### key schedule core:
            # left-rotate by 1 byte
            word = word[1:4] + word[0:1]

            # apply S-box to all bytes
            for j in range(4):
                word[j] = aes_sbox[word[j]]

            # apply the Rcon table to the leftmost byte
            word[0] ^= aes_Rcon[i]
            #### end key schedule core

            for z in range(4):
                for j in range(4):
                    # mix in bytes from the last subkey
                    word[j] ^= exkey[-self.key_size + j]
                exkey.extend(word)

            # Last key expansion cycle always finishes here
            if len(exkey) >= (self.rounds + 1) * self.block_size:
                break
        
        
        # Shuffle round keys if `self.permutation_indices` is set
        if self.permutation_indices:
            for round_idx in range(self.rounds + 1):
                start = round_idx * 16
                end = start + 16
                round_key = exkey[start:end]
                permuted_round_key = array('B', [round_key[i] for i in self.permutation_indices[round_idx]])
                exkey[start:end] = permuted_round_key

        # If round key order shuffling is set, reorder the round keys
        if self.round_key_order:
            shuffled_exkey = array('B')
            for round_idx in self.round_key_order:
                start = round_idx * 16
                end = start + 16
                shuffled_exkey.extend(exkey[start:end])
            self.exkey = shuffled_exkey
        else:
            self.exkey = exkey
            


    def add_round_key(self, block, round):
        """AddRoundKey step. This is where the key is mixed into plaintext"""

        offset = round * 16
        exkey = self.exkey

        for i in range(16):
            block[i] ^= exkey[offset + i]

        if round == self.modified_round_number:
            for i in range(16):
                block[i] ^= self.modified_round_skey[i % 8]


    def sub_bytes(self, block, sbox):
        """
        SubBytes step, apply S-box to all bytes

        Depending on whether encrypting or decrypting, a different sbox array
        is passed in.
        """

        for i in range(16):
            block[i] = sbox[block[i]]

        #print 'SubBytes   :', block

    def shift_rows(self, b):
        """
        ShiftRows step in AES.

        Shifts 2nd row to left by 1, 3rd row by 2, 4th row by 3

        Since we're performing this on a transposed matrix, cells are numbered
        from top to bottom first::

          0  4  8 12 ->  0  4  8 12  -- 1st row doesn't change
          1  5  9 13 ->  5  9 13  1  -- row shifted to left by 1 (wraps around)
          2  6 10 14 -> 10 14  2  6  -- shifted by 2
          3  7 11 15 -> 15  3  7 11  -- shifted by 3
        """

        b[1], b[5], b[9],  b[13] = b[5],  b[9],  b[13], b[1]
        b[2], b[6], b[10], b[14] = b[10], b[14], b[2],  b[6]
        b[3], b[7], b[11], b[15] = b[15], b[3],  b[7],  b[11]

        #print 'ShiftRows  :', b

    def shift_rows_inv(self, b):
        """
        Similar to shift_rows above, but performed in inverse for decryption.
        """
        b[5] , b[9],  b[13], b[1]  = b[1], b[5], b[9],  b[13]
        b[10], b[14], b[2],  b[6]  = b[2], b[6], b[10], b[14]
        b[15], b[3],  b[7],  b[11] = b[3], b[7], b[11], b[15]

        #print 'ShiftRows  :', b

    def mix_columns(self, block):
        """MixColumns step. Mixes the values in each column"""

        # Cache global multiplication tables (see below)
        mul_by_2 = gf_mul_by_2
        mul_by_3 = gf_mul_by_3

        # Since we're dealing with a transposed matrix, columns are already
        # sequential
        for col in range(0, 16, 4):
            v0, v1, v2, v3 = block[col:col + 4]

            block[col] =     mul_by_2[v0] ^ v3 ^ v2 ^ mul_by_3[v1]
            block[col + 1] = mul_by_2[v1] ^ v0 ^ v3 ^ mul_by_3[v2]
            block[col + 2] = mul_by_2[v2] ^ v1 ^ v0 ^ mul_by_3[v3]
            block[col + 3] = mul_by_2[v3] ^ v2 ^ v1 ^ mul_by_3[v0]

        #print 'MixColumns :', block

    def mix_columns_inv(self, block):
        """
        Similar to mix_columns above, but performed in inverse for decryption.
        """
        # Cache global multiplication tables (see below)
        mul_9 = gf_mul_by_9
        mul_11 = gf_mul_by_11
        mul_13 = gf_mul_by_13
        mul_14 = gf_mul_by_14

        # Since we're dealing with a transposed matrix, columns are already
        # sequential
        for col in range(0, 16, 4):
            v0, v1, v2, v3 = block[col:col + 4]

            block[col] = mul_14[v0] ^ mul_9[v3] ^ mul_13[v2] ^ mul_11[v1]
            block[col + 1] = mul_14[v1] ^ mul_9[v0] ^ mul_13[v3] ^ mul_11[v2]
            block[col + 2] = mul_14[v2] ^ mul_9[v1] ^ mul_13[v0] ^ mul_11[v3]
            block[col + 3] = mul_14[v3] ^ mul_9[v2] ^ mul_13[v1] ^ mul_11[v0]

        #print 'MixColumns :', block

    def encrypt_block(self, block):
        """Encrypts a single block. This is the main AES function"""

        # For efficiency reasons, the state between steps is transmitted via a
        # mutable array, not returned
        self.add_round_key(block, 0)

        for round in range(1, self.rounds):
            if self.modified_round_number is None or round != self.modified_round_number:
                self.sub_bytes(block, aes_sbox)
            else:
                self.sub_bytes(block, self.saes_sbox)
            self.shift_rows(block)
            self.mix_columns(block)
            self.add_round_key(block, round)

        self.sub_bytes(block, aes_sbox)
        self.shift_rows(block)
        # no mix_columns step in the last round
        self.add_round_key(block, self.rounds)

    def decrypt_block(self, block):
        """Decrypts a single block. This is the main AES decryption function"""

        # For efficiency reasons, the state between steps is transmitted via a
        # mutable array, not returned
        self.add_round_key(block, self.rounds)

        # count rounds down from (self.rounds) ... 1
        for round in range(self.rounds - 1, 0, -1):
            self.shift_rows_inv(block)
            if self.modified_round_number is None or round != self.modified_round_number - 1:
                self.sub_bytes(block, aes_inv_sbox)
            else:
                self.sub_bytes(block, self.saes_inv_sbox)
            self.add_round_key(block, round)
            self.mix_columns_inv(block)

        self.shift_rows_inv(block)
        if self.modified_round_number is None or 0 != self.modified_round_number - 1:
            self.sub_bytes(block, aes_inv_sbox)
        else:
            self.sub_bytes(block, self.saes_inv_sbox)
        self.add_round_key(block, 0)
        # no mix_columns step in the last round


#### ECB mode implementation

class ECBMode(object):
    """Electronic CodeBook (ECB) mode encryption.

    Basically this mode applies the cipher function to each block individually;
    no feedback is done. NB! This is insecure for almost all purposes
    """

    def __init__(self, cipher):
        self.cipher = cipher
        self.block_size = cipher.block_size

    def ecb(self, data:str, block_func):
        """Perform ECB mode with the given function"""
        
        if len(data) % self.block_size != 0:
            raise ValueError("Input length must be multiple of 16")

        data = array('B', data)

        for offset in range(0, len(data), self.block_size):
            block = data[offset:offset + self.block_size]
            processed_block = bytearray(block)
            block_func(processed_block)
            data[offset:offset + self.block_size] = array('B', processed_block)

        return data.tobytes()

    def encrypt(self, data):
        """Encrypt data in ECB mode"""
        
        #data = data.encode()
        data = add_pkcs7_padding(data.encode())

        return self.ecb(data, self.cipher.encrypt_block)

    def decrypt(self, data):
        """Decrypt data in ECB mode"""
        data = self.ecb(data, self.cipher.decrypt_block)

        try:
            return remove_pkcs7_padding(data.decode('utf-8'))  # Attempt to decode as UTF-8
        except UnicodeDecodeError:
            # If decoding fails, return the raw byte data or a placeholder
            print("Warning: Decrypted data is not valid UTF-8. Returning raw bytes.")
            return data  # or you could return some error message or empty string

def add_pkcs7_padding(plain):
    """
    Adds PKCS7 padding to given bytes.
    """

    padding_len = 16 - (len(plain) % 16)
    return plain + bytes([padding_len] * padding_len)

def remove_pkcs7_padding(plain_with_padding):
    """
    Removes PKCS7 padding from given bytes.
    """

    return plain_with_padding[:len(plain_with_padding)-ord(plain_with_padding[-1])]

def galois_multiply(a, b):
    """Galois Field multiplicaiton for AES"""
    p = 0
    while b:
        if b & 1:
            p ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x1b
        b >>= 1

    return p & 0xff

# Precompute the multiplication tables for encryption
gf_mul_by_2 = array('B', [galois_multiply(x, 2) for x in range(256)])
gf_mul_by_3 = array('B', [galois_multiply(x, 3) for x in range(256)])
# ... for decryption
gf_mul_by_9 = array('B', [galois_multiply(x, 9) for x in range(256)])
gf_mul_by_11 = array('B', [galois_multiply(x, 11) for x in range(256)])
gf_mul_by_13 = array('B', [galois_multiply(x, 13) for x in range(256)])
gf_mul_by_14 = array('B', [galois_multiply(x, 14) for x in range(256)])

####

# The S-box is a 256-element array, that maps a single byte value to another
# byte value. Since it's designed to be reversible, each value occurs only once
# in the S-box
#
# More information: http://en.wikipedia.org/wiki/Rijndael_S-box

aes_sbox = array(
    'B',
    bytes.fromhex(
    '637c777bf26b6fc53001672bfed7ab76'
    'ca82c97dfa5947f0add4a2af9ca472c0'
    'b7fd9326363ff7cc34a5e5f171d83115'
    '04c723c31896059a071280e2eb27b275'
    '09832c1a1b6e5aa0523bd6b329e32f84'
    '53d100ed20fcb15b6acbbe394a4c58cf'
    'd0efaafb434d338545f9027f503c9fa8'
    '51a3408f929d38f5bcb6da2110fff3d2'
    'cd0c13ec5f974417c4a77e3d645d1973'
    '60814fdc222a908846eeb814de5e0bdb'
    'e0323a0a4906245cc2d3ac629195e479'
    'e7c8376d8dd54ea96c56f4ea657aae08'
    'ba78252e1ca6b4c6e8dd741f4bbd8b8a'
    '703eb5664803f60e613557b986c11d9e'
    'e1f8981169d98e949b1e87e9ce5528df'
    '8ca1890dbfe6426841992d0fb054bb16')
)

# This is the inverse of the above. In other words:
# aes_inv_sbox[aes_sbox[val]] == val

aes_inv_sbox = array(
    'B',
    bytes.fromhex(
    '52096ad53036a538bf40a39e81f3d7fb'
    '7ce339829b2fff87348e4344c4dee9cb'
    '547b9432a6c2233dee4c950b42fac34e'
    '082ea16628d924b2765ba2496d8bd125'
    '72f8f66486689816d4a45ccc5d65b692'
    '6c704850fdedb9da5e154657a78d9d84'
    '90d8ab008cbcd30af7e45805b8b34506'
    'd02c1e8fca3f0f02c1afbd0301138a6b'
    '3a9111414f67dcea97f2cfcef0b4e673'
    '96ac7422e7ad3585e2f937e81c75df6e'
    '47f11a711d29c5896fb7620eaa18be1b'
    'fc563e4bc6d279209adbc0fe78cd5af4'
    '1fdda8338807c731b11210592780ec5f'
    '60517fa919b54a0d2de57a9f93c99cef'
    'a0e03b4dae2af5b0c8ebbb3c83539961'
    '172b047eba77d626e169146355210c7d'
    )
)

# The Rcon table is used in AES's key schedule (key expansion)
# It's a pre-computed table of exponentation of 2 in AES's finite field
#
# More information: http://en.wikipedia.org/wiki/Rijndael_key_schedule

aes_Rcon = array(
    'B',
    bytes.fromhex(
    '8d01020408102040801b366cd8ab4d9a'
    '2f5ebc63c697356ad4b37dfaefc59139'
    '72e4d3bd61c29f254a943366cc831d3a'
    '74e8cb8d01020408102040801b366cd8'
    'ab4d9a2f5ebc63c697356ad4b37dfaef'
    'c5913972e4d3bd61c29f254a943366cc'
    '831d3a74e8cb8d01020408102040801b'
    '366cd8ab4d9a2f5ebc63c697356ad4b3'
    '7dfaefc5913972e4d3bd61c29f254a94'
    '3366cc831d3a74e8cb8d010204081020'
    '40801b366cd8ab4d9a2f5ebc63c69735'
    '6ad4b37dfaefc5913972e4d3bd61c29f'
    '254a943366cc831d3a74e8cb8d010204'
    '08102040801b366cd8ab4d9a2f5ebc63'
    'c697356ad4b37dfaefc5913972e4d3bd'
    '61c29f254a943366cc831d3a74e8cb'
    )
)