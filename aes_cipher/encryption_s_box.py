from aes_cipher.constants import s_box


class EncryptionSBox:
    def __init__(self, round_keys=None):
        self.round_keys = round_keys
        self.state = [0] * 16

    def set_round_keys(self, round_keys):
        self.round_keys = round_keys

    def add_round_key(self, round_number=0):
        for i in range(16):
            self.state[i] ^= self.round_keys[round_number][i]

    def sub_bytes(self):
        for i in range(16):
            self.state[i] = s_box[self.state[i]]

    def shift_rows(self):
        # Row 0: no shift

        # Row 1: shift by 1
        temp_1 = self.state[1]
        self.state[1] = self.state[5]
        self.state[5] = self.state[9]
        self.state[9] = self.state[13]
        self.state[13] = temp_1

        # Row 2: shift by 2
        temp_1 = self.state[2]
        temp_2 = self.state[6]
        self.state[2] = self.state[10]
        self.state[6] = self.state[14]
        self.state[10] = temp_1
        self.state[14] = temp_2

        # Row 3: shift by 3
        temp_1 = self.state[3]
        temp_2 = self.state[7]
        temp_3 = self.state[11]
        self.state[3] = self.state[15]
        self.state[7] = temp_1
        self.state[11] = temp_2
        self.state[15] = temp_3

    @staticmethod
    def multiply(a, b):
        p = 0

        for i in range(8):
            if 1 == b & 1:
                p ^= a
            high_bit_set = a & 0x80
            a = (a << 1) & 0xff
            if 0x80 == high_bit_set:
                a ^= 0x1b
            b >>= 1

        return p

    def mix_columns(self):
        # Column 0
        s0 = self.state[0]
        s1 = self.state[1]
        s2 = self.state[2]
        s3 = self.state[3]

        self.state[0] = self.multiply(s0, 2) ^ self.multiply(s1, 3) ^ s2 ^ s3
        self.state[1] = s0 ^ self.multiply(s1, 2) ^ self.multiply(s2, 3) ^ s3
        self.state[2] = s0 ^ s1 ^ self.multiply(s2, 2) ^ self.multiply(s3, 3)
        self.state[3] = self.multiply(s0, 3) ^ s1 ^ s2 ^ self.multiply(s3, 2)

        # Column 1
        s0 = self.state[4]
        s1 = self.state[5]
        s2 = self.state[6]
        s3 = self.state[7]

        self.state[4] = self.multiply(s0, 2) ^ self.multiply(s1, 3) ^ s2 ^ s3
        self.state[5] = s0 ^ self.multiply(s1, 2) ^ self.multiply(s2, 3) ^ s3
        self.state[6] = s0 ^ s1 ^ self.multiply(s2, 2) ^ self.multiply(s3, 3)
        self.state[7] = self.multiply(s0, 3) ^ s1 ^ s2 ^ self.multiply(s3, 2)

        # Column 2
        s0 = self.state[8]
        s1 = self.state[9]
        s2 = self.state[10]
        s3 = self.state[11]

        self.state[8] = self.multiply(s0, 2) ^ self.multiply(s1, 3) ^ s2 ^ s3
        self.state[9] = s0 ^ self.multiply(s1, 2) ^ self.multiply(s2, 3) ^ s3
        self.state[10] = s0 ^ s1 ^ self.multiply(s2, 2) ^ self.multiply(s3, 3)
        self.state[11] = self.multiply(s0, 3) ^ s1 ^ s2 ^ self.multiply(s3, 2)

        # Column 3
        s0 = self.state[12]
        s1 = self.state[13]
        s2 = self.state[14]
        s3 = self.state[15]

        self.state[12] = self.multiply(s0, 2) ^ self.multiply(s1, 3) ^ s2 ^ s3
        self.state[13] = s0 ^ self.multiply(s1, 2) ^ self.multiply(s2, 3) ^ s3
        self.state[14] = s0 ^ s1 ^ self.multiply(s2, 2) ^ self.multiply(s3, 3)
        self.state[15] = self.multiply(s0, 3) ^ s1 ^ s2 ^ self.multiply(s3, 2)

    def encrypt_round(self, round_number):
        self.sub_bytes()
        self.shift_rows()
        self.mix_columns()
        self.add_round_key(round_number)

    def encrypt_last_round(self, round_number):
        self.sub_bytes()
        self.shift_rows()
        self.add_round_key(round_number)

    def set_state(self, plaintext):
        for i in range(16):
            self.state[i] = (plaintext >> 8 * (15 - i)) & 0xff

    def get_state(self):
        ciphertext = 0

        for i in range(16):
            ciphertext <<= 8
            ciphertext ^= self.state[i]

        return ciphertext

    def print_state(self):
        for i in range(16):
            print('{} '.format(format(self.state[i], '02x')), end='')
        print()

    def encrypt(self, plaintext):
        self.set_state(plaintext)

        self.add_round_key()

        for round_number in range(1, 10, 1):
            self.encrypt_round(round_number)
        self.encrypt_last_round(10)

        return self.get_state()
