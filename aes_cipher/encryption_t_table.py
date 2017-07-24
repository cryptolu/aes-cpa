from aes_cipher.constants import s_box, t0, t1, t2, t3


class EncryptionTTable:
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

    def t_table_lookup(self):
        c0 = t0[self.state[0]] ^ t1[self.state[5]] ^ t2[self.state[10]] ^ t3[self.state[15]]
        c1 = t0[self.state[4]] ^ t1[self.state[9]] ^ t2[self.state[14]] ^ t3[self.state[3]]
        c2 = t0[self.state[8]] ^ t1[self.state[13]] ^ t2[self.state[2]] ^ t3[self.state[7]]
        c3 = t0[self.state[12]] ^ t1[self.state[1]] ^ t2[self.state[6]] ^ t3[self.state[11]]

        self.state[0] = (c0 >> 24) & 0xff
        self.state[1] = (c0 >> 16) & 0xff
        self.state[2] = (c0 >> 8) & 0xff
        self.state[3] = (c0 >> 0) & 0xff

        self.state[4] = (c1 >> 24) & 0xff
        self.state[5] = (c1 >> 16) & 0xff
        self.state[6] = (c1 >> 8) & 0xff
        self.state[7] = (c1 >> 0) & 0xff

        self.state[8] = (c2 >> 24) & 0xff
        self.state[9] = (c2 >> 16) & 0xff
        self.state[10] = (c2 >> 8) & 0xff
        self.state[11] = (c2 >> 0) & 0xff

        self.state[12] = (c3 >> 24) & 0xff
        self.state[13] = (c3 >> 16) & 0xff
        self.state[14] = (c3 >> 8) & 0xff
        self.state[15] = (c3 >> 0) & 0xff

    def encrypt_round(self, round_number):
        self.t_table_lookup()
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
