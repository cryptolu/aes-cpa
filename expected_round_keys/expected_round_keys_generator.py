from aes_cipher.key_schedule import KeySchedule
from aes_cipher.constants import s_box
from settings.active_settings import ActiveSettings


import copy
import random


class ExpectedRoundKeysGenerator:
    def __init__(self, state):
        self.state = copy.deepcopy(state)

        self.debug = False

        for i in range(len(state)):
            for j in range(16):
                if 0 != self.state[i][j]:
                    self.state[i][j] = 0xff

        active_settings = ActiveSettings()
        self.key = active_settings.key
        self.random_state = active_settings.random_state

        self.plaintext = 0
        for i in range(16):
            self.plaintext <<= 8

            # 1. Fill with zeros
            # self.plaintext += random.getrandbits(8) & self.state[0][i]

            # 2. Fill with random values
            # '''
            if self.state[0][i]:
                self.plaintext += random.getrandbits(8)
            else:
                self.plaintext += self.random_state[i]
            # '''

        self.round_keys = [[0 for i in range(16)] for j in range(4)]

        for i in range(len(state)):
            for j in range(16):
                if 0xff == self.state[i][j]:
                    self.state[i][j] = 1

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

    def generate(self):
        key_schedule = KeySchedule()
        key_schedule.run(self.key)

        # Round 0
        x0 = (self.plaintext >> 120) & 0xff
        x1 = (self.plaintext >> 112) & 0xff
        x2 = (self.plaintext >> 104) & 0xff
        x3 = (self.plaintext >> 96) & 0xff

        x4 = (self.plaintext >> 88) & 0xff
        x5 = (self.plaintext >> 80) & 0xff
        x6 = (self.plaintext >> 72) & 0xff
        x7 = (self.plaintext >> 64) & 0xff

        x8 = (self.plaintext >> 56) & 0xff
        x9 = (self.plaintext >> 48) & 0xff
        x10 = (self.plaintext >> 40) & 0xff
        x11 = (self.plaintext >> 32) & 0xff

        x12 = (self.plaintext >> 24) & 0xff
        x13 = (self.plaintext >> 16) & 0xff
        x14 = (self.plaintext >> 8) & 0xff
        x15 = (self.plaintext >> 0) & 0xff

        # AddRoundKey
        x0 ^= key_schedule.round_keys[0][0]
        x1 ^= key_schedule.round_keys[0][1]
        x2 ^= key_schedule.round_keys[0][2]
        x3 ^= key_schedule.round_keys[0][3]

        x4 ^= key_schedule.round_keys[0][4]
        x5 ^= key_schedule.round_keys[0][5]
        x6 ^= key_schedule.round_keys[0][6]
        x7 ^= key_schedule.round_keys[0][7]

        x8 ^= key_schedule.round_keys[0][8]
        x9 ^= key_schedule.round_keys[0][9]
        x10 ^= key_schedule.round_keys[0][10]
        x11 ^= key_schedule.round_keys[0][11]

        x12 ^= key_schedule.round_keys[0][12]
        x13 ^= key_schedule.round_keys[0][13]
        x14 ^= key_schedule.round_keys[0][14]
        x15 ^= key_schedule.round_keys[0][15]

        # SubBytes
        y0 = s_box[x0]
        y1 = s_box[x1]
        y2 = s_box[x2]
        y3 = s_box[x3]

        y4 = s_box[x4]
        y5 = s_box[x5]
        y6 = s_box[x6]
        y7 = s_box[x7]

        y8 = s_box[x8]
        y9 = s_box[x9]
        y10 = s_box[x10]
        y11 = s_box[x11]

        y12 = s_box[x12]
        y13 = s_box[x13]
        y14 = s_box[x14]
        y15 = s_box[x15]

        for i in range(16):
            if self.state[0][i]:
                self.round_keys[0][i] = key_schedule.round_keys[0][i]

        # Round 1
        x16 = self.multiply(y0, 2) ^ self.multiply(y5, 3) ^ y10 ^ y15
        x17 = y0 ^ self.multiply(y5, 2) ^ self.multiply(y10, 3) ^ y15
        x18 = y0 ^ y5 ^ self.multiply(y10, 2) ^ self.multiply(y15, 3)
        x19 = self.multiply(y0, 3) ^ y5 ^ y10 ^ self.multiply(y15, 2)

        x20 = self.multiply(y4, 2) ^ self.multiply(y9, 3) ^ y14 ^ y3
        x21 = y4 ^ self.multiply(y9, 2) ^ self.multiply(y14, 3) ^ y3
        x22 = y4 ^ y9 ^ self.multiply(y14, 2) ^ self.multiply(y3, 3)
        x23 = self.multiply(y4, 3) ^ y9 ^ y14 ^ self.multiply(y3, 2)

        x24 = self.multiply(y8, 2) ^ self.multiply(y13, 3) ^ y2 ^ y7
        x25 = y8 ^ self.multiply(y13, 2) ^ self.multiply(y2, 3) ^ y7
        x26 = y8 ^ y13 ^ self.multiply(y2, 2) ^ self.multiply(y7, 3)
        x27 = self.multiply(y8, 3) ^ y13 ^ y2 ^ self.multiply(y7, 2)

        x28 = self.multiply(y12, 2) ^ self.multiply(y1, 3) ^ y6 ^ y11
        x29 = y12 ^ self.multiply(y1, 2) ^ self.multiply(y6, 3) ^ y11
        x30 = y12 ^ y1 ^ self.multiply(y6, 2) ^ self.multiply(y11, 3)
        x31 = self.multiply(y12, 3) ^ y1 ^ y6 ^ self.multiply(y11, 2)

        # AddRoundKey
        x16 ^= key_schedule.round_keys[1][0]
        x17 ^= key_schedule.round_keys[1][1]
        x18 ^= key_schedule.round_keys[1][2]
        x19 ^= key_schedule.round_keys[1][3]

        x20 ^= key_schedule.round_keys[1][4]
        x21 ^= key_schedule.round_keys[1][5]
        x22 ^= key_schedule.round_keys[1][6]
        x23 ^= key_schedule.round_keys[1][7]

        x24 ^= key_schedule.round_keys[1][8]
        x25 ^= key_schedule.round_keys[1][9]
        x26 ^= key_schedule.round_keys[1][10]
        x27 ^= key_schedule.round_keys[1][11]

        x28 ^= key_schedule.round_keys[1][12]
        x29 ^= key_schedule.round_keys[1][13]
        x30 ^= key_schedule.round_keys[1][14]
        x31 ^= key_schedule.round_keys[1][15]

        # SubBytes
        y16 = s_box[x16]
        y17 = s_box[x17]
        y18 = s_box[x18]
        y19 = s_box[x19]

        y20 = s_box[x20]
        y21 = s_box[x21]
        y22 = s_box[x22]
        y23 = s_box[x23]

        y24 = s_box[x24]
        y25 = s_box[x25]
        y26 = s_box[x26]
        y27 = s_box[x27]

        y28 = s_box[x28]
        y29 = s_box[x29]
        y30 = s_box[x30]
        y31 = s_box[x31]

        variable_part = [0 for i in range(16)]

        variable_part[0] = \
            self.multiply((1 - self.state[0][0]) * y0, 2) ^ \
            self.multiply((1 - self.state[0][5]) * y5, 3) ^ \
            ((1 - self.state[0][10]) * y10) ^ \
            ((1 - self.state[0][15]) * y15)
        variable_part[1] = \
            ((1 - self.state[0][0]) * y0) ^ \
            self.multiply((1 - self.state[0][5]) * y5, 2) ^ \
            self.multiply((1 - self.state[0][10]) * y10, 3) ^ \
            ((1 - self.state[0][15]) * y15)
        variable_part[2] = \
            ((1 - self.state[0][0]) * y0) ^ \
            ((1 - self.state[0][5]) * y5) ^ \
            self.multiply((1 - self.state[0][10]) * y10, 2) ^ \
            self.multiply((1 - self.state[0][15]) * y15, 3)
        variable_part[3] = \
            self.multiply((1 - self.state[0][0]) * y0, 3) ^ \
            ((1 - self.state[0][5]) * y5) ^ \
            ((1 - self.state[0][10]) * y10) ^ \
            self.multiply((1 - self.state[0][15]) * y15, 2)

        variable_part[4] = \
            self.multiply((1 - self.state[0][4]) * y4, 2) ^ \
            self.multiply((1 - self.state[0][9]) * y9, 3) ^ \
            ((1 - self.state[0][14]) * y14) ^ \
            ((1 - self.state[0][3]) * y3)
        variable_part[5] = \
            ((1 - self.state[0][4]) * y4) ^ \
            self.multiply((1 - self.state[0][9]) * y9, 2) ^ \
            self.multiply((1 - self.state[0][14]) * y14, 3) ^ \
            ((1 - self.state[0][3]) * y3)
        variable_part[6] = \
            ((1 - self.state[0][4]) * y4) ^ \
            ((1 - self.state[0][9]) * y9) ^ \
            self.multiply((1 - self.state[0][14]) * y14, 2) ^ \
            self.multiply((1 - self.state[0][3]) * y3, 3)
        variable_part[7] = \
            self.multiply((1 - self.state[0][4]) * y4, 3) ^ \
            ((1 - self.state[0][9]) * y9) ^ \
            ((1 - self.state[0][14]) * y14) ^ \
            self.multiply((1 - self.state[0][3]) * y3, 2)

        variable_part[8] = \
            self.multiply((1 - self.state[0][8]) * y8, 2) ^ \
            self.multiply((1 - self.state[0][13]) * y13, 3) ^ \
            ((1 - self.state[0][2]) * y2) ^ \
            ((1 - self.state[0][7]) * y7)
        variable_part[9] = \
            ((1 - self.state[0][8]) * y8) ^ \
            self.multiply((1 - self.state[0][13]) * y13, 2) ^ \
            self.multiply((1 - self.state[0][2]) * y2, 3) ^ \
            ((1 - self.state[0][7]) * y7)
        variable_part[10] = \
            ((1 - self.state[0][8]) * y8) ^ \
            ((1 - self.state[0][13]) * y13) ^ \
            self.multiply((1 - self.state[0][2]) * y2, 2) ^ \
            self.multiply((1 - self.state[0][7]) * y7, 3)
        variable_part[11] = \
            self.multiply((1 - self.state[0][8]) * y8, 3) ^ \
            ((1 - self.state[0][13]) * y13) ^ \
            (1 - self.state[0][2]) * y2 ^ \
            self.multiply((1 - self.state[0][7]) * y7, 2)

        variable_part[12] = \
            self.multiply((1 - self.state[0][12]) * y12, 2) ^ \
            self.multiply((1 - self.state[0][1]) * y1, 3) ^ \
            ((1 - self.state[0][6]) * y6) ^ \
            ((1 - self.state[0][11]) * y11)
        variable_part[13] = \
            ((1 - self.state[0][12]) * y12) ^ \
            self.multiply((1 - self.state[0][1]) * y1, 2) ^ \
            self.multiply((1 - self.state[0][6]) * y6, 3) ^ \
            ((1 - self.state[0][11]) * y11)
        variable_part[14] = \
            ((1 - self.state[0][12]) * y12) ^ \
            ((1 - self.state[0][1]) * y1) ^ \
            self.multiply((1 - self.state[0][6]) * y6, 2) ^ \
            self.multiply((1 - self.state[0][11]) * y11, 3)
        variable_part[15] = \
            self.multiply((1 - self.state[0][12]) * y12, 3) ^ \
            ((1 - self.state[0][1]) * y1) ^ \
            ((1 - self.state[0][6]) * y6) ^ \
            self.multiply((1 - self.state[0][11]) * y11, 2)

        for i in range(16):
            if self.state[1][i]:
                self.round_keys[1][i] = key_schedule.round_keys[1][i] ^ variable_part[i]

        # Round 2
        variable_part = [0 for i in range(16)]

        variable_part[0] = \
            self.multiply((1 - self.state[1][0]) * y16, 2) ^ \
            self.multiply((1 - self.state[1][5]) * y21, 3) ^ \
            ((1 - self.state[1][10]) * y26) ^ \
            ((1 - self.state[1][15]) * y31)
        variable_part[1] = \
            ((1 - self.state[1][0]) * y16) ^ \
            self.multiply((1 - self.state[1][5]) * y21, 2) ^ \
            self.multiply((1 - self.state[1][10]) * y26, 3) ^ \
            ((1 - self.state[1][15]) * y31)
        variable_part[2] = \
            ((1 - self.state[1][0]) * y16) ^ \
            ((1 - self.state[1][5]) * y21) ^ \
            self.multiply((1 - self.state[1][10]) * y26, 2) ^ \
            self.multiply((1 - self.state[1][15]) * y31, 3)
        variable_part[3] = \
            self.multiply((1 - self.state[1][0]) * y16, 3) ^ \
            ((1 - self.state[1][5]) * y21) ^ \
            ((1 - self.state[1][10]) * y26) ^ \
            self.multiply((1 - self.state[1][15]) * y31, 2)

        variable_part[4] = \
            self.multiply((1 - self.state[1][4]) * y20, 2) ^ \
            self.multiply((1 - self.state[1][9]) * y25, 3) ^ \
            ((1 - self.state[1][14]) * y30) ^ \
            ((1 - self.state[1][3]) * y19)
        variable_part[5] = \
            ((1 - self.state[1][4]) * y20) ^ \
            self.multiply((1 - self.state[1][9]) * y25, 2) ^ \
            self.multiply((1 - self.state[1][14]) * y30, 3) ^ \
            ((1 - self.state[1][3]) * y19)
        variable_part[6] = \
            ((1 - self.state[1][4]) * y20) ^ \
            ((1 - self.state[1][9]) * y25) ^ \
            self.multiply((1 - self.state[1][14]) * y30, 2) ^ \
            self.multiply((1 - self.state[1][3]) * y19, 3)
        variable_part[7] = \
            self.multiply((1 - self.state[1][4]) * y20, 3) ^ \
            ((1 - self.state[1][9]) * y25) ^ \
            ((1 - self.state[1][14]) * y30) ^ \
            self.multiply((1 - self.state[1][3]) * y19, 2)

        variable_part[8] = \
            self.multiply((1 - self.state[1][8]) * y24, 2) ^ \
            self.multiply((1 - self.state[1][13]) * y29, 3) ^ \
            ((1 - self.state[1][2]) * y18) ^ \
            ((1 - self.state[1][7]) * y23)
        variable_part[9] = \
            ((1 - self.state[1][8]) * y24) ^ \
            self.multiply((1 - self.state[1][13]) * y29, 2) ^ \
            self.multiply((1 - self.state[1][2]) * y18, 3) ^ \
            ((1 - self.state[1][7]) * y23)
        variable_part[10] = \
            ((1 - self.state[1][8]) * y24) ^ \
            ((1 - self.state[1][13]) * y29) ^ \
            self.multiply((1 - self.state[1][2]) * y18, 2) ^ \
            self.multiply((1 - self.state[1][7]) * y23, 3)
        variable_part[11] = \
            self.multiply((1 - self.state[1][8]) * y24, 3) ^ \
            ((1 - self.state[1][13]) * y29) ^ \
            ((1 - self.state[1][2]) * y18) ^ \
            self.multiply((1 - self.state[1][7]) * y23, 2)

        variable_part[12] = \
            self.multiply((1 - self.state[1][12]) * y28, 2) ^ \
            self.multiply((1 - self.state[1][1]) * y17, 3) ^ \
            ((1 - self.state[1][6]) * y22) ^ \
            ((1 - self.state[1][11]) * y27)
        variable_part[13] = \
            ((1 - self.state[1][12]) * y28) ^ \
            self.multiply((1 - self.state[1][1]) * y17, 2) ^ \
            self.multiply((1 - self.state[1][6]) * y22, 3) ^ \
            ((1 - self.state[1][11]) * y27)
        variable_part[14] = \
            ((1 - self.state[1][12]) * y28) ^ \
            ((1 - self.state[1][1]) * y17) ^ \
            self.multiply((1 - self.state[1][6]) * y22, 2) ^ \
            self.multiply((1 - self.state[1][11]) * y27, 3)
        variable_part[15] = \
            self.multiply((1 - self.state[1][12]) * y28, 3) ^ \
            ((1 - self.state[1][1]) * y17) ^ \
            ((1 - self.state[1][6]) * y22) ^ \
            self.multiply((1 - self.state[1][11]) * y27, 2)

        for i in range(16):
            if self.state[2][i]:
                self.round_keys[2][i] = key_schedule.round_keys[2][i] ^ variable_part[i]

        # Round 3
        self.round_keys[3][0] = key_schedule.round_keys[3][0]
        self.round_keys[3][1] = key_schedule.round_keys[3][1]
        self.round_keys[3][2] = key_schedule.round_keys[3][2]
        self.round_keys[3][3] = key_schedule.round_keys[3][3]

        self.round_keys[3][4] = key_schedule.round_keys[3][4]
        self.round_keys[3][5] = key_schedule.round_keys[3][5]
        self.round_keys[3][6] = key_schedule.round_keys[3][6]
        self.round_keys[3][7] = key_schedule.round_keys[3][7]

        self.round_keys[3][8] = key_schedule.round_keys[3][8]
        self.round_keys[3][9] = key_schedule.round_keys[3][9]
        self.round_keys[3][10] = key_schedule.round_keys[3][10]
        self.round_keys[3][11] = key_schedule.round_keys[3][11]

        self.round_keys[3][12] = key_schedule.round_keys[3][12]
        self.round_keys[3][13] = key_schedule.round_keys[3][13]
        self.round_keys[3][14] = key_schedule.round_keys[3][14]
        self.round_keys[3][15] = key_schedule.round_keys[3][15]

        if self.debug:
            for i in range(4):
                print('{:2}: '.format(i), end='')
                for j in range(16):
                    print('{} '.format(format(self.round_keys[i][j], '02x')), end='')
                print()

            print()
            print()

            for i in range(4):
                print('{:2}: '.format(i), end='')
                print('[ ', end='')
                for j in range(16):
                    print('0x{}, '.format(format(self.round_keys[i][j], '02x')), end='')
                print(']', end='')
                print()

        round_keys = []
        for i in range(4):
            for j in range(16):
                round_keys.append(self.round_keys[i][j])

        return round_keys
