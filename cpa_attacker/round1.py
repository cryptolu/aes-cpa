from aes_cipher.constants import s_box


import copy


class Round1:
    def __init__(self, round_keys, state):
        self.round_keys = round_keys
        self.state = copy.deepcopy(state)

        for i in range(len(state)):
            for j in range(16):
                if 0 != self.state[i][j]:
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

    def get_plaintext_part(self, plaintext, index):
        if 16 == index:
            return self.get_plaintext_part_round1_k0(plaintext)
        elif 17 == index:
            return self.get_plaintext_part_round1_k1(plaintext)
        elif 18 == index:
            return self.get_plaintext_part_round1_k2(plaintext)
        elif 19 == index:
            return self.get_plaintext_part_round1_k3(plaintext)
        elif 20 == index:
            return self.get_plaintext_part_round1_k4(plaintext)
        elif 21 == index:
            return self.get_plaintext_part_round1_k5(plaintext)
        elif 22 == index:
            return self.get_plaintext_part_round1_k6(plaintext)
        elif 23 == index:
            return self.get_plaintext_part_round1_k7(plaintext)
        elif 24 == index:
            return self.get_plaintext_part_round1_k8(plaintext)
        elif 25 == index:
            return self.get_plaintext_part_round1_k9(plaintext)
        elif 26 == index:
            return self.get_plaintext_part_round1_k10(plaintext)
        elif 27 == index:
            return self.get_plaintext_part_round1_k11(plaintext)
        elif 28 == index:
            return self.get_plaintext_part_round1_k12(plaintext)
        elif 29 == index:
            return self.get_plaintext_part_round1_k13(plaintext)
        elif 30 == index:
            return self.get_plaintext_part_round1_k14(plaintext)
        elif 31 == index:
            return self.get_plaintext_part_round1_k15(plaintext)

    def get_plaintext_part_round1_k0(self, plaintext):
        # Round 0
        x0 = (plaintext >> 120) & 0xff
        x5 = (plaintext >> 80) & 0xff
        x10 = (plaintext >> 40) & 0xff
        x15 = (plaintext >> 0) & 0xff

        # AddRoundKey
        x0 ^= self.round_keys[0]
        x5 ^= self.round_keys[5]
        x10 ^= self.round_keys[10]
        x15 ^= self.round_keys[15]

        # SubBytes
        y0 = s_box[x0]
        y5 = s_box[x5]
        y10 = s_box[x10]
        y15 = s_box[x15]

        y0 *= self.state[0][0]
        y5 *= self.state[0][5]
        y10 *= self.state[0][10]
        y15 *= self.state[0][15]

        z = self.multiply(y0, 2) ^ self.multiply(y5, 3) ^ y10 ^ y15
        return z

    def get_plaintext_part_round1_k1(self, plaintext):
        # Round 0
        x0 = (plaintext >> 120) & 0xff
        x5 = (plaintext >> 80) & 0xff
        x10 = (plaintext >> 40) & 0xff
        x15 = (plaintext >> 0) & 0xff

        # AddRoundKey
        x0 ^= self.round_keys[0]
        x5 ^= self.round_keys[5]
        x10 ^= self.round_keys[10]
        x15 ^= self.round_keys[15]

        # SubBytes
        y0 = s_box[x0]
        y5 = s_box[x5]
        y10 = s_box[x10]
        y15 = s_box[x15]

        y0 *= self.state[0][0]
        y5 *= self.state[0][5]
        y10 *= self.state[0][10]
        y15 *= self.state[0][15]

        z = y0 ^ self.multiply(y5, 2) ^ self.multiply(y10, 3) ^ y15
        return z

    def get_plaintext_part_round1_k2(self, plaintext):
        # Round 0
        x0 = (plaintext >> 120) & 0xff
        x5 = (plaintext >> 80) & 0xff
        x10 = (plaintext >> 40) & 0xff
        x15 = (plaintext >> 0) & 0xff

        # AddRoundKey
        x0 ^= self.round_keys[0]
        x5 ^= self.round_keys[5]
        x10 ^= self.round_keys[10]
        x15 ^= self.round_keys[15]

        # SubBytes
        y0 = s_box[x0]
        y5 = s_box[x5]
        y10 = s_box[x10]
        y15 = s_box[x15]

        y0 *= self.state[0][0]
        y5 *= self.state[0][5]
        y10 *= self.state[0][10]
        y15 *= self.state[0][15]

        z = y0 ^ y5 ^ self.multiply(y10, 2) ^ self.multiply(y15, 3)
        return z

    def get_plaintext_part_round1_k3(self, plaintext):
        # Round 0
        x0 = (plaintext >> 120) & 0xff
        x5 = (plaintext >> 80) & 0xff
        x10 = (plaintext >> 40) & 0xff
        x15 = (plaintext >> 0) & 0xff

        # AddRoundKey
        x0 ^= self.round_keys[0]
        x5 ^= self.round_keys[5]
        x10 ^= self.round_keys[10]
        x15 ^= self.round_keys[15]

        # SubBytes
        y0 = s_box[x0]
        y5 = s_box[x5]
        y10 = s_box[x10]
        y15 = s_box[x15]

        y0 *= self.state[0][0]
        y5 *= self.state[0][5]
        y10 *= self.state[0][10]
        y15 *= self.state[0][15]

        z = self.multiply(y0, 3) ^ y5 ^ y10 ^ self.multiply(y15, 2)
        return z

    def get_plaintext_part_round1_k4(self, plaintext):
        # Round 0
        x4 = (plaintext >> 88) & 0xff
        x9 = (plaintext >> 48) & 0xff
        x14 = (plaintext >> 8) & 0xff
        x3 = (plaintext >> 96) & 0xff

        # AddRoundKey
        x4 ^= self.round_keys[4]
        x9 ^= self.round_keys[9]
        x14 ^= self.round_keys[14]
        x3 ^= self.round_keys[3]

        # SubBytes
        y4 = s_box[x4]
        y9 = s_box[x9]
        y14 = s_box[x14]
        y3 = s_box[x3]

        y4 *= self.state[0][4]
        y9 *= self.state[0][9]
        y14 *= self.state[0][14]
        y3 *= self.state[0][3]

        z = self.multiply(y4, 2) ^ self.multiply(y9, 3) ^ y14 ^ y3
        return z

    def get_plaintext_part_round1_k5(self, plaintext):
        # Round 0
        x4 = (plaintext >> 88) & 0xff
        x9 = (plaintext >> 48) & 0xff
        x14 = (plaintext >> 8) & 0xff
        x3 = (plaintext >> 96) & 0xff

        # AddRoundKey
        x4 ^= self.round_keys[4]
        x9 ^= self.round_keys[9]
        x14 ^= self.round_keys[14]
        x3 ^= self.round_keys[3]

        # SubBytes
        y4 = s_box[x4]
        y9 = s_box[x9]
        y14 = s_box[x14]
        y3 = s_box[x3]

        y4 *= self.state[0][4]
        y9 *= self.state[0][9]
        y14 *= self.state[0][14]
        y3 *= self.state[0][3]

        z = y4 ^ self.multiply(y9, 2) ^ self.multiply(y14, 3) ^ y3
        return z

    def get_plaintext_part_round1_k6(self, plaintext):
        # Round 0
        x4 = (plaintext >> 88) & 0xff
        x9 = (plaintext >> 48) & 0xff
        x14 = (plaintext >> 8) & 0xff
        x3 = (plaintext >> 96) & 0xff

        # AddRoundKey
        x4 ^= self.round_keys[4]
        x9 ^= self.round_keys[9]
        x14 ^= self.round_keys[14]
        x3 ^= self.round_keys[3]

        # SubBytes
        y4 = s_box[x4]
        y9 = s_box[x9]
        y14 = s_box[x14]
        y3 = s_box[x3]

        y4 *= self.state[0][4]
        y9 *= self.state[0][9]
        y14 *= self.state[0][14]
        y3 *= self.state[0][3]

        z = y4 ^ y9 ^ self.multiply(y14, 2) ^ self.multiply(y3, 3)
        return z

    def get_plaintext_part_round1_k7(self, plaintext):
        # Round 0
        x4 = (plaintext >> 88) & 0xff
        x9 = (plaintext >> 48) & 0xff
        x14 = (plaintext >> 8) & 0xff
        x3 = (plaintext >> 96) & 0xff

        # AddRoundKey
        x4 ^= self.round_keys[4]
        x9 ^= self.round_keys[9]
        x14 ^= self.round_keys[14]
        x3 ^= self.round_keys[3]

        # SubBytes
        y4 = s_box[x4]
        y9 = s_box[x9]
        y14 = s_box[x14]
        y3 = s_box[x3]

        y4 *= self.state[0][4]
        y9 *= self.state[0][9]
        y14 *= self.state[0][14]
        y3 *= self.state[0][3]

        z = self.multiply(y4, 3) ^ y9 ^ y14 ^ self.multiply(y3, 2)
        return z

    def get_plaintext_part_round1_k8(self, plaintext):
        # Round 0
        x8 = (plaintext >> 56) & 0xff
        x13 = (plaintext >> 16) & 0xff
        x2 = (plaintext >> 104) & 0xff
        x7 = (plaintext >> 64) & 0xff

        # AddRoundKey
        x8 ^= self.round_keys[8]
        x13 ^= self.round_keys[13]
        x2 ^= self.round_keys[2]
        x7 ^= self.round_keys[7]

        # SubBytes
        y8 = s_box[x8]
        y13 = s_box[x13]
        y2 = s_box[x2]
        y7 = s_box[x7]

        y8 *= self.state[0][8]
        y13 *= self.state[0][13]
        y2 *= self.state[0][2]
        y7 *= self.state[0][7]

        z = self.multiply(y8, 2) ^ self.multiply(y13, 3) ^ y2 ^ y7
        return z

    def get_plaintext_part_round1_k9(self, plaintext):
        # Round 0
        x8 = (plaintext >> 56) & 0xff
        x13 = (plaintext >> 16) & 0xff
        x2 = (plaintext >> 104) & 0xff
        x7 = (plaintext >> 64) & 0xff

        # AddRoundKey
        x8 ^= self.round_keys[8]
        x13 ^= self.round_keys[13]
        x2 ^= self.round_keys[2]
        x7 ^= self.round_keys[7]

        # SubBytes
        y8 = s_box[x8]
        y13 = s_box[x13]
        y2 = s_box[x2]
        y7 = s_box[x7]

        y8 *= self.state[0][8]
        y13 *= self.state[0][13]
        y2 *= self.state[0][2]
        y7 *= self.state[0][7]

        z = y8 ^ self.multiply(y13, 2) ^ self.multiply(y2, 3) ^ y7
        return z

    def get_plaintext_part_round1_k10(self, plaintext):
        # Round 0
        x8 = (plaintext >> 56) & 0xff
        x13 = (plaintext >> 16) & 0xff
        x2 = (plaintext >> 104) & 0xff
        x7 = (plaintext >> 64) & 0xff

        # AddRoundKey
        x8 ^= self.round_keys[8]
        x13 ^= self.round_keys[13]
        x2 ^= self.round_keys[2]
        x7 ^= self.round_keys[7]

        # SubBytes
        y8 = s_box[x8]
        y13 = s_box[x13]
        y2 = s_box[x2]
        y7 = s_box[x7]

        y8 *= self.state[0][8]
        y13 *= self.state[0][13]
        y2 *= self.state[0][2]
        y7 *= self.state[0][7]

        z = y8 ^ y13 ^ self.multiply(y2, 2) ^ self.multiply(y7, 3)
        return z

    def get_plaintext_part_round1_k11(self, plaintext):
        # Round 0
        x8 = (plaintext >> 56) & 0xff
        x13 = (plaintext >> 16) & 0xff
        x2 = (plaintext >> 104) & 0xff
        x7 = (plaintext >> 64) & 0xff

        # AddRoundKey
        x8 ^= self.round_keys[8]
        x13 ^= self.round_keys[13]
        x2 ^= self.round_keys[2]
        x7 ^= self.round_keys[7]

        # SubBytes
        y8 = s_box[x8]
        y13 = s_box[x13]
        y2 = s_box[x2]
        y7 = s_box[x7]

        y8 *= self.state[0][8]
        y13 *= self.state[0][13]
        y2 *= self.state[0][2]
        y7 *= self.state[0][7]

        z = self.multiply(y8, 3) ^ y13 ^ y2 ^ self.multiply(y7, 2)
        return z

    def get_plaintext_part_round1_k12(self, plaintext):
        # Round 0
        x12 = (plaintext >> 24) & 0xff
        x1 = (plaintext >> 112) & 0xff
        x6 = (plaintext >> 72) & 0xff
        x11 = (plaintext >> 32) & 0xff

        # AddRoundKey
        x12 ^= self.round_keys[12]
        x1 ^= self.round_keys[1]
        x6 ^= self.round_keys[6]
        x11 ^= self.round_keys[11]

        # SubBytes
        y12 = s_box[x12]
        y1 = s_box[x1]
        y6 = s_box[x6]
        y11 = s_box[x11]

        y12 *= self.state[0][12]
        y1 *= self.state[0][1]
        y6 *= self.state[0][6]
        y11 *= self.state[0][11]

        z = self.multiply(y12, 2) ^ self.multiply(y1, 3) ^ y6 ^ y11
        return z

    def get_plaintext_part_round1_k13(self, plaintext):
        # Round 0
        x12 = (plaintext >> 24) & 0xff
        x1 = (plaintext >> 112) & 0xff
        x6 = (plaintext >> 72) & 0xff
        x11 = (plaintext >> 32) & 0xff

        # AddRoundKey
        x12 ^= self.round_keys[12]
        x1 ^= self.round_keys[1]
        x6 ^= self.round_keys[6]
        x11 ^= self.round_keys[11]

        # SubBytes
        y12 = s_box[x12]
        y1 = s_box[x1]
        y6 = s_box[x6]
        y11 = s_box[x11]

        y12 *= self.state[0][12]
        y1 *= self.state[0][1]
        y6 *= self.state[0][6]
        y11 *= self.state[0][11]

        z = y12 ^ self.multiply(y1, 2) ^ self.multiply(y6, 3) ^ y11
        return z

    def get_plaintext_part_round1_k14(self, plaintext):
        # Round 0
        x12 = (plaintext >> 24) & 0xff
        x1 = (plaintext >> 112) & 0xff
        x6 = (plaintext >> 72) & 0xff
        x11 = (plaintext >> 32) & 0xff

        # AddRoundKey
        x12 ^= self.round_keys[12]
        x1 ^= self.round_keys[1]
        x6 ^= self.round_keys[6]
        x11 ^= self.round_keys[11]

        # SubBytes
        y12 = s_box[x12]
        y1 = s_box[x1]
        y6 = s_box[x6]
        y11 = s_box[x11]

        y12 *= self.state[0][12]
        y1 *= self.state[0][1]
        y6 *= self.state[0][6]
        y11 *= self.state[0][11]

        z = y12 ^ y1 ^ self.multiply(y6, 2) ^ self.multiply(y11, 3)
        return z

    def get_plaintext_part_round1_k15(self, plaintext):
        # Round 0
        x12 = (plaintext >> 24) & 0xff
        x1 = (plaintext >> 112) & 0xff
        x6 = (plaintext >> 72) & 0xff
        x11 = (plaintext >> 32) & 0xff

        # AddRoundKey
        x12 ^= self.round_keys[12]
        x1 ^= self.round_keys[1]
        x6 ^= self.round_keys[6]
        x11 ^= self.round_keys[11]

        # SubBytes
        y12 = s_box[x12]
        y1 = s_box[x1]
        y6 = s_box[x6]
        y11 = s_box[x11]

        y12 *= self.state[0][12]
        y1 *= self.state[0][1]
        y6 *= self.state[0][6]
        y11 *= self.state[0][11]

        z = self.multiply(y12, 3) ^ y1 ^ y6 ^ self.multiply(y11, 2)
        return z
