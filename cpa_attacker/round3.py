from aes_cipher.constants import s_box


import copy


class Round3:
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
        if 48 == index:
            return self.get_plaintext_part_round3_k0(plaintext)
        elif 49 == index:
            return self.get_plaintext_part_round3_k1(plaintext)
        elif 50 == index:
            return self.get_plaintext_part_round3_k2(plaintext)
        elif 51 == index:
            return self.get_plaintext_part_round3_k3(plaintext)
        elif 52 == index:
            return self.get_plaintext_part_round3_k4(plaintext)
        elif 53 == index:
            return self.get_plaintext_part_round3_k5(plaintext)
        elif 54 == index:
            return self.get_plaintext_part_round3_k6(plaintext)
        elif 55 == index:
            return self.get_plaintext_part_round3_k7(plaintext)
        elif 56 == index:
            return self.get_plaintext_part_round3_k8(plaintext)
        elif 57 == index:
            return self.get_plaintext_part_round3_k9(plaintext)
        elif 58 == index:
            return self.get_plaintext_part_round3_k10(plaintext)
        elif 59 == index:
            return self.get_plaintext_part_round3_k11(plaintext)
        elif 60 == index:
            return self.get_plaintext_part_round3_k12(plaintext)
        elif 61 == index:
            return self.get_plaintext_part_round3_k13(plaintext)
        elif 62 == index:
            return self.get_plaintext_part_round3_k14(plaintext)
        elif 63 == index:
            return self.get_plaintext_part_round3_k15(plaintext)

    def get_plaintext_part_round3_k0(self, plaintext):
        # Round 0
        x0 = (plaintext >> 120) & 0xff
        x1 = (plaintext >> 112) & 0xff
        x2 = (plaintext >> 104) & 0xff
        x3 = (plaintext >> 96) & 0xff

        x4 = (plaintext >> 88) & 0xff
        x5 = (plaintext >> 80) & 0xff
        x6 = (plaintext >> 72) & 0xff
        x7 = (plaintext >> 64) & 0xff

        x8 = (plaintext >> 56) & 0xff
        x9 = (plaintext >> 48) & 0xff
        x10 = (plaintext >> 40) & 0xff
        x11 = (plaintext >> 32) & 0xff

        x12 = (plaintext >> 24) & 0xff
        x13 = (plaintext >> 16) & 0xff
        x14 = (plaintext >> 8) & 0xff
        x15 = (plaintext >> 0) & 0xff

        # AddRoundKey
        x0 ^= self.round_keys[0]
        x1 ^= self.round_keys[1]
        x2 ^= self.round_keys[2]
        x3 ^= self.round_keys[3]

        x4 ^= self.round_keys[4]
        x5 ^= self.round_keys[5]
        x6 ^= self.round_keys[6]
        x7 ^= self.round_keys[7]

        x8 ^= self.round_keys[8]
        x9 ^= self.round_keys[9]
        x10 ^= self.round_keys[10]
        x11 ^= self.round_keys[11]

        x12 ^= self.round_keys[12]
        x13 ^= self.round_keys[13]
        x14 ^= self.round_keys[14]
        x15 ^= self.round_keys[15]

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

        # Round 1
        y0 *= self.state[0][0]
        y1 *= self.state[0][1]
        y2 *= self.state[0][2]
        y3 *= self.state[0][3]

        y4 *= self.state[0][4]
        y5 *= self.state[0][5]
        y6 *= self.state[0][6]
        y7 *= self.state[0][7]

        y8 *= self.state[0][8]
        y9 *= self.state[0][9]
        y10 *= self.state[0][10]
        y11 *= self.state[0][11]

        y12 *= self.state[0][12]
        y13 *= self.state[0][13]
        y14 *= self.state[0][14]
        y15 *= self.state[0][15]

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
        x16 ^= self.round_keys[16]
        x17 ^= self.round_keys[17]
        x18 ^= self.round_keys[18]
        x19 ^= self.round_keys[19]

        x20 ^= self.round_keys[20]
        x21 ^= self.round_keys[21]
        x22 ^= self.round_keys[22]
        x23 ^= self.round_keys[23]

        x24 ^= self.round_keys[24]
        x25 ^= self.round_keys[25]
        x26 ^= self.round_keys[26]
        x27 ^= self.round_keys[27]

        x28 ^= self.round_keys[28]
        x29 ^= self.round_keys[29]
        x30 ^= self.round_keys[30]
        x31 ^= self.round_keys[31]

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

        # Round 2
        y16 *= self.state[1][0]
        y17 *= self.state[1][1]
        y18 *= self.state[1][2]
        y19 *= self.state[1][3]

        y20 *= self.state[1][4]
        y21 *= self.state[1][5]
        y22 *= self.state[1][6]
        y23 *= self.state[1][7]

        y24 *= self.state[1][8]
        y25 *= self.state[1][9]
        y26 *= self.state[1][10]
        y27 *= self.state[1][11]

        y28 *= self.state[1][12]
        y29 *= self.state[1][13]
        y30 *= self.state[1][14]
        y31 *= self.state[1][15]

        x32 = self.multiply(y16, 2) ^ self.multiply(y21, 3) ^ y26 ^ y31
        x37 = y20 ^ self.multiply(y25, 2) ^ self.multiply(y30, 3) ^ y19
        x42 = y24 ^ y29 ^ self.multiply(y18, 2) ^ self.multiply(y23, 3)
        x47 = self.multiply(y28, 3) ^ y17 ^ y22 ^ self.multiply(y27, 2)

        # AddRoundKey
        x32 ^= self.round_keys[32]
        x37 ^= self.round_keys[37]
        x42 ^= self.round_keys[42]
        x47 ^= self.round_keys[47]

        # SubBytes
        y32 = s_box[x32]
        y37 = s_box[x37]
        y42 = s_box[x42]
        y47 = s_box[x47]

        y32 *= self.state[2][0]
        y37 *= self.state[2][5]
        y42 *= self.state[2][10]
        y47 *= self.state[2][15]

        z = self.multiply(y32, 2) ^ self.multiply(y37, 3) ^ y42 ^ y47
        return z

    def get_plaintext_part_round3_k1(self, plaintext):
        # Round 0
        x0 = (plaintext >> 120) & 0xff
        x1 = (plaintext >> 112) & 0xff
        x2 = (plaintext >> 104) & 0xff
        x3 = (plaintext >> 96) & 0xff

        x4 = (plaintext >> 88) & 0xff
        x5 = (plaintext >> 80) & 0xff
        x6 = (plaintext >> 72) & 0xff
        x7 = (plaintext >> 64) & 0xff

        x8 = (plaintext >> 56) & 0xff
        x9 = (plaintext >> 48) & 0xff
        x10 = (plaintext >> 40) & 0xff
        x11 = (plaintext >> 32) & 0xff

        x12 = (plaintext >> 24) & 0xff
        x13 = (plaintext >> 16) & 0xff
        x14 = (plaintext >> 8) & 0xff
        x15 = (plaintext >> 0) & 0xff

        # AddRoundKey
        x0 ^= self.round_keys[0]
        x1 ^= self.round_keys[1]
        x2 ^= self.round_keys[2]
        x3 ^= self.round_keys[3]

        x4 ^= self.round_keys[4]
        x5 ^= self.round_keys[5]
        x6 ^= self.round_keys[6]
        x7 ^= self.round_keys[7]

        x8 ^= self.round_keys[8]
        x9 ^= self.round_keys[9]
        x10 ^= self.round_keys[10]
        x11 ^= self.round_keys[11]

        x12 ^= self.round_keys[12]
        x13 ^= self.round_keys[13]
        x14 ^= self.round_keys[14]
        x15 ^= self.round_keys[15]

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

        # Round 1
        y0 *= self.state[0][0]
        y1 *= self.state[0][1]
        y2 *= self.state[0][2]
        y3 *= self.state[0][3]

        y4 *= self.state[0][4]
        y5 *= self.state[0][5]
        y6 *= self.state[0][6]
        y7 *= self.state[0][7]

        y8 *= self.state[0][8]
        y9 *= self.state[0][9]
        y10 *= self.state[0][10]
        y11 *= self.state[0][11]

        y12 *= self.state[0][12]
        y13 *= self.state[0][13]
        y14 *= self.state[0][14]
        y15 *= self.state[0][15]

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
        x16 ^= self.round_keys[16]
        x17 ^= self.round_keys[17]
        x18 ^= self.round_keys[18]
        x19 ^= self.round_keys[19]

        x20 ^= self.round_keys[20]
        x21 ^= self.round_keys[21]
        x22 ^= self.round_keys[22]
        x23 ^= self.round_keys[23]

        x24 ^= self.round_keys[24]
        x25 ^= self.round_keys[25]
        x26 ^= self.round_keys[26]
        x27 ^= self.round_keys[27]

        x28 ^= self.round_keys[28]
        x29 ^= self.round_keys[29]
        x30 ^= self.round_keys[30]
        x31 ^= self.round_keys[31]

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

        # Round 2
        y16 *= self.state[1][0]
        y17 *= self.state[1][1]
        y18 *= self.state[1][2]
        y19 *= self.state[1][3]

        y20 *= self.state[1][4]
        y21 *= self.state[1][5]
        y22 *= self.state[1][6]
        y23 *= self.state[1][7]

        y24 *= self.state[1][8]
        y25 *= self.state[1][9]
        y26 *= self.state[1][10]
        y27 *= self.state[1][11]

        y28 *= self.state[1][12]
        y29 *= self.state[1][13]
        y30 *= self.state[1][14]
        y31 *= self.state[1][15]

        x32 = self.multiply(y16, 2) ^ self.multiply(y21, 3) ^ y26 ^ y31
        x37 = y20 ^ self.multiply(y25, 2) ^ self.multiply(y30, 3) ^ y19
        x42 = y24 ^ y29 ^ self.multiply(y18, 2) ^ self.multiply(y23, 3)
        x47 = self.multiply(y28, 3) ^ y17 ^ y22 ^ self.multiply(y27, 2)

        # AddRoundKey
        x32 ^= self.round_keys[32]
        x37 ^= self.round_keys[37]
        x42 ^= self.round_keys[42]
        x47 ^= self.round_keys[47]

        # SubBytes
        y32 = s_box[x32]
        y37 = s_box[x37]
        y42 = s_box[x42]
        y47 = s_box[x47]

        y32 *= self.state[2][0]
        y37 *= self.state[2][5]
        y42 *= self.state[2][10]
        y47 *= self.state[2][15]

        z = y32 ^ self.multiply(y37, 2) ^ self.multiply(y42, 3) ^ y47
        return z

    def get_plaintext_part_round3_k2(self, plaintext):
        # Round 0
        x0 = (plaintext >> 120) & 0xff
        x1 = (plaintext >> 112) & 0xff
        x2 = (plaintext >> 104) & 0xff
        x3 = (plaintext >> 96) & 0xff

        x4 = (plaintext >> 88) & 0xff
        x5 = (plaintext >> 80) & 0xff
        x6 = (plaintext >> 72) & 0xff
        x7 = (plaintext >> 64) & 0xff

        x8 = (plaintext >> 56) & 0xff
        x9 = (plaintext >> 48) & 0xff
        x10 = (plaintext >> 40) & 0xff
        x11 = (plaintext >> 32) & 0xff

        x12 = (plaintext >> 24) & 0xff
        x13 = (plaintext >> 16) & 0xff
        x14 = (plaintext >> 8) & 0xff
        x15 = (plaintext >> 0) & 0xff

        # AddRoundKey
        x0 ^= self.round_keys[0]
        x1 ^= self.round_keys[1]
        x2 ^= self.round_keys[2]
        x3 ^= self.round_keys[3]

        x4 ^= self.round_keys[4]
        x5 ^= self.round_keys[5]
        x6 ^= self.round_keys[6]
        x7 ^= self.round_keys[7]

        x8 ^= self.round_keys[8]
        x9 ^= self.round_keys[9]
        x10 ^= self.round_keys[10]
        x11 ^= self.round_keys[11]

        x12 ^= self.round_keys[12]
        x13 ^= self.round_keys[13]
        x14 ^= self.round_keys[14]
        x15 ^= self.round_keys[15]

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

        # Round 1
        y0 *= self.state[0][0]
        y1 *= self.state[0][1]
        y2 *= self.state[0][2]
        y3 *= self.state[0][3]

        y4 *= self.state[0][4]
        y5 *= self.state[0][5]
        y6 *= self.state[0][6]
        y7 *= self.state[0][7]

        y8 *= self.state[0][8]
        y9 *= self.state[0][9]
        y10 *= self.state[0][10]
        y11 *= self.state[0][11]

        y12 *= self.state[0][12]
        y13 *= self.state[0][13]
        y14 *= self.state[0][14]
        y15 *= self.state[0][15]

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
        x16 ^= self.round_keys[16]
        x17 ^= self.round_keys[17]
        x18 ^= self.round_keys[18]
        x19 ^= self.round_keys[19]

        x20 ^= self.round_keys[20]
        x21 ^= self.round_keys[21]
        x22 ^= self.round_keys[22]
        x23 ^= self.round_keys[23]

        x24 ^= self.round_keys[24]
        x25 ^= self.round_keys[25]
        x26 ^= self.round_keys[26]
        x27 ^= self.round_keys[27]

        x28 ^= self.round_keys[28]
        x29 ^= self.round_keys[29]
        x30 ^= self.round_keys[30]
        x31 ^= self.round_keys[31]

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

        # Round 2
        y16 *= self.state[1][0]
        y17 *= self.state[1][1]
        y18 *= self.state[1][2]
        y19 *= self.state[1][3]

        y20 *= self.state[1][4]
        y21 *= self.state[1][5]
        y22 *= self.state[1][6]
        y23 *= self.state[1][7]

        y24 *= self.state[1][8]
        y25 *= self.state[1][9]
        y26 *= self.state[1][10]
        y27 *= self.state[1][11]

        y28 *= self.state[1][12]
        y29 *= self.state[1][13]
        y30 *= self.state[1][14]
        y31 *= self.state[1][15]

        x32 = self.multiply(y16, 2) ^ self.multiply(y21, 3) ^ y26 ^ y31
        x37 = y20 ^ self.multiply(y25, 2) ^ self.multiply(y30, 3) ^ y19
        x42 = y24 ^ y29 ^ self.multiply(y18, 2) ^ self.multiply(y23, 3)
        x47 = self.multiply(y28, 3) ^ y17 ^ y22 ^ self.multiply(y27, 2)

        # AddRoundKey
        x32 ^= self.round_keys[32]
        x37 ^= self.round_keys[37]
        x42 ^= self.round_keys[42]
        x47 ^= self.round_keys[47]

        # SubBytes
        y32 = s_box[x32]
        y37 = s_box[x37]
        y42 = s_box[x42]
        y47 = s_box[x47]

        y32 *= self.state[2][0]
        y37 *= self.state[2][5]
        y42 *= self.state[2][10]
        y47 *= self.state[2][15]

        z = y32 ^ y37 ^ self.multiply(y42, 2) ^ self.multiply(y47, 3)
        return z

    def get_plaintext_part_round3_k3(self, plaintext):
        # Round 0
        x0 = (plaintext >> 120) & 0xff
        x1 = (plaintext >> 112) & 0xff
        x2 = (plaintext >> 104) & 0xff
        x3 = (plaintext >> 96) & 0xff

        x4 = (plaintext >> 88) & 0xff
        x5 = (plaintext >> 80) & 0xff
        x6 = (plaintext >> 72) & 0xff
        x7 = (plaintext >> 64) & 0xff

        x8 = (plaintext >> 56) & 0xff
        x9 = (plaintext >> 48) & 0xff
        x10 = (plaintext >> 40) & 0xff
        x11 = (plaintext >> 32) & 0xff

        x12 = (plaintext >> 24) & 0xff
        x13 = (plaintext >> 16) & 0xff
        x14 = (plaintext >> 8) & 0xff
        x15 = (plaintext >> 0) & 0xff

        # AddRoundKey
        x0 ^= self.round_keys[0]
        x1 ^= self.round_keys[1]
        x2 ^= self.round_keys[2]
        x3 ^= self.round_keys[3]

        x4 ^= self.round_keys[4]
        x5 ^= self.round_keys[5]
        x6 ^= self.round_keys[6]
        x7 ^= self.round_keys[7]

        x8 ^= self.round_keys[8]
        x9 ^= self.round_keys[9]
        x10 ^= self.round_keys[10]
        x11 ^= self.round_keys[11]

        x12 ^= self.round_keys[12]
        x13 ^= self.round_keys[13]
        x14 ^= self.round_keys[14]
        x15 ^= self.round_keys[15]

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

        # Round 1
        y0 *= self.state[0][0]
        y1 *= self.state[0][1]
        y2 *= self.state[0][2]
        y3 *= self.state[0][3]

        y4 *= self.state[0][4]
        y5 *= self.state[0][5]
        y6 *= self.state[0][6]
        y7 *= self.state[0][7]

        y8 *= self.state[0][8]
        y9 *= self.state[0][9]
        y10 *= self.state[0][10]
        y11 *= self.state[0][11]

        y12 *= self.state[0][12]
        y13 *= self.state[0][13]
        y14 *= self.state[0][14]
        y15 *= self.state[0][15]

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
        x16 ^= self.round_keys[16]
        x17 ^= self.round_keys[17]
        x18 ^= self.round_keys[18]
        x19 ^= self.round_keys[19]

        x20 ^= self.round_keys[20]
        x21 ^= self.round_keys[21]
        x22 ^= self.round_keys[22]
        x23 ^= self.round_keys[23]

        x24 ^= self.round_keys[24]
        x25 ^= self.round_keys[25]
        x26 ^= self.round_keys[26]
        x27 ^= self.round_keys[27]

        x28 ^= self.round_keys[28]
        x29 ^= self.round_keys[29]
        x30 ^= self.round_keys[30]
        x31 ^= self.round_keys[31]

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

        # Round 2
        y16 *= self.state[1][0]
        y17 *= self.state[1][1]
        y18 *= self.state[1][2]
        y19 *= self.state[1][3]

        y20 *= self.state[1][4]
        y21 *= self.state[1][5]
        y22 *= self.state[1][6]
        y23 *= self.state[1][7]

        y24 *= self.state[1][8]
        y25 *= self.state[1][9]
        y26 *= self.state[1][10]
        y27 *= self.state[1][11]

        y28 *= self.state[1][12]
        y29 *= self.state[1][13]
        y30 *= self.state[1][14]
        y31 *= self.state[1][15]

        x32 = self.multiply(y16, 2) ^ self.multiply(y21, 3) ^ y26 ^ y31
        x37 = y20 ^ self.multiply(y25, 2) ^ self.multiply(y30, 3) ^ y19
        x42 = y24 ^ y29 ^ self.multiply(y18, 2) ^ self.multiply(y23, 3)
        x47 = self.multiply(y28, 3) ^ y17 ^ y22 ^ self.multiply(y27, 2)

        # AddRoundKey
        x32 ^= self.round_keys[32]
        x37 ^= self.round_keys[37]
        x42 ^= self.round_keys[42]
        x47 ^= self.round_keys[47]

        # SubBytes
        y32 = s_box[x32]
        y37 = s_box[x37]
        y42 = s_box[x42]
        y47 = s_box[x47]

        y32 *= self.state[2][0]
        y37 *= self.state[2][5]
        y42 *= self.state[2][10]
        y47 *= self.state[2][15]

        z = self.multiply(y32, 3) ^ y37 ^ y42 ^ self.multiply(y47, 2)
        return z

    def get_plaintext_part_round3_k4(self, plaintext):
        # Round 0
        x0 = (plaintext >> 120) & 0xff
        x1 = (plaintext >> 112) & 0xff
        x2 = (plaintext >> 104) & 0xff
        x3 = (plaintext >> 96) & 0xff

        x4 = (plaintext >> 88) & 0xff
        x5 = (plaintext >> 80) & 0xff
        x6 = (plaintext >> 72) & 0xff
        x7 = (plaintext >> 64) & 0xff

        x8 = (plaintext >> 56) & 0xff
        x9 = (plaintext >> 48) & 0xff
        x10 = (plaintext >> 40) & 0xff
        x11 = (plaintext >> 32) & 0xff

        x12 = (plaintext >> 24) & 0xff
        x13 = (plaintext >> 16) & 0xff
        x14 = (plaintext >> 8) & 0xff
        x15 = (plaintext >> 0) & 0xff

        # AddRoundKey
        x0 ^= self.round_keys[0]
        x1 ^= self.round_keys[1]
        x2 ^= self.round_keys[2]
        x3 ^= self.round_keys[3]

        x4 ^= self.round_keys[4]
        x5 ^= self.round_keys[5]
        x6 ^= self.round_keys[6]
        x7 ^= self.round_keys[7]

        x8 ^= self.round_keys[8]
        x9 ^= self.round_keys[9]
        x10 ^= self.round_keys[10]
        x11 ^= self.round_keys[11]

        x12 ^= self.round_keys[12]
        x13 ^= self.round_keys[13]
        x14 ^= self.round_keys[14]
        x15 ^= self.round_keys[15]

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

        # Round 1
        y0 *= self.state[0][0]
        y1 *= self.state[0][1]
        y2 *= self.state[0][2]
        y3 *= self.state[0][3]

        y4 *= self.state[0][4]
        y5 *= self.state[0][5]
        y6 *= self.state[0][6]
        y7 *= self.state[0][7]

        y8 *= self.state[0][8]
        y9 *= self.state[0][9]
        y10 *= self.state[0][10]
        y11 *= self.state[0][11]

        y12 *= self.state[0][12]
        y13 *= self.state[0][13]
        y14 *= self.state[0][14]
        y15 *= self.state[0][15]

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
        x16 ^= self.round_keys[16]
        x17 ^= self.round_keys[17]
        x18 ^= self.round_keys[18]
        x19 ^= self.round_keys[19]

        x20 ^= self.round_keys[20]
        x21 ^= self.round_keys[21]
        x22 ^= self.round_keys[22]
        x23 ^= self.round_keys[23]

        x24 ^= self.round_keys[24]
        x25 ^= self.round_keys[25]
        x26 ^= self.round_keys[26]
        x27 ^= self.round_keys[27]

        x28 ^= self.round_keys[28]
        x29 ^= self.round_keys[29]
        x30 ^= self.round_keys[30]
        x31 ^= self.round_keys[31]

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

        # Round 2
        y16 *= self.state[1][0]
        y17 *= self.state[1][1]
        y18 *= self.state[1][2]
        y19 *= self.state[1][3]

        y20 *= self.state[1][4]
        y21 *= self.state[1][5]
        y22 *= self.state[1][6]
        y23 *= self.state[1][7]

        y24 *= self.state[1][8]
        y25 *= self.state[1][9]
        y26 *= self.state[1][10]
        y27 *= self.state[1][11]

        y28 *= self.state[1][12]
        y29 *= self.state[1][13]
        y30 *= self.state[1][14]
        y31 *= self.state[1][15]

        x36 = self.multiply(y20, 2) ^ self.multiply(y25, 3) ^ y30 ^ y19
        x41 = y24 ^ self.multiply(y29, 2) ^ self.multiply(y18, 3) ^ y23
        x46 = y28 ^ y17 ^ self.multiply(y22, 2) ^ self.multiply(y27, 3)
        x35 = self.multiply(y16, 3) ^ y21 ^ y26 ^ self.multiply(y31, 2)

        # AddRoundKey
        x36 ^= self.round_keys[36]
        x41 ^= self.round_keys[41]
        x46 ^= self.round_keys[46]
        x35 ^= self.round_keys[35]

        # SubBytes
        y36 = s_box[x36]
        y41 = s_box[x41]
        y46 = s_box[x46]
        y35 = s_box[x35]

        y36 *= self.state[2][4]
        y41 *= self.state[2][9]
        y46 *= self.state[2][14]
        y35 *= self.state[2][3]

        z = self.multiply(y36, 2) ^ self.multiply(y41, 3) ^ y46 ^ y35
        return z

    def get_plaintext_part_round3_k5(self, plaintext):
        # Round 0
        x0 = (plaintext >> 120) & 0xff
        x1 = (plaintext >> 112) & 0xff
        x2 = (plaintext >> 104) & 0xff
        x3 = (plaintext >> 96) & 0xff

        x4 = (plaintext >> 88) & 0xff
        x5 = (plaintext >> 80) & 0xff
        x6 = (plaintext >> 72) & 0xff
        x7 = (plaintext >> 64) & 0xff

        x8 = (plaintext >> 56) & 0xff
        x9 = (plaintext >> 48) & 0xff
        x10 = (plaintext >> 40) & 0xff
        x11 = (plaintext >> 32) & 0xff

        x12 = (plaintext >> 24) & 0xff
        x13 = (plaintext >> 16) & 0xff
        x14 = (plaintext >> 8) & 0xff
        x15 = (plaintext >> 0) & 0xff

        # AddRoundKey
        x0 ^= self.round_keys[0]
        x1 ^= self.round_keys[1]
        x2 ^= self.round_keys[2]
        x3 ^= self.round_keys[3]

        x4 ^= self.round_keys[4]
        x5 ^= self.round_keys[5]
        x6 ^= self.round_keys[6]
        x7 ^= self.round_keys[7]

        x8 ^= self.round_keys[8]
        x9 ^= self.round_keys[9]
        x10 ^= self.round_keys[10]
        x11 ^= self.round_keys[11]

        x12 ^= self.round_keys[12]
        x13 ^= self.round_keys[13]
        x14 ^= self.round_keys[14]
        x15 ^= self.round_keys[15]

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

        # Round 1
        y0 *= self.state[0][0]
        y1 *= self.state[0][1]
        y2 *= self.state[0][2]
        y3 *= self.state[0][3]

        y4 *= self.state[0][4]
        y5 *= self.state[0][5]
        y6 *= self.state[0][6]
        y7 *= self.state[0][7]

        y8 *= self.state[0][8]
        y9 *= self.state[0][9]
        y10 *= self.state[0][10]
        y11 *= self.state[0][11]

        y12 *= self.state[0][12]
        y13 *= self.state[0][13]
        y14 *= self.state[0][14]
        y15 *= self.state[0][15]

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
        x16 ^= self.round_keys[16]
        x17 ^= self.round_keys[17]
        x18 ^= self.round_keys[18]
        x19 ^= self.round_keys[19]

        x20 ^= self.round_keys[20]
        x21 ^= self.round_keys[21]
        x22 ^= self.round_keys[22]
        x23 ^= self.round_keys[23]

        x24 ^= self.round_keys[24]
        x25 ^= self.round_keys[25]
        x26 ^= self.round_keys[26]
        x27 ^= self.round_keys[27]

        x28 ^= self.round_keys[28]
        x29 ^= self.round_keys[29]
        x30 ^= self.round_keys[30]
        x31 ^= self.round_keys[31]

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

        # Round 2
        y16 *= self.state[1][0]
        y17 *= self.state[1][1]
        y18 *= self.state[1][2]
        y19 *= self.state[1][3]

        y20 *= self.state[1][4]
        y21 *= self.state[1][5]
        y22 *= self.state[1][6]
        y23 *= self.state[1][7]

        y24 *= self.state[1][8]
        y25 *= self.state[1][9]
        y26 *= self.state[1][10]
        y27 *= self.state[1][11]

        y28 *= self.state[1][12]
        y29 *= self.state[1][13]
        y30 *= self.state[1][14]
        y31 *= self.state[1][15]

        x36 = self.multiply(y20, 2) ^ self.multiply(y25, 3) ^ y30 ^ y19
        x41 = y24 ^ self.multiply(y29, 2) ^ self.multiply(y18, 3) ^ y23
        x46 = y28 ^ y17 ^ self.multiply(y22, 2) ^ self.multiply(y27, 3)
        x35 = self.multiply(y16, 3) ^ y21 ^ y26 ^ self.multiply(y31, 2)

        # AddRoundKey
        x36 ^= self.round_keys[36]
        x41 ^= self.round_keys[41]
        x46 ^= self.round_keys[46]
        x35 ^= self.round_keys[35]

        # SubBytes
        y36 = s_box[x36]
        y41 = s_box[x41]
        y46 = s_box[x46]
        y35 = s_box[x35]

        y36 *= self.state[2][4]
        y41 *= self.state[2][9]
        y46 *= self.state[2][14]
        y35 *= self.state[2][3]

        z = y36 ^ self.multiply(y41, 2) ^ self.multiply(y46, 3) ^ y35
        return z

    def get_plaintext_part_round3_k6(self, plaintext):
        # Round 0
        x0 = (plaintext >> 120) & 0xff
        x1 = (plaintext >> 112) & 0xff
        x2 = (plaintext >> 104) & 0xff
        x3 = (plaintext >> 96) & 0xff

        x4 = (plaintext >> 88) & 0xff
        x5 = (plaintext >> 80) & 0xff
        x6 = (plaintext >> 72) & 0xff
        x7 = (plaintext >> 64) & 0xff

        x8 = (plaintext >> 56) & 0xff
        x9 = (plaintext >> 48) & 0xff
        x10 = (plaintext >> 40) & 0xff
        x11 = (plaintext >> 32) & 0xff

        x12 = (plaintext >> 24) & 0xff
        x13 = (plaintext >> 16) & 0xff
        x14 = (plaintext >> 8) & 0xff
        x15 = (plaintext >> 0) & 0xff

        # AddRoundKey
        x0 ^= self.round_keys[0]
        x1 ^= self.round_keys[1]
        x2 ^= self.round_keys[2]
        x3 ^= self.round_keys[3]

        x4 ^= self.round_keys[4]
        x5 ^= self.round_keys[5]
        x6 ^= self.round_keys[6]
        x7 ^= self.round_keys[7]

        x8 ^= self.round_keys[8]
        x9 ^= self.round_keys[9]
        x10 ^= self.round_keys[10]
        x11 ^= self.round_keys[11]

        x12 ^= self.round_keys[12]
        x13 ^= self.round_keys[13]
        x14 ^= self.round_keys[14]
        x15 ^= self.round_keys[15]

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

        # Round 1
        y0 *= self.state[0][0]
        y1 *= self.state[0][1]
        y2 *= self.state[0][2]
        y3 *= self.state[0][3]

        y4 *= self.state[0][4]
        y5 *= self.state[0][5]
        y6 *= self.state[0][6]
        y7 *= self.state[0][7]

        y8 *= self.state[0][8]
        y9 *= self.state[0][9]
        y10 *= self.state[0][10]
        y11 *= self.state[0][11]

        y12 *= self.state[0][12]
        y13 *= self.state[0][13]
        y14 *= self.state[0][14]
        y15 *= self.state[0][15]

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
        x16 ^= self.round_keys[16]
        x17 ^= self.round_keys[17]
        x18 ^= self.round_keys[18]
        x19 ^= self.round_keys[19]

        x20 ^= self.round_keys[20]
        x21 ^= self.round_keys[21]
        x22 ^= self.round_keys[22]
        x23 ^= self.round_keys[23]

        x24 ^= self.round_keys[24]
        x25 ^= self.round_keys[25]
        x26 ^= self.round_keys[26]
        x27 ^= self.round_keys[27]

        x28 ^= self.round_keys[28]
        x29 ^= self.round_keys[29]
        x30 ^= self.round_keys[30]
        x31 ^= self.round_keys[31]

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

        # Round 2
        y16 *= self.state[1][0]
        y17 *= self.state[1][1]
        y18 *= self.state[1][2]
        y19 *= self.state[1][3]

        y20 *= self.state[1][4]
        y21 *= self.state[1][5]
        y22 *= self.state[1][6]
        y23 *= self.state[1][7]

        y24 *= self.state[1][8]
        y25 *= self.state[1][9]
        y26 *= self.state[1][10]
        y27 *= self.state[1][11]

        y28 *= self.state[1][12]
        y29 *= self.state[1][13]
        y30 *= self.state[1][14]
        y31 *= self.state[1][15]

        x36 = self.multiply(y20, 2) ^ self.multiply(y25, 3) ^ y30 ^ y19
        x41 = y24 ^ self.multiply(y29, 2) ^ self.multiply(y18, 3) ^ y23
        x46 = y28 ^ y17 ^ self.multiply(y22, 2) ^ self.multiply(y27, 3)
        x35 = self.multiply(y16, 3) ^ y21 ^ y26 ^ self.multiply(y31, 2)

        # AddRoundKey
        x36 ^= self.round_keys[36]
        x41 ^= self.round_keys[41]
        x46 ^= self.round_keys[46]
        x35 ^= self.round_keys[35]

        # SubBytes
        y36 = s_box[x36]
        y41 = s_box[x41]
        y46 = s_box[x46]
        y35 = s_box[x35]

        y36 *= self.state[2][4]
        y41 *= self.state[2][9]
        y46 *= self.state[2][14]
        y35 *= self.state[2][3]

        z = y36 ^ y41 ^ self.multiply(y46, 2) ^ self.multiply(y35, 3)
        return z

    def get_plaintext_part_round3_k7(self, plaintext):
        # Round 0
        x0 = (plaintext >> 120) & 0xff
        x1 = (plaintext >> 112) & 0xff
        x2 = (plaintext >> 104) & 0xff
        x3 = (plaintext >> 96) & 0xff

        x4 = (plaintext >> 88) & 0xff
        x5 = (plaintext >> 80) & 0xff
        x6 = (plaintext >> 72) & 0xff
        x7 = (plaintext >> 64) & 0xff

        x8 = (plaintext >> 56) & 0xff
        x9 = (plaintext >> 48) & 0xff
        x10 = (plaintext >> 40) & 0xff
        x11 = (plaintext >> 32) & 0xff

        x12 = (plaintext >> 24) & 0xff
        x13 = (plaintext >> 16) & 0xff
        x14 = (plaintext >> 8) & 0xff
        x15 = (plaintext >> 0) & 0xff

        # AddRoundKey
        x0 ^= self.round_keys[0]
        x1 ^= self.round_keys[1]
        x2 ^= self.round_keys[2]
        x3 ^= self.round_keys[3]

        x4 ^= self.round_keys[4]
        x5 ^= self.round_keys[5]
        x6 ^= self.round_keys[6]
        x7 ^= self.round_keys[7]

        x8 ^= self.round_keys[8]
        x9 ^= self.round_keys[9]
        x10 ^= self.round_keys[10]
        x11 ^= self.round_keys[11]

        x12 ^= self.round_keys[12]
        x13 ^= self.round_keys[13]
        x14 ^= self.round_keys[14]
        x15 ^= self.round_keys[15]

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

        # Round 1
        y0 *= self.state[0][0]
        y1 *= self.state[0][1]
        y2 *= self.state[0][2]
        y3 *= self.state[0][3]

        y4 *= self.state[0][4]
        y5 *= self.state[0][5]
        y6 *= self.state[0][6]
        y7 *= self.state[0][7]

        y8 *= self.state[0][8]
        y9 *= self.state[0][9]
        y10 *= self.state[0][10]
        y11 *= self.state[0][11]

        y12 *= self.state[0][12]
        y13 *= self.state[0][13]
        y14 *= self.state[0][14]
        y15 *= self.state[0][15]

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
        x16 ^= self.round_keys[16]
        x17 ^= self.round_keys[17]
        x18 ^= self.round_keys[18]
        x19 ^= self.round_keys[19]

        x20 ^= self.round_keys[20]
        x21 ^= self.round_keys[21]
        x22 ^= self.round_keys[22]
        x23 ^= self.round_keys[23]

        x24 ^= self.round_keys[24]
        x25 ^= self.round_keys[25]
        x26 ^= self.round_keys[26]
        x27 ^= self.round_keys[27]

        x28 ^= self.round_keys[28]
        x29 ^= self.round_keys[29]
        x30 ^= self.round_keys[30]
        x31 ^= self.round_keys[31]

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

        # Round 2
        y16 *= self.state[1][0]
        y17 *= self.state[1][1]
        y18 *= self.state[1][2]
        y19 *= self.state[1][3]

        y20 *= self.state[1][4]
        y21 *= self.state[1][5]
        y22 *= self.state[1][6]
        y23 *= self.state[1][7]

        y24 *= self.state[1][8]
        y25 *= self.state[1][9]
        y26 *= self.state[1][10]
        y27 *= self.state[1][11]

        y28 *= self.state[1][12]
        y29 *= self.state[1][13]
        y30 *= self.state[1][14]
        y31 *= self.state[1][15]

        x36 = self.multiply(y20, 2) ^ self.multiply(y25, 3) ^ y30 ^ y19
        x41 = y24 ^ self.multiply(y29, 2) ^ self.multiply(y18, 3) ^ y23
        x46 = y28 ^ y17 ^ self.multiply(y22, 2) ^ self.multiply(y27, 3)
        x35 = self.multiply(y16, 3) ^ y21 ^ y26 ^ self.multiply(y31, 2)

        # AddRoundKey
        x36 ^= self.round_keys[36]
        x41 ^= self.round_keys[41]
        x46 ^= self.round_keys[46]
        x35 ^= self.round_keys[35]

        # SubBytes
        y36 = s_box[x36]
        y41 = s_box[x41]
        y46 = s_box[x46]
        y35 = s_box[x35]

        y36 *= self.state[2][4]
        y41 *= self.state[2][9]
        y46 *= self.state[2][14]
        y35 *= self.state[2][3]

        z = self.multiply(y36, 3) ^ y41 ^ y46 ^ self.multiply(y35, 2)
        return z

    def get_plaintext_part_round3_k8(self, plaintext):
        # Round 0
        x0 = (plaintext >> 120) & 0xff
        x1 = (plaintext >> 112) & 0xff
        x2 = (plaintext >> 104) & 0xff
        x3 = (plaintext >> 96) & 0xff

        x4 = (plaintext >> 88) & 0xff
        x5 = (plaintext >> 80) & 0xff
        x6 = (plaintext >> 72) & 0xff
        x7 = (plaintext >> 64) & 0xff

        x8 = (plaintext >> 56) & 0xff
        x9 = (plaintext >> 48) & 0xff
        x10 = (plaintext >> 40) & 0xff
        x11 = (plaintext >> 32) & 0xff

        x12 = (plaintext >> 24) & 0xff
        x13 = (plaintext >> 16) & 0xff
        x14 = (plaintext >> 8) & 0xff
        x15 = (plaintext >> 0) & 0xff

        # AddRoundKey
        x0 ^= self.round_keys[0]
        x1 ^= self.round_keys[1]
        x2 ^= self.round_keys[2]
        x3 ^= self.round_keys[3]

        x4 ^= self.round_keys[4]
        x5 ^= self.round_keys[5]
        x6 ^= self.round_keys[6]
        x7 ^= self.round_keys[7]

        x8 ^= self.round_keys[8]
        x9 ^= self.round_keys[9]
        x10 ^= self.round_keys[10]
        x11 ^= self.round_keys[11]

        x12 ^= self.round_keys[12]
        x13 ^= self.round_keys[13]
        x14 ^= self.round_keys[14]
        x15 ^= self.round_keys[15]

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

        # Round 1
        y0 *= self.state[0][0]
        y1 *= self.state[0][1]
        y2 *= self.state[0][2]
        y3 *= self.state[0][3]

        y4 *= self.state[0][4]
        y5 *= self.state[0][5]
        y6 *= self.state[0][6]
        y7 *= self.state[0][7]

        y8 *= self.state[0][8]
        y9 *= self.state[0][9]
        y10 *= self.state[0][10]
        y11 *= self.state[0][11]

        y12 *= self.state[0][12]
        y13 *= self.state[0][13]
        y14 *= self.state[0][14]
        y15 *= self.state[0][15]

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
        x16 ^= self.round_keys[16]
        x17 ^= self.round_keys[17]
        x18 ^= self.round_keys[18]
        x19 ^= self.round_keys[19]

        x20 ^= self.round_keys[20]
        x21 ^= self.round_keys[21]
        x22 ^= self.round_keys[22]
        x23 ^= self.round_keys[23]

        x24 ^= self.round_keys[24]
        x25 ^= self.round_keys[25]
        x26 ^= self.round_keys[26]
        x27 ^= self.round_keys[27]

        x28 ^= self.round_keys[28]
        x29 ^= self.round_keys[29]
        x30 ^= self.round_keys[30]
        x31 ^= self.round_keys[31]

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

        # Round 2
        y16 *= self.state[1][0]
        y17 *= self.state[1][1]
        y18 *= self.state[1][2]
        y19 *= self.state[1][3]

        y20 *= self.state[1][4]
        y21 *= self.state[1][5]
        y22 *= self.state[1][6]
        y23 *= self.state[1][7]

        y24 *= self.state[1][8]
        y25 *= self.state[1][9]
        y26 *= self.state[1][10]
        y27 *= self.state[1][11]

        y28 *= self.state[1][12]
        y29 *= self.state[1][13]
        y30 *= self.state[1][14]
        y31 *= self.state[1][15]

        x40 = self.multiply(y24, 2) ^ self.multiply(y29, 3) ^ y18 ^ y23
        x45 = y28 ^ self.multiply(y17, 2) ^ self.multiply(y22, 3) ^ y27
        x34 = y16 ^ y21 ^ self.multiply(y26, 2) ^ self.multiply(y31, 3)
        x39 = self.multiply(y20, 3) ^ y25 ^ y30 ^ self.multiply(y19, 2)

        # AddRoundKey
        x40 ^= self.round_keys[40]
        x45 ^= self.round_keys[45]
        x34 ^= self.round_keys[34]
        x39 ^= self.round_keys[39]

        # SubBytes
        y40 = s_box[x40]
        y45 = s_box[x45]
        y34 = s_box[x34]
        y39 = s_box[x39]

        y40 *= self.state[2][8]
        y45 *= self.state[2][13]
        y34 *= self.state[2][2]
        y39 *= self.state[2][7]

        z = self.multiply(y40, 2) ^ self.multiply(y45, 3) ^ y34 ^ y39
        return z

    def get_plaintext_part_round3_k9(self, plaintext):
        # Round 0
        x0 = (plaintext >> 120) & 0xff
        x1 = (plaintext >> 112) & 0xff
        x2 = (plaintext >> 104) & 0xff
        x3 = (plaintext >> 96) & 0xff

        x4 = (plaintext >> 88) & 0xff
        x5 = (plaintext >> 80) & 0xff
        x6 = (plaintext >> 72) & 0xff
        x7 = (plaintext >> 64) & 0xff

        x8 = (plaintext >> 56) & 0xff
        x9 = (plaintext >> 48) & 0xff
        x10 = (plaintext >> 40) & 0xff
        x11 = (plaintext >> 32) & 0xff

        x12 = (plaintext >> 24) & 0xff
        x13 = (plaintext >> 16) & 0xff
        x14 = (plaintext >> 8) & 0xff
        x15 = (plaintext >> 0) & 0xff

        # AddRoundKey
        x0 ^= self.round_keys[0]
        x1 ^= self.round_keys[1]
        x2 ^= self.round_keys[2]
        x3 ^= self.round_keys[3]

        x4 ^= self.round_keys[4]
        x5 ^= self.round_keys[5]
        x6 ^= self.round_keys[6]
        x7 ^= self.round_keys[7]

        x8 ^= self.round_keys[8]
        x9 ^= self.round_keys[9]
        x10 ^= self.round_keys[10]
        x11 ^= self.round_keys[11]

        x12 ^= self.round_keys[12]
        x13 ^= self.round_keys[13]
        x14 ^= self.round_keys[14]
        x15 ^= self.round_keys[15]

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

        # Round 1
        y0 *= self.state[0][0]
        y1 *= self.state[0][1]
        y2 *= self.state[0][2]
        y3 *= self.state[0][3]

        y4 *= self.state[0][4]
        y5 *= self.state[0][5]
        y6 *= self.state[0][6]
        y7 *= self.state[0][7]

        y8 *= self.state[0][8]
        y9 *= self.state[0][9]
        y10 *= self.state[0][10]
        y11 *= self.state[0][11]

        y12 *= self.state[0][12]
        y13 *= self.state[0][13]
        y14 *= self.state[0][14]
        y15 *= self.state[0][15]

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
        x16 ^= self.round_keys[16]
        x17 ^= self.round_keys[17]
        x18 ^= self.round_keys[18]
        x19 ^= self.round_keys[19]

        x20 ^= self.round_keys[20]
        x21 ^= self.round_keys[21]
        x22 ^= self.round_keys[22]
        x23 ^= self.round_keys[23]

        x24 ^= self.round_keys[24]
        x25 ^= self.round_keys[25]
        x26 ^= self.round_keys[26]
        x27 ^= self.round_keys[27]

        x28 ^= self.round_keys[28]
        x29 ^= self.round_keys[29]
        x30 ^= self.round_keys[30]
        x31 ^= self.round_keys[31]

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

        # Round 2
        y16 *= self.state[1][0]
        y17 *= self.state[1][1]
        y18 *= self.state[1][2]
        y19 *= self.state[1][3]

        y20 *= self.state[1][4]
        y21 *= self.state[1][5]
        y22 *= self.state[1][6]
        y23 *= self.state[1][7]

        y24 *= self.state[1][8]
        y25 *= self.state[1][9]
        y26 *= self.state[1][10]
        y27 *= self.state[1][11]

        y28 *= self.state[1][12]
        y29 *= self.state[1][13]
        y30 *= self.state[1][14]
        y31 *= self.state[1][15]

        x40 = self.multiply(y24, 2) ^ self.multiply(y29, 3) ^ y18 ^ y23
        x45 = y28 ^ self.multiply(y17, 2) ^ self.multiply(y22, 3) ^ y27
        x34 = y16 ^ y21 ^ self.multiply(y26, 2) ^ self.multiply(y31, 3)
        x39 = self.multiply(y20, 3) ^ y25 ^ y30 ^ self.multiply(y19, 2)

        # AddRoundKey
        x40 ^= self.round_keys[40]
        x45 ^= self.round_keys[45]
        x34 ^= self.round_keys[34]
        x39 ^= self.round_keys[39]

        # SubBytes
        y40 = s_box[x40]
        y45 = s_box[x45]
        y34 = s_box[x34]
        y39 = s_box[x39]

        y40 *= self.state[2][8]
        y45 *= self.state[2][13]
        y34 *= self.state[2][2]
        y39 *= self.state[2][7]

        z = y40 ^ self.multiply(y45, 2) ^ self.multiply(y34, 3) ^ y39
        return z

    def get_plaintext_part_round3_k10(self, plaintext):
        # Round 0
        x0 = (plaintext >> 120) & 0xff
        x1 = (plaintext >> 112) & 0xff
        x2 = (plaintext >> 104) & 0xff
        x3 = (plaintext >> 96) & 0xff

        x4 = (plaintext >> 88) & 0xff
        x5 = (plaintext >> 80) & 0xff
        x6 = (plaintext >> 72) & 0xff
        x7 = (plaintext >> 64) & 0xff

        x8 = (plaintext >> 56) & 0xff
        x9 = (plaintext >> 48) & 0xff
        x10 = (plaintext >> 40) & 0xff
        x11 = (plaintext >> 32) & 0xff

        x12 = (plaintext >> 24) & 0xff
        x13 = (plaintext >> 16) & 0xff
        x14 = (plaintext >> 8) & 0xff
        x15 = (plaintext >> 0) & 0xff

        # AddRoundKey
        x0 ^= self.round_keys[0]
        x1 ^= self.round_keys[1]
        x2 ^= self.round_keys[2]
        x3 ^= self.round_keys[3]

        x4 ^= self.round_keys[4]
        x5 ^= self.round_keys[5]
        x6 ^= self.round_keys[6]
        x7 ^= self.round_keys[7]

        x8 ^= self.round_keys[8]
        x9 ^= self.round_keys[9]
        x10 ^= self.round_keys[10]
        x11 ^= self.round_keys[11]

        x12 ^= self.round_keys[12]
        x13 ^= self.round_keys[13]
        x14 ^= self.round_keys[14]
        x15 ^= self.round_keys[15]

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

        # Round 1
        y0 *= self.state[0][0]
        y1 *= self.state[0][1]
        y2 *= self.state[0][2]
        y3 *= self.state[0][3]

        y4 *= self.state[0][4]
        y5 *= self.state[0][5]
        y6 *= self.state[0][6]
        y7 *= self.state[0][7]

        y8 *= self.state[0][8]
        y9 *= self.state[0][9]
        y10 *= self.state[0][10]
        y11 *= self.state[0][11]

        y12 *= self.state[0][12]
        y13 *= self.state[0][13]
        y14 *= self.state[0][14]
        y15 *= self.state[0][15]

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
        x16 ^= self.round_keys[16]
        x17 ^= self.round_keys[17]
        x18 ^= self.round_keys[18]
        x19 ^= self.round_keys[19]

        x20 ^= self.round_keys[20]
        x21 ^= self.round_keys[21]
        x22 ^= self.round_keys[22]
        x23 ^= self.round_keys[23]

        x24 ^= self.round_keys[24]
        x25 ^= self.round_keys[25]
        x26 ^= self.round_keys[26]
        x27 ^= self.round_keys[27]

        x28 ^= self.round_keys[28]
        x29 ^= self.round_keys[29]
        x30 ^= self.round_keys[30]
        x31 ^= self.round_keys[31]

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

        # Round 2
        y16 *= self.state[1][0]
        y17 *= self.state[1][1]
        y18 *= self.state[1][2]
        y19 *= self.state[1][3]

        y20 *= self.state[1][4]
        y21 *= self.state[1][5]
        y22 *= self.state[1][6]
        y23 *= self.state[1][7]

        y24 *= self.state[1][8]
        y25 *= self.state[1][9]
        y26 *= self.state[1][10]
        y27 *= self.state[1][11]

        y28 *= self.state[1][12]
        y29 *= self.state[1][13]
        y30 *= self.state[1][14]
        y31 *= self.state[1][15]

        x40 = self.multiply(y24, 2) ^ self.multiply(y29, 3) ^ y18 ^ y23
        x45 = y28 ^ self.multiply(y17, 2) ^ self.multiply(y22, 3) ^ y27
        x34 = y16 ^ y21 ^ self.multiply(y26, 2) ^ self.multiply(y31, 3)
        x39 = self.multiply(y20, 3) ^ y25 ^ y30 ^ self.multiply(y19, 2)

        # AddRoundKey
        x40 ^= self.round_keys[40]
        x45 ^= self.round_keys[45]
        x34 ^= self.round_keys[34]
        x39 ^= self.round_keys[39]

        # SubBytes
        y40 = s_box[x40]
        y45 = s_box[x45]
        y34 = s_box[x34]
        y39 = s_box[x39]

        y40 *= self.state[2][8]
        y45 *= self.state[2][13]
        y34 *= self.state[2][2]
        y39 *= self.state[2][7]

        z = y40 ^ y45 ^ self.multiply(y34, 2) ^ self.multiply(y39, 3)
        return z

    def get_plaintext_part_round3_k11(self, plaintext):
        # Round 0
        x0 = (plaintext >> 120) & 0xff
        x1 = (plaintext >> 112) & 0xff
        x2 = (plaintext >> 104) & 0xff
        x3 = (plaintext >> 96) & 0xff

        x4 = (plaintext >> 88) & 0xff
        x5 = (plaintext >> 80) & 0xff
        x6 = (plaintext >> 72) & 0xff
        x7 = (plaintext >> 64) & 0xff

        x8 = (plaintext >> 56) & 0xff
        x9 = (plaintext >> 48) & 0xff
        x10 = (plaintext >> 40) & 0xff
        x11 = (plaintext >> 32) & 0xff

        x12 = (plaintext >> 24) & 0xff
        x13 = (plaintext >> 16) & 0xff
        x14 = (plaintext >> 8) & 0xff
        x15 = (plaintext >> 0) & 0xff

        # AddRoundKey
        x0 ^= self.round_keys[0]
        x1 ^= self.round_keys[1]
        x2 ^= self.round_keys[2]
        x3 ^= self.round_keys[3]

        x4 ^= self.round_keys[4]
        x5 ^= self.round_keys[5]
        x6 ^= self.round_keys[6]
        x7 ^= self.round_keys[7]

        x8 ^= self.round_keys[8]
        x9 ^= self.round_keys[9]
        x10 ^= self.round_keys[10]
        x11 ^= self.round_keys[11]

        x12 ^= self.round_keys[12]
        x13 ^= self.round_keys[13]
        x14 ^= self.round_keys[14]
        x15 ^= self.round_keys[15]

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

        # Round 1
        y0 *= self.state[0][0]
        y1 *= self.state[0][1]
        y2 *= self.state[0][2]
        y3 *= self.state[0][3]

        y4 *= self.state[0][4]
        y5 *= self.state[0][5]
        y6 *= self.state[0][6]
        y7 *= self.state[0][7]

        y8 *= self.state[0][8]
        y9 *= self.state[0][9]
        y10 *= self.state[0][10]
        y11 *= self.state[0][11]

        y12 *= self.state[0][12]
        y13 *= self.state[0][13]
        y14 *= self.state[0][14]
        y15 *= self.state[0][15]

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
        x16 ^= self.round_keys[16]
        x17 ^= self.round_keys[17]
        x18 ^= self.round_keys[18]
        x19 ^= self.round_keys[19]

        x20 ^= self.round_keys[20]
        x21 ^= self.round_keys[21]
        x22 ^= self.round_keys[22]
        x23 ^= self.round_keys[23]

        x24 ^= self.round_keys[24]
        x25 ^= self.round_keys[25]
        x26 ^= self.round_keys[26]
        x27 ^= self.round_keys[27]

        x28 ^= self.round_keys[28]
        x29 ^= self.round_keys[29]
        x30 ^= self.round_keys[30]
        x31 ^= self.round_keys[31]

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

        # Round 2
        y16 *= self.state[1][0]
        y17 *= self.state[1][1]
        y18 *= self.state[1][2]
        y19 *= self.state[1][3]

        y20 *= self.state[1][4]
        y21 *= self.state[1][5]
        y22 *= self.state[1][6]
        y23 *= self.state[1][7]

        y24 *= self.state[1][8]
        y25 *= self.state[1][9]
        y26 *= self.state[1][10]
        y27 *= self.state[1][11]

        y28 *= self.state[1][12]
        y29 *= self.state[1][13]
        y30 *= self.state[1][14]
        y31 *= self.state[1][15]

        x40 = self.multiply(y24, 2) ^ self.multiply(y29, 3) ^ y18 ^ y23
        x45 = y28 ^ self.multiply(y17, 2) ^ self.multiply(y22, 3) ^ y27
        x34 = y16 ^ y21 ^ self.multiply(y26, 2) ^ self.multiply(y31, 3)
        x39 = self.multiply(y20, 3) ^ y25 ^ y30 ^ self.multiply(y19, 2)

        # AddRoundKey
        x40 ^= self.round_keys[40]
        x45 ^= self.round_keys[45]
        x34 ^= self.round_keys[34]
        x39 ^= self.round_keys[39]

        # SubBytes
        y40 = s_box[x40]
        y45 = s_box[x45]
        y34 = s_box[x34]
        y39 = s_box[x39]

        y40 *= self.state[2][8]
        y45 *= self.state[2][13]
        y34 *= self.state[2][2]
        y39 *= self.state[2][7]

        z = self.multiply(y40, 3) ^ y45 ^ y34 ^ self.multiply(y39, 2)
        return z

    def get_plaintext_part_round3_k12(self, plaintext):
        # Round 0
        x0 = (plaintext >> 120) & 0xff
        x1 = (plaintext >> 112) & 0xff
        x2 = (plaintext >> 104) & 0xff
        x3 = (plaintext >> 96) & 0xff

        x4 = (plaintext >> 88) & 0xff
        x5 = (plaintext >> 80) & 0xff
        x6 = (plaintext >> 72) & 0xff
        x7 = (plaintext >> 64) & 0xff

        x8 = (plaintext >> 56) & 0xff
        x9 = (plaintext >> 48) & 0xff
        x10 = (plaintext >> 40) & 0xff
        x11 = (plaintext >> 32) & 0xff

        x12 = (plaintext >> 24) & 0xff
        x13 = (plaintext >> 16) & 0xff
        x14 = (plaintext >> 8) & 0xff
        x15 = (plaintext >> 0) & 0xff

        # AddRoundKey
        x0 ^= self.round_keys[0]
        x1 ^= self.round_keys[1]
        x2 ^= self.round_keys[2]
        x3 ^= self.round_keys[3]

        x4 ^= self.round_keys[4]
        x5 ^= self.round_keys[5]
        x6 ^= self.round_keys[6]
        x7 ^= self.round_keys[7]

        x8 ^= self.round_keys[8]
        x9 ^= self.round_keys[9]
        x10 ^= self.round_keys[10]
        x11 ^= self.round_keys[11]

        x12 ^= self.round_keys[12]
        x13 ^= self.round_keys[13]
        x14 ^= self.round_keys[14]
        x15 ^= self.round_keys[15]

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

        # Round 1
        y0 *= self.state[0][0]
        y1 *= self.state[0][1]
        y2 *= self.state[0][2]
        y3 *= self.state[0][3]

        y4 *= self.state[0][4]
        y5 *= self.state[0][5]
        y6 *= self.state[0][6]
        y7 *= self.state[0][7]

        y8 *= self.state[0][8]
        y9 *= self.state[0][9]
        y10 *= self.state[0][10]
        y11 *= self.state[0][11]

        y12 *= self.state[0][12]
        y13 *= self.state[0][13]
        y14 *= self.state[0][14]
        y15 *= self.state[0][15]

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
        x16 ^= self.round_keys[16]
        x17 ^= self.round_keys[17]
        x18 ^= self.round_keys[18]
        x19 ^= self.round_keys[19]

        x20 ^= self.round_keys[20]
        x21 ^= self.round_keys[21]
        x22 ^= self.round_keys[22]
        x23 ^= self.round_keys[23]

        x24 ^= self.round_keys[24]
        x25 ^= self.round_keys[25]
        x26 ^= self.round_keys[26]
        x27 ^= self.round_keys[27]

        x28 ^= self.round_keys[28]
        x29 ^= self.round_keys[29]
        x30 ^= self.round_keys[30]
        x31 ^= self.round_keys[31]

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

        # Round 2
        y16 *= self.state[1][0]
        y17 *= self.state[1][1]
        y18 *= self.state[1][2]
        y19 *= self.state[1][3]

        y20 *= self.state[1][4]
        y21 *= self.state[1][5]
        y22 *= self.state[1][6]
        y23 *= self.state[1][7]

        y24 *= self.state[1][8]
        y25 *= self.state[1][9]
        y26 *= self.state[1][10]
        y27 *= self.state[1][11]

        y28 *= self.state[1][12]
        y29 *= self.state[1][13]
        y30 *= self.state[1][14]
        y31 *= self.state[1][15]

        x44 = self.multiply(y28, 2) ^ self.multiply(y17, 3) ^ y22 ^ y27
        x33 = y16 ^ self.multiply(y21, 2) ^ self.multiply(y26, 3) ^ y31
        x38 = y20 ^ y25 ^ self.multiply(y30, 2) ^ self.multiply(y19, 3)
        x43 = self.multiply(y24, 3) ^ y29 ^ y18 ^ self.multiply(y23, 2)

        # AddRoundKey
        x44 ^= self.round_keys[44]
        x33 ^= self.round_keys[33]
        x38 ^= self.round_keys[38]
        x43 ^= self.round_keys[43]

        # SubBytes
        y44 = s_box[x44]
        y33 = s_box[x33]
        y38 = s_box[x38]
        y43 = s_box[x43]

        y44 *= self.state[2][12]
        y33 *= self.state[2][1]
        y38 *= self.state[2][6]
        y43 *= self.state[2][11]

        z = self.multiply(y44, 2) ^ self.multiply(y33, 3) ^ y38 ^ y43
        return z

    def get_plaintext_part_round3_k13(self, plaintext):
        # Round 0
        x0 = (plaintext >> 120) & 0xff
        x1 = (plaintext >> 112) & 0xff
        x2 = (plaintext >> 104) & 0xff
        x3 = (plaintext >> 96) & 0xff

        x4 = (plaintext >> 88) & 0xff
        x5 = (plaintext >> 80) & 0xff
        x6 = (plaintext >> 72) & 0xff
        x7 = (plaintext >> 64) & 0xff

        x8 = (plaintext >> 56) & 0xff
        x9 = (plaintext >> 48) & 0xff
        x10 = (plaintext >> 40) & 0xff
        x11 = (plaintext >> 32) & 0xff

        x12 = (plaintext >> 24) & 0xff
        x13 = (plaintext >> 16) & 0xff
        x14 = (plaintext >> 8) & 0xff
        x15 = (plaintext >> 0) & 0xff

        # AddRoundKey
        x0 ^= self.round_keys[0]
        x1 ^= self.round_keys[1]
        x2 ^= self.round_keys[2]
        x3 ^= self.round_keys[3]

        x4 ^= self.round_keys[4]
        x5 ^= self.round_keys[5]
        x6 ^= self.round_keys[6]
        x7 ^= self.round_keys[7]

        x8 ^= self.round_keys[8]
        x9 ^= self.round_keys[9]
        x10 ^= self.round_keys[10]
        x11 ^= self.round_keys[11]

        x12 ^= self.round_keys[12]
        x13 ^= self.round_keys[13]
        x14 ^= self.round_keys[14]
        x15 ^= self.round_keys[15]

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

        # Round 1
        y0 *= self.state[0][0]
        y1 *= self.state[0][1]
        y2 *= self.state[0][2]
        y3 *= self.state[0][3]

        y4 *= self.state[0][4]
        y5 *= self.state[0][5]
        y6 *= self.state[0][6]
        y7 *= self.state[0][7]

        y8 *= self.state[0][8]
        y9 *= self.state[0][9]
        y10 *= self.state[0][10]
        y11 *= self.state[0][11]

        y12 *= self.state[0][12]
        y13 *= self.state[0][13]
        y14 *= self.state[0][14]
        y15 *= self.state[0][15]

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
        x16 ^= self.round_keys[16]
        x17 ^= self.round_keys[17]
        x18 ^= self.round_keys[18]
        x19 ^= self.round_keys[19]

        x20 ^= self.round_keys[20]
        x21 ^= self.round_keys[21]
        x22 ^= self.round_keys[22]
        x23 ^= self.round_keys[23]

        x24 ^= self.round_keys[24]
        x25 ^= self.round_keys[25]
        x26 ^= self.round_keys[26]
        x27 ^= self.round_keys[27]

        x28 ^= self.round_keys[28]
        x29 ^= self.round_keys[29]
        x30 ^= self.round_keys[30]
        x31 ^= self.round_keys[31]

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

        # Round 2
        y16 *= self.state[1][0]
        y17 *= self.state[1][1]
        y18 *= self.state[1][2]
        y19 *= self.state[1][3]

        y20 *= self.state[1][4]
        y21 *= self.state[1][5]
        y22 *= self.state[1][6]
        y23 *= self.state[1][7]

        y24 *= self.state[1][8]
        y25 *= self.state[1][9]
        y26 *= self.state[1][10]
        y27 *= self.state[1][11]

        y28 *= self.state[1][12]
        y29 *= self.state[1][13]
        y30 *= self.state[1][14]
        y31 *= self.state[1][15]

        x44 = self.multiply(y28, 2) ^ self.multiply(y17, 3) ^ y22 ^ y27
        x33 = y16 ^ self.multiply(y21, 2) ^ self.multiply(y26, 3) ^ y31
        x38 = y20 ^ y25 ^ self.multiply(y30, 2) ^ self.multiply(y19, 3)
        x43 = self.multiply(y24, 3) ^ y29 ^ y18 ^ self.multiply(y23, 2)

        # AddRoundKey
        x44 ^= self.round_keys[44]
        x33 ^= self.round_keys[33]
        x38 ^= self.round_keys[38]
        x43 ^= self.round_keys[43]

        # SubBytes
        y44 = s_box[x44]
        y33 = s_box[x33]
        y38 = s_box[x38]
        y43 = s_box[x43]

        y44 *= self.state[2][12]
        y33 *= self.state[2][1]
        y38 *= self.state[2][6]
        y43 *= self.state[2][11]

        z = y44 ^ self.multiply(y33, 2) ^ self.multiply(y38, 3) ^ y43
        return z

    def get_plaintext_part_round3_k14(self, plaintext):
        # Round 0
        x0 = (plaintext >> 120) & 0xff
        x1 = (plaintext >> 112) & 0xff
        x2 = (plaintext >> 104) & 0xff
        x3 = (plaintext >> 96) & 0xff

        x4 = (plaintext >> 88) & 0xff
        x5 = (plaintext >> 80) & 0xff
        x6 = (plaintext >> 72) & 0xff
        x7 = (plaintext >> 64) & 0xff

        x8 = (plaintext >> 56) & 0xff
        x9 = (plaintext >> 48) & 0xff
        x10 = (plaintext >> 40) & 0xff
        x11 = (plaintext >> 32) & 0xff

        x12 = (plaintext >> 24) & 0xff
        x13 = (plaintext >> 16) & 0xff
        x14 = (plaintext >> 8) & 0xff
        x15 = (plaintext >> 0) & 0xff

        # AddRoundKey
        x0 ^= self.round_keys[0]
        x1 ^= self.round_keys[1]
        x2 ^= self.round_keys[2]
        x3 ^= self.round_keys[3]

        x4 ^= self.round_keys[4]
        x5 ^= self.round_keys[5]
        x6 ^= self.round_keys[6]
        x7 ^= self.round_keys[7]

        x8 ^= self.round_keys[8]
        x9 ^= self.round_keys[9]
        x10 ^= self.round_keys[10]
        x11 ^= self.round_keys[11]

        x12 ^= self.round_keys[12]
        x13 ^= self.round_keys[13]
        x14 ^= self.round_keys[14]
        x15 ^= self.round_keys[15]

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

        # Round 1
        y0 *= self.state[0][0]
        y1 *= self.state[0][1]
        y2 *= self.state[0][2]
        y3 *= self.state[0][3]

        y4 *= self.state[0][4]
        y5 *= self.state[0][5]
        y6 *= self.state[0][6]
        y7 *= self.state[0][7]

        y8 *= self.state[0][8]
        y9 *= self.state[0][9]
        y10 *= self.state[0][10]
        y11 *= self.state[0][11]

        y12 *= self.state[0][12]
        y13 *= self.state[0][13]
        y14 *= self.state[0][14]
        y15 *= self.state[0][15]

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
        x16 ^= self.round_keys[16]
        x17 ^= self.round_keys[17]
        x18 ^= self.round_keys[18]
        x19 ^= self.round_keys[19]

        x20 ^= self.round_keys[20]
        x21 ^= self.round_keys[21]
        x22 ^= self.round_keys[22]
        x23 ^= self.round_keys[23]

        x24 ^= self.round_keys[24]
        x25 ^= self.round_keys[25]
        x26 ^= self.round_keys[26]
        x27 ^= self.round_keys[27]

        x28 ^= self.round_keys[28]
        x29 ^= self.round_keys[29]
        x30 ^= self.round_keys[30]
        x31 ^= self.round_keys[31]

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

        # Round 2
        y16 *= self.state[1][0]
        y17 *= self.state[1][1]
        y18 *= self.state[1][2]
        y19 *= self.state[1][3]

        y20 *= self.state[1][4]
        y21 *= self.state[1][5]
        y22 *= self.state[1][6]
        y23 *= self.state[1][7]

        y24 *= self.state[1][8]
        y25 *= self.state[1][9]
        y26 *= self.state[1][10]
        y27 *= self.state[1][11]

        y28 *= self.state[1][12]
        y29 *= self.state[1][13]
        y30 *= self.state[1][14]
        y31 *= self.state[1][15]

        x44 = self.multiply(y28, 2) ^ self.multiply(y17, 3) ^ y22 ^ y27
        x33 = y16 ^ self.multiply(y21, 2) ^ self.multiply(y26, 3) ^ y31
        x38 = y20 ^ y25 ^ self.multiply(y30, 2) ^ self.multiply(y19, 3)
        x43 = self.multiply(y24, 3) ^ y29 ^ y18 ^ self.multiply(y23, 2)

        # AddRoundKey
        x44 ^= self.round_keys[44]
        x33 ^= self.round_keys[33]
        x38 ^= self.round_keys[38]
        x43 ^= self.round_keys[43]

        # SubBytes
        y44 = s_box[x44]
        y33 = s_box[x33]
        y38 = s_box[x38]
        y43 = s_box[x43]

        y44 *= self.state[2][12]
        y33 *= self.state[2][1]
        y38 *= self.state[2][6]
        y43 *= self.state[2][11]

        z = y44 ^ y33 ^ self.multiply(y38, 2) ^ self.multiply(y43, 3)
        return z

    def get_plaintext_part_round3_k15(self, plaintext):
        # Round 0
        x0 = (plaintext >> 120) & 0xff
        x1 = (plaintext >> 112) & 0xff
        x2 = (plaintext >> 104) & 0xff
        x3 = (plaintext >> 96) & 0xff

        x4 = (plaintext >> 88) & 0xff
        x5 = (plaintext >> 80) & 0xff
        x6 = (plaintext >> 72) & 0xff
        x7 = (plaintext >> 64) & 0xff

        x8 = (plaintext >> 56) & 0xff
        x9 = (plaintext >> 48) & 0xff
        x10 = (plaintext >> 40) & 0xff
        x11 = (plaintext >> 32) & 0xff

        x12 = (plaintext >> 24) & 0xff
        x13 = (plaintext >> 16) & 0xff
        x14 = (plaintext >> 8) & 0xff
        x15 = (plaintext >> 0) & 0xff

        # AddRoundKey
        x0 ^= self.round_keys[0]
        x1 ^= self.round_keys[1]
        x2 ^= self.round_keys[2]
        x3 ^= self.round_keys[3]

        x4 ^= self.round_keys[4]
        x5 ^= self.round_keys[5]
        x6 ^= self.round_keys[6]
        x7 ^= self.round_keys[7]

        x8 ^= self.round_keys[8]
        x9 ^= self.round_keys[9]
        x10 ^= self.round_keys[10]
        x11 ^= self.round_keys[11]

        x12 ^= self.round_keys[12]
        x13 ^= self.round_keys[13]
        x14 ^= self.round_keys[14]
        x15 ^= self.round_keys[15]

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

        # Round 1
        y0 *= self.state[0][0]
        y1 *= self.state[0][1]
        y2 *= self.state[0][2]
        y3 *= self.state[0][3]

        y4 *= self.state[0][4]
        y5 *= self.state[0][5]
        y6 *= self.state[0][6]
        y7 *= self.state[0][7]

        y8 *= self.state[0][8]
        y9 *= self.state[0][9]
        y10 *= self.state[0][10]
        y11 *= self.state[0][11]

        y12 *= self.state[0][12]
        y13 *= self.state[0][13]
        y14 *= self.state[0][14]
        y15 *= self.state[0][15]

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
        x16 ^= self.round_keys[16]
        x17 ^= self.round_keys[17]
        x18 ^= self.round_keys[18]
        x19 ^= self.round_keys[19]

        x20 ^= self.round_keys[20]
        x21 ^= self.round_keys[21]
        x22 ^= self.round_keys[22]
        x23 ^= self.round_keys[23]

        x24 ^= self.round_keys[24]
        x25 ^= self.round_keys[25]
        x26 ^= self.round_keys[26]
        x27 ^= self.round_keys[27]

        x28 ^= self.round_keys[28]
        x29 ^= self.round_keys[29]
        x30 ^= self.round_keys[30]
        x31 ^= self.round_keys[31]

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

        # Round 2
        y16 *= self.state[1][0]
        y17 *= self.state[1][1]
        y18 *= self.state[1][2]
        y19 *= self.state[1][3]

        y20 *= self.state[1][4]
        y21 *= self.state[1][5]
        y22 *= self.state[1][6]
        y23 *= self.state[1][7]

        y24 *= self.state[1][8]
        y25 *= self.state[1][9]
        y26 *= self.state[1][10]
        y27 *= self.state[1][11]

        y28 *= self.state[1][12]
        y29 *= self.state[1][13]
        y30 *= self.state[1][14]
        y31 *= self.state[1][15]

        x44 = self.multiply(y28, 2) ^ self.multiply(y17, 3) ^ y22 ^ y27
        x33 = y16 ^ self.multiply(y21, 2) ^ self.multiply(y26, 3) ^ y31
        x38 = y20 ^ y25 ^ self.multiply(y30, 2) ^ self.multiply(y19, 3)
        x43 = self.multiply(y24, 3) ^ y29 ^ y18 ^ self.multiply(y23, 2)

        # AddRoundKey
        x44 ^= self.round_keys[44]
        x33 ^= self.round_keys[33]
        x38 ^= self.round_keys[38]
        x43 ^= self.round_keys[43]

        # SubBytes
        y44 = s_box[x44]
        y33 = s_box[x33]
        y38 = s_box[x38]
        y43 = s_box[x43]

        y44 *= self.state[2][12]
        y33 *= self.state[2][1]
        y38 *= self.state[2][6]
        y43 *= self.state[2][11]

        z = self.multiply(y44, 3) ^ y33 ^ y38 ^ self.multiply(y43, 2)
        return z
