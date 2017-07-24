from aes_cipher.constants import r_con
from aes_cipher.constants import s_box


class KeySchedule:
    def __init__(self):
        self.key = None
        self.round_keys = [[0 for i in range(16)] for i in range(11)]

    def run(self, key):
        self.key = key

        for i in range(16):
            self.round_keys[0][i] = (key >> 8 * (15 - i)) & 0xff

        for i in range(1, 11, 1):
            self.round_keys[i][0] = self.round_keys[i - 1][0] ^ r_con[i - 1] ^ s_box[self.round_keys[i - 1][13]]
            self.round_keys[i][1] = self.round_keys[i - 1][1] ^ s_box[self.round_keys[i - 1][14]]
            self.round_keys[i][2] = self.round_keys[i - 1][2] ^ s_box[self.round_keys[i - 1][15]]
            self.round_keys[i][3] = self.round_keys[i - 1][3] ^ s_box[self.round_keys[i - 1][12]]

            self.round_keys[i][4] = self.round_keys[i - 1][4] ^ self.round_keys[i][0]
            self.round_keys[i][5] = self.round_keys[i - 1][5] ^ self.round_keys[i][1]
            self.round_keys[i][6] = self.round_keys[i - 1][6] ^ self.round_keys[i][2]
            self.round_keys[i][7] = self.round_keys[i - 1][7] ^ self.round_keys[i][3]

            self.round_keys[i][8] = self.round_keys[i - 1][8] ^ self.round_keys[i][4]
            self.round_keys[i][9] = self.round_keys[i - 1][9] ^ self.round_keys[i][5]
            self.round_keys[i][10] = self.round_keys[i - 1][10] ^ self.round_keys[i][6]
            self.round_keys[i][11] = self.round_keys[i - 1][11] ^ self.round_keys[i][7]

            self.round_keys[i][12] = self.round_keys[i - 1][12] ^ self.round_keys[i][8]
            self.round_keys[i][13] = self.round_keys[i - 1][13] ^ self.round_keys[i][9]
            self.round_keys[i][14] = self.round_keys[i - 1][14] ^ self.round_keys[i][10]
            self.round_keys[i][15] = self.round_keys[i - 1][15] ^ self.round_keys[i][11]

        return self.round_keys
