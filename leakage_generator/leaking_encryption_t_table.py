from aes_cipher.encryption_t_table import EncryptionTTable
from aes_cipher.constants import t0, t1, t2, t3
from leakage_model.hw_t_table import HwTTable


import numpy


class LeakingEncryptionTTable(EncryptionTTable):
    def __init__(self, round_keys):
        EncryptionTTable.__init__(self, round_keys)
        self.number_of_samples = 16 * 10

        self.leakage = None
        self.leakage_index = 0

        self.power_model = HwTTable()

    def t_table_lookup(self):
        c0 = t0[self.state[0]] ^ t1[self.state[5]] ^ t2[self.state[10]] ^ t3[self.state[15]]
        c1 = t0[self.state[4]] ^ t1[self.state[9]] ^ t2[self.state[14]] ^ t3[self.state[3]]
        c2 = t0[self.state[8]] ^ t1[self.state[13]] ^ t2[self.state[2]] ^ t3[self.state[7]]
        c3 = t0[self.state[12]] ^ t1[self.state[1]] ^ t2[self.state[6]] ^ t3[self.state[11]]

        for i in range(16):
            if 0 == i % 4:
                value = t0[self.state[i]]
            elif 1 == i % 4:
                value = t1[self.state[i]]
            elif 2 == i % 4:
                value = t2[self.state[i]]
            elif 3 == i % 4:
                value = t3[self.state[i]]

            self.leakage[self.leakage_index] = self.power_model.leak(value)
            self.leakage_index += 1

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

    def encrypt(self, plaintext):
        self.leakage = numpy.zeros(self.number_of_samples)
        self.leakage_index = 0

        self.set_state(plaintext)

        self.add_round_key()

        for round_number in range(1, 10, 1):
            self.encrypt_round(round_number)
        self.encrypt_last_round(10)

        return self.leakage
