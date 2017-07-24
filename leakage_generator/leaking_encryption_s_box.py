from aes_cipher.encryption_s_box import EncryptionSBox
from aes_cipher.constants import s_box
from leakage_model.hw_s_box import HwSBox


import numpy


class LeakingEncryptionSBox(EncryptionSBox):
    def __init__(self, round_keys):
        EncryptionSBox.__init__(self, round_keys)
        self.number_of_samples = 16 * 10

        self.leakage = None
        self.leakage_index = 0

        self.power_model = HwSBox()

    def sub_bytes(self):
        for i in range(16):
            self.state[i] = s_box[self.state[i]]

            self.leakage[self.leakage_index] = self.power_model.leak(self.state[i])
            self.leakage_index += 1

    def encrypt(self, plaintext):
        self.leakage = numpy.zeros(self.number_of_samples)
        self.leakage_index = 0

        self.set_state(plaintext)

        self.add_round_key()

        for round_number in range(1, 10, 1):
            self.encrypt_round(round_number)
        self.encrypt_last_round(10)

        return self.leakage
