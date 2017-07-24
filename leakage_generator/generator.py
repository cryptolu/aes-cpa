from aes_cipher.key_schedule import KeySchedule
from leakage_generator.leaking_encryption_s_box import LeakingEncryptionSBox
from leakage_generator.leaking_encryption_t_table import LeakingEncryptionTTable
from settings.active_settings import ActiveSettings


import copy
import numpy
import pickle
import random


class Generator:
    def __init__(self, state, number_of_traces=1000, t_tables_implementation=False):
        self.number_of_samples = 16 * 10

        active_settings = ActiveSettings()
        self.key = active_settings.key
        self.random_state = active_settings.random_state

        self.traces_file = './data/traces.npy'
        self.plaintexts_file = './data/plaintexts.bin'
        self.number_of_traces = number_of_traces

        self.state = copy.deepcopy(state[0])

        for i in range(16):
            if 0 != self.state[i]:
                self.state[i] = 0xff

        self.t_tables_implementation = t_tables_implementation

    def init_leaking_aes(self):
        key_schedule = KeySchedule()
        key_schedule.run(self.key)

        if self.t_tables_implementation:
            return LeakingEncryptionTTable(key_schedule.round_keys)
        return LeakingEncryptionSBox(key_schedule.round_keys)

    def get_plaintext(self):
        plaintext = 0

        for i in range(16):
            plaintext <<= 8

            # 1. Fill with zeros
            # plaintext += random.getrandbits(8) & self.state[i]

            # 2. Fill with random values
            # '''
            if self.state[i]:
                plaintext += random.getrandbits(8)
            else:
                plaintext += self.random_state[i]
            # '''

        return plaintext

    def generate(self):
        leaking_encryption = self.init_leaking_aes()

        traces = numpy.zeros((self.number_of_traces, self.number_of_samples))
        plaintexts = [0] * self.number_of_traces

        for i in range(self.number_of_traces):
            plaintexts[i] = self.get_plaintext()
            traces[i] = leaking_encryption.encrypt(plaintexts[i])

        numpy.save(self.traces_file, traces)

        f = open(self.plaintexts_file, 'wb')
        pickle.dump(plaintexts, f)
        f.close()


def main():
    generator = Generator([[1] * 16])
    generator.generate()


if "__main__" == __name__:
    main()
