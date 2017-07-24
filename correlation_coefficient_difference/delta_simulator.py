from aes_cipher.constants import s_box, t0, t1, t2, t3
from leakage_model.hw_s_box import HwSBox
from leakage_model.hw_t_table import HwTTable


import numpy
import operator
import random
import scipy
import scipy.stats
import time


class DeltaSimulator:
    def __init__(self):
        self.number_of_plaintexts = 2 ** 8
        self.subkey_size = 8

        self.number_of_samples = 1
        self.leaking_sample = self.number_of_samples // 2

        self.evaluation_case = None
        self.power_model = None
        self.traces = None

        self.init_type = 0
        if 0 == self.init_type:
            self.init_evaluation_case1()
        else:
            self.init_evaluation_case2()

        numpy.seterr(divide='ignore', invalid='ignore')

    def init_evaluation_case1(self, evaluation_case=-1):
        self.evaluation_case = evaluation_case

        if -1 == self.evaluation_case:
            self.power_model = HwSBox()
            max_hw = 8
        else:
            self.power_model = HwTTable()
            max_hw = 32

        self.traces = numpy.zeros((self.number_of_plaintexts, self.number_of_samples))

    def init_evaluation_case2(self, evaluation_case=-1, targeted_key=0x00):
        self.evaluation_case = evaluation_case

        if -1 == self.evaluation_case:
            self.power_model = HwSBox()
        else:
            self.power_model = HwTTable()

        self.traces = numpy.zeros((self.number_of_plaintexts, self.number_of_samples))

        random_keys = [0 for i in range(self.number_of_samples)]
        for i in range(self.number_of_samples):
            random_keys[i] = random.getrandbits(self.subkey_size)

            if i == self.leaking_sample and random_keys[i] == targeted_key:
                while random_keys[i] == targeted_key:
                    random_keys[i] = random.getrandbits(self.subkey_size)

        if -1 == evaluation_case:
            for i in range(self.number_of_plaintexts):
                for j in range(self.number_of_samples):
                    p = random.getrandbits(self.subkey_size)
                    value = self.power_model.leak(s_box[p ^ random_keys[j]])
                    self.traces[i][j] = value
        elif 0 == evaluation_case:
            for i in range(self.number_of_plaintexts):
                for j in range(self.number_of_samples):
                    p = random.getrandbits(self.subkey_size)
                    value = self.power_model.leak(t0[p ^ random_keys[j]])
                    self.traces[i][j] = value
        elif 1 == evaluation_case:
            for i in range(self.number_of_plaintexts):
                for j in range(self.number_of_samples):
                    p = random.getrandbits(self.subkey_size)
                    value = self.power_model.leak(t1[p ^ random_keys[j]])
                    self.traces[i][j] = value
        elif 2 == evaluation_case:
            for i in range(self.number_of_plaintexts):
                for j in range(self.number_of_samples):
                    p = random.getrandbits(self.subkey_size)
                    value = self.power_model.leak(t2[p ^ random_keys[j]])
                    self.traces[i][j] = value
        elif 3 == evaluation_case:
            for i in range(self.number_of_plaintexts):
                for j in range(self.number_of_samples):
                    p = random.getrandbits(self.subkey_size)
                    value = self.power_model.leak(t3[p ^ random_keys[j]])
                    self.traces[i][j] = value

    def generate_leakage(self, k):
        for p in range(self.number_of_plaintexts):
            c = s_box[p ^ k]
            self.traces[p][self.leaking_sample] = self.power_model.leak(c)

    @staticmethod
    def pcc(p, o):
        n = p.size
        do = o - (numpy.einsum('ij->j', o) / numpy.double(n))
        p -= (numpy.einsum('i->', p) / numpy.double(n))
        tmp = numpy.einsum('ij,ij->j', do, do)
        tmp *= numpy.einsum('i,i->', p, p)
        return numpy.dot(p, do) / numpy.sqrt(tmp)

    def predict_power_consumption(self, plaintext, key):
        value = plaintext ^ key

        if -1 == self.evaluation_case:
            value = s_box[value]
        elif 0 == self.evaluation_case:
            value = t0[value]
        elif 1 == self.evaluation_case:
            value = t1[value]
        elif 2 == self.evaluation_case:
            value = t2[value]
        elif 3 == self.evaluation_case:
            value = t3[value]

        return self.power_model.leak(value)

    def get_delta(self, correlation_matrix, expected_key):
        correlation_coefficients = [0] * (2 ** self.subkey_size)

        for i in range(correlation_matrix.shape[0]):
            max_value_index = numpy.argmax(correlation_matrix[i])
            max_value = correlation_matrix[i][max_value_index]
            correlation_coefficients[i] = (i, max_value, max_value_index)

        correlation_coefficients = sorted(correlation_coefficients, key=operator.itemgetter(1), reverse=True)

        delta_1 = 0
        delta_2 = 0

        rank_index = -1
        break_next = False
        for i in range(len(correlation_coefficients)):
            key = correlation_coefficients[i][0]
            value = correlation_coefficients[i][1]
            sample = correlation_coefficients[i][2]

            rank_index += 1

            # print('Rank {}: 0x{} {:1.010} ({})'.format(rank_index, format(key, '02x'), value, sample))

            if break_next:
                break

            if expected_key == key:
                delta_1 = value

                if 0 != i:
                    delta_2 = correlation_coefficients[0][1]
                else:
                    delta_2 = correlation_coefficients[i + 1][1]
                break_next = True

        delta = delta_1 - delta_2
        # print('d1 (expected)         : {:+1.06}'.format(delta_1))
        # print('d2 (best != expected) : {:+1.06}'.format(delta_2))
        # print('d  (d1 - d2)          : {:+1.06}'.format(delta))

        return delta

    def attack(self, expected_key):
        hypothetical_power_consumption = numpy.zeros((self.number_of_plaintexts, 2 ** self.subkey_size))

        for p in range(self.number_of_plaintexts):
            for k in range(2 ** self.subkey_size):
                power = self.predict_power_consumption(p, k)
                hypothetical_power_consumption[p][k] = power

        correlation_matrix = numpy.zeros((2 ** self.subkey_size, self.number_of_samples))

        for i in range(2 ** self.subkey_size):
            pcc = self.pcc(hypothetical_power_consumption[:, i], self.traces)
            correlation_matrix[i] = pcc

        correlation_matrix = numpy.nan_to_num(correlation_matrix)
        delta = self.get_delta(correlation_matrix, expected_key)

        return delta

    def check_all(self, evaluation_case=-1):
        if 0 == self.init_type:
            self.init_evaluation_case1(evaluation_case)
        else:
            self.init_evaluation_case2()

        delta_value = 0

        for k in range(2 ** self.subkey_size):
            if 0 != self.init_type:
                self.init_evaluation_case2(evaluation_case, k)

            self.generate_leakage(k)
            delta = self.attack(k)

            if 0 == k:
                delta_value = delta

            if delta_value != delta:
                print('Error: key 0x{} has delta {:+1.06}, not {:+1.06}!'.format(format(k, '02x'), delta, delta_value))

        return delta_value

    def run(self, key, evaluation_case=-1):
        if 0 == self.init_type:
            self.init_evaluation_case1(evaluation_case)
        else:
            self.init_evaluation_case2(evaluation_case, key)

        self.generate_leakage(key)
        delta = self.attack(key)

        return delta


def run_keys(evaluation_case=-1, key1=0x00, key2=0x0F, key3=0xFF):
    delta_s = DeltaSimulator()

    delta = delta_s.run(key1, evaluation_case)
    print('k = 0x{}: {:+1.03}'.format(format(key1, '02x'), delta))

    delta = delta_s.run(key2, evaluation_case)
    print('k = 0x{}: {:+1.03}'.format(format(key2, '02x'), delta))

    delta = delta_s.run(key3, evaluation_case)
    print('k = 0x{}: {:+1.03}'.format(format(key3, '02x'), delta))


def run():
    number_of_experiments = 10

    evaluation_cases = [-1, 0, 1, 2, 3]

    keys = list(range(2 ** 8))

    delta_s = DeltaSimulator()
    for evaluation_case in evaluation_cases:

        print('Evaluation case: {:+1}'.format(evaluation_case))

        global_delta = [0 for i in range(len(keys))]
        global_index = 0

        for k in keys:
            delta = [0 for i in range(number_of_experiments)]

            for experiment in range(number_of_experiments):
                delta[experiment] = delta_s.run(k, evaluation_case)

            global_delta[global_index] = numpy.mean(delta)
            global_index += 1

        global_delta = 1.0 * numpy.array(global_delta)
        n = len(global_delta)

        confidence = 0.95
        m, se = numpy.mean(global_delta), scipy.stats.sem(global_delta)
        h = se * scipy.stats.t._ppf((1 + confidence) / 2., n - 1)

        print('global delta = {}'.format(global_delta))

        print('Result: {:+1.03} {:+1.03}'.format(m, h))
        print()


def check_all():
    delta_simulator = DeltaSimulator()
    delta_simulator.check_all()


if "__main__" == __name__:
    start_time = time.time()

    # run_keys()
    run()
    # check_all()

    stop_time = time.time()

    print()
    print('Duration: {}'.format(time.strftime('%H:%M:%S', time.gmtime(stop_time - start_time))))
