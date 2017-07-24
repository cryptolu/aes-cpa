from aes_cipher.constants import s_box, t0, t1, t2, t3
from cpa_attacker.plotter import Plotter
from cpa_attacker.round1 import Round1
from cpa_attacker.round2 import Round2
from cpa_attacker.round3 import Round3
from leakage_generator.generator import Generator
from leakage_model.hw_s_box import HwSBox
from leakage_model.hw_t_table import HwTTable
from expected_round_keys.expected_round_keys_generator import ExpectedRoundKeysGenerator
from symbolic_evaluator.evaluation_case_solver import EvaluationCaseSolver


import gc
import math
import numpy
import operator
import pickle
import shutil
import time


class Attacker:
    def __init__(self, generate_traces=True, t_tables_implementation=False, debug=False):
        self.t_tables_implementation = t_tables_implementation
        if self.t_tables_implementation:
            self.power_model = HwTTable()
        else:
            self.power_model = HwSBox()

        self.path = './data/'
        self.source_plaintexts_file = self.path + 'plaintexts.bin'
        self.source_traces_file = self.path + 'traces.npy'

        self.plaintexts_file_format = self.path + 'plaintexts_evaluation_case_{:02}_experiment_{:03}.bin'
        self.traces_file_format = self.path + 'traces_evaluation_case_{:02}_experiment_{:03}.npy'

        self.number_of_plaintexts = 0
        self.plaintexts = None

        self.start_sample = 0
        if t_tables_implementation:
            self.number_of_samples = 16 * 9
        else:
            self.number_of_samples = 16 * 9

        self.traces = None

        self.subkey_size = 8

        self.average_traces = None
        self.average_traces_count = None

        self.expected_key = None

        self.round1 = None
        self.round2 = None
        self.round3 = None

        self.recovered_keys = None
        self.valid_recovered_keys = None
        self.guessing_entropy = None

        self.number_of_cpa_attacks = 0

        self.debug = debug

        self.plotter_possible_key = [-1] * 64
        self.plot_correlation_matrix = False

        self.number_of_traces = 500

        self.attacked_number_of_rounds = 0

        self.generate_traces = generate_traces

        self.conditional_average = True

        self.round_leakage = True

        numpy.seterr(divide='ignore', invalid='ignore')

    @staticmethod
    def pcc(p, o):
        n = p.size
        do = o - (numpy.einsum('ij->j', o) / numpy.double(n))
        p -= (numpy.einsum('i->', p) / numpy.double(n))
        tmp = numpy.einsum('ij,ij->j', do, do)
        tmp *= numpy.einsum('i,i->', p, p)
        return numpy.dot(p, do) / numpy.sqrt(tmp)

    @staticmethod
    def get_keys(correlation_matrix):
        max_value_indexes = numpy.argwhere(correlation_matrix == numpy.amax(correlation_matrix))

        subkeys = []
        for max_value_index in max_value_indexes:
            subkeys.append(max_value_index[0])

        return subkeys

    @staticmethod
    def get_keys2(correlation_matrix):
        subkeys = []

        max_value_index = numpy.argmax(correlation_matrix)
        subkey = numpy.unravel_index(max_value_index, correlation_matrix.shape)[0]

        subkeys.append(subkey)

        old_correlation_coefficient = correlation_matrix[subkey, :]
        correlation_matrix[subkey, :] = numpy.zeros((1, correlation_matrix.shape[1]))

        max_value_index = numpy.argmax(correlation_matrix)
        subkey = numpy.unravel_index(max_value_index, correlation_matrix.shape)[0]

        subkeys.append(subkey)

        correlation_matrix[subkeys[0], :] = old_correlation_coefficient

        return subkeys

    def predict_power_consumption(self, plaintext, key, index):
        value = plaintext ^ key

        if self.t_tables_implementation:
            if 0 == index % 4:
                value = t0[value]
            elif 1 == index % 4:
                value = t1[value]
            elif 2 == index % 4:
                value = t2[value]
            elif 3 == index % 4:
                value = t3[value]
        else:
            value = s_box[value]

        return self.power_model.leak(value)

    def get_plaintext_part(self, plaintext, index):
        if (0 <= index) & (15 >= index):
            # first round
            x = (plaintext >> ((15 - index) * 8)) & 0xff
        elif (16 <= index) & (31 >= index):
            # second round
            x = self.round1.get_plaintext_part(plaintext, index)
        elif (32 <= index) & (47 >= index):
            # third round
            x = self.round2.get_plaintext_part(plaintext, index)
        elif (48 <= index) & (63 >= index):
            # fourth round
            x = self.round3.get_plaintext_part(plaintext, index)

        return x

    def rank(self, correlation_matrix, expected_key):
        correlation_coefficients = [0] * (2 ** self.subkey_size)

        for i in range(correlation_matrix.shape[0]):
            max_value_index = numpy.argmax(correlation_matrix[i])
            max_value = correlation_matrix[i][max_value_index]
            correlation_coefficients[i] = (i, max_value, max_value_index)

        correlation_coefficients = sorted(correlation_coefficients, key=operator.itemgetter(1), reverse=True)

        rank_index = -1
        rank = 10
        expected_key_rank = rank_index
        break_next = False
        for i in range(len(correlation_coefficients)):
            key = correlation_coefficients[i][0]
            value = correlation_coefficients[i][1]
            sample = correlation_coefficients[i][2]

            if value != rank:
                rank_index += 1
                rank = value
                # print('Rank {}: 0x{} {} ({})'.format(rank_index, format(key, '02x'), value, sample))
                if break_next:
                    break
                if key == expected_key:
                    expected_key_rank = rank_index
                    break_next = True
            else:
                # print('Rank {}: 0x{} {} ({})'.format(rank_index, format(key, '02x'), value, sample))
                if key == expected_key:
                    expected_key_rank = rank_index
                    break_next = True

        return expected_key_rank

    def delta(self, correlation_matrix):
        correlation_coefficients = [0] * (2 ** self.subkey_size)

        for i in range(correlation_matrix.shape[0]):
            max_value_index = numpy.argmax(correlation_matrix[i])
            max_value = correlation_matrix[i][max_value_index]
            correlation_coefficients[i] = (i, max_value, max_value_index)

        correlation_coefficients = sorted(correlation_coefficients, key=operator.itemgetter(1), reverse=True)

        first_value = correlation_coefficients[0][1]
        second_value = correlation_coefficients[1][1]
        delta = first_value - second_value

        return delta

    def init_conditional_average(self, index):
        self.start_sample = 0

        # all rounds
        if self.t_tables_implementation:
            self.number_of_samples = 16 * 9
        else:
            self.number_of_samples = 16 * 9

        # first 4 rounds
        # self.number_of_samples = 16 * 4

        # just 1 round
        if self.round_leakage:
            self.number_of_samples = 16

        self.average_traces = numpy.zeros((2 ** self.subkey_size, self.number_of_samples))
        self.average_traces_count = [0 for i in range(2 ** self.subkey_size)]

        self.number_of_plaintexts = 2 ** self.subkey_size
        self.plaintexts = [i for i in range(self.number_of_plaintexts)]

    def load_conditional_average(self, index, start, number_of_traces, evaluation_case, experiment):
        plaintexts_file = self.plaintexts_file_format.format(evaluation_case, experiment)
        traces_file = self.traces_file_format.format(evaluation_case, experiment)

        f = open(plaintexts_file, 'rb')
        plaintexts = pickle.load(f)
        number_of_plaintexts = len(plaintexts)
        f.close()

        traces = numpy.load(traces_file)

        if not self.round_leakage:
            traces = traces[:, self.start_sample:self.start_sample + self.number_of_samples]

        # Use just the leakage from the attacked round
        if self.round_leakage:
            if index in range(16):
                traces = traces[:, 0:16]
            elif index in range(16, 32, 1):
                traces = traces[:, 16:32]
            elif index in range(32, 48, 1):
                traces = traces[:, 32:48]
            else:
                traces = traces[:, 48:64]

        if self.conditional_average:
            # Conditional average
            for j in range(start, number_of_traces, 1):
                x = self.get_plaintext_part(plaintexts[j], index)
                self.average_traces_count[x] += 1
                self.average_traces[x] += (traces[j] - self.average_traces[x]) / self.average_traces_count[x]

            self.traces = self.average_traces

            valid_plaintexts = 0
            for i in range(2 ** self.subkey_size):
                if self.average_traces[i][0]:
                    valid_plaintexts += 1

            if self.number_of_plaintexts != valid_plaintexts:
                self.number_of_plaintexts = valid_plaintexts
                new_plaintexts = [0 for i in range(self.number_of_plaintexts)]
                new_traces = numpy.zeros((self.number_of_plaintexts, self.number_of_samples))

                index = 0
                for i in range(2 ** self.subkey_size):
                    if self.average_traces[i][0]:
                        new_plaintexts[index] = self.plaintexts[i]
                        new_traces[index] = self.average_traces[i]
                        index += 1

                self.plaintexts = new_plaintexts
                self.traces = new_traces
        else:
            # No conditional average
            self.number_of_plaintexts = number_of_plaintexts
            self.plaintexts = [0 for i in range(self.number_of_plaintexts)]
            for j in range(start, number_of_traces, 1):
                self.plaintexts[j] = self.get_plaintext_part(plaintexts[j], index)
            self.traces = traces

    def conditional_average_attack(self, index, number_of_traces):
        self.number_of_cpa_attacks += 1

        hypothetical_power_consumption = numpy.zeros((self.number_of_plaintexts, 2 ** self.subkey_size))

        for i in range(self.number_of_plaintexts):
            x = self.plaintexts[i]

            for j in range(2 ** self.subkey_size):
                power = self.predict_power_consumption(x, j, index)
                hypothetical_power_consumption[i][j] = power

        correlation_matrix = numpy.zeros((2 ** self.subkey_size, self.number_of_samples))

        for i in range(2 ** self.subkey_size):
            pcc = self.pcc(hypothetical_power_consumption[:, i], self.traces)
            correlation_matrix[i] = pcc

        correlation_matrix = numpy.nan_to_num(correlation_matrix)

        recovered_keys = self.get_keys(correlation_matrix)

        expected_key = self.expected_key[index]

        rank = self.rank(correlation_matrix, expected_key)

        guessing_entropy = self.get_guessing_entropy(index, rank)

        if self.plot_correlation_matrix:
            self.plotter_possible_key[index] += 1
            Plotter.plot_correlation_matrix(correlation_matrix, index, expected_key, self.plotter_possible_key[index])

        return recovered_keys, guessing_entropy

    def conditional_average_attack2(self, index, number_of_traces):
        self.number_of_cpa_attacks += 1

        hypothetical_power_consumption = numpy.zeros((self.number_of_plaintexts, 2 ** self.subkey_size))

        for i in range(self.number_of_plaintexts):
            x = self.plaintexts[i]

            for j in range(2 ** self.subkey_size):
                power = self.predict_power_consumption(x, j, index)
                hypothetical_power_consumption[i][j] = power

        correlation_matrix = numpy.zeros((2 ** self.subkey_size, self.number_of_samples))

        for i in range(2 ** self.subkey_size):
            pcc = self.pcc(hypothetical_power_consumption[:, i], self.traces)
            correlation_matrix[i] = pcc

        correlation_matrix = numpy.nan_to_num(correlation_matrix)

        recovered_keys = self.get_keys2(correlation_matrix)

        expected_key = self.expected_key[index]

        rank = self.rank(correlation_matrix, expected_key)

        guessing_entropy = self.get_guessing_entropy(index, rank)

        if self.plot_correlation_matrix:
            self.plotter_possible_key[index] += 1
            Plotter.plot_correlation_matrix(correlation_matrix, index, expected_key, self.plotter_possible_key[index])

        return recovered_keys

    def conditional_average_attack_delta(self, index, number_of_traces):
        self.number_of_cpa_attacks += 1

        hypothetical_power_consumption = numpy.zeros((self.number_of_plaintexts, 2 ** self.subkey_size))

        for i in range(self.number_of_plaintexts):
            x = self.plaintexts[i]

            for j in range(2 ** self.subkey_size):
                power = self.predict_power_consumption(x, j, index)
                hypothetical_power_consumption[i][j] = power

        correlation_matrix = numpy.zeros((2 ** self.subkey_size, self.number_of_samples))

        for i in range(2 ** self.subkey_size):
            pcc = self.pcc(hypothetical_power_consumption[:, i], self.traces)
            correlation_matrix[i] = pcc

        correlation_matrix = numpy.nan_to_num(correlation_matrix)

        recovered_keys = self.get_keys(correlation_matrix)

        expected_key = self.expected_key[index]

        rank = self.rank(correlation_matrix, expected_key)
        delta = self.delta(correlation_matrix)

        guessing_entropy = self.get_guessing_entropy(index, rank)

        if self.plot_correlation_matrix:
            self.plotter_possible_key[index] += 1
            Plotter.plot_correlation_matrix(correlation_matrix, index, expected_key, self.plotter_possible_key[index])

        return recovered_keys, delta, guessing_entropy

    def get_guessing_entropy(self, index, rank):
        if (self.attacked_number_of_rounds - 1) * 16 <= index < self.attacked_number_of_rounds * 16:
            return math.log(rank + 1, 2)

        return 0

    def attack_subkey(self, index, evaluation_case, experiment):
        self.init_conditional_average(index)
        self.load_conditional_average(index, 0, self.number_of_traces, evaluation_case, experiment)
        keys, guessing_entropy = self.conditional_average_attack(index, self.number_of_traces)

        self.traces = None
        self.plaintexts = None
        gc.collect()

        return keys[0], guessing_entropy

    def attack_subkey2(self, index, evaluation_case, experiment):
        self.init_conditional_average(index)
        self.load_conditional_average(index, 0, self.number_of_traces, evaluation_case, experiment)
        keys = self.conditional_average_attack2(index, self.number_of_traces)

        self.traces = None
        self.plaintexts = None
        gc.collect()

        return keys

    def attack_subkey_delta(self, index, evaluation_case, experiment):
        self.init_conditional_average(index)
        self.load_conditional_average(index, 0, self.number_of_traces, evaluation_case, experiment)
        keys, delta, guessing_entropy = self.conditional_average_attack_delta(index, self.number_of_traces)

        self.traces = None
        self.plaintexts = None
        gc.collect()

        return keys[0], delta, guessing_entropy

    @staticmethod
    def get_pair_indexes(pairs, pair, round_number):
        indexes = []

        for i in range(16):
            if pair in set(pairs[i]):
                indexes.append(16 * round_number + i)

        return indexes

    def check_recovery(self, number_of_possible_keys, number_of_rounds):
        if self.debug:
            print('INDEX')
            print('IDX ', end='')
            for i in range(16 * number_of_rounds):
                print('{:2} '.format(i), end='')
            print()

            print('RECOVERED')
            for i in range(number_of_possible_keys):
                print('{:2}) '.format(i), end='')
                for j in range(16 * number_of_rounds):
                    if self.recovered_keys[i][j] is not None:
                        print('{} '.format(format(self.recovered_keys[i][j], '02x')), end='')
                    else:
                        print('{} '.format(format(0x00, '02x')), end='')
                print(' {}'.format(self.valid_recovered_keys[i]), end='')
                print()
            print()

            print('EXPECTED')
            print('EXP ', end='')
            for i in range(16 * number_of_rounds):
                print('{} '.format(format(self.expected_key[i], '02x')), end='')
            print()

        correct_key_index = -1

        valid_keys = 0
        for i in range(number_of_possible_keys):
            if self.valid_recovered_keys[i]:
                valid_keys += 1

            found = True
            for j in range(16 * number_of_rounds):
                if self.recovered_keys[i][j] != self.expected_key[j]:
                    found = False
                    break

            if found:
                correct_key_index = i

            if self.debug and found:
                print('Correct key at index {}.'.format(i))

        if self.debug and 1 == valid_keys:
            print('Unique candidate!')

        if 1 == valid_keys:
            return correct_key_index
        else:
            return -1

    def attack(self, initial_state, number_of_traces, evaluation_case, experiment):
        self.number_of_traces = number_of_traces
        self.guessing_entropy = 0
        self.number_of_cpa_attacks = 0

        evaluation_case_solver = EvaluationCaseSolver(initial_state)
        evaluation_case_solver.process()
        state = evaluation_case_solver.state
        pairs = evaluation_case_solver.pairs
        statistics = evaluation_case_solver.get_statistics()
        max_possible_keys = evaluation_case_solver.get_max_possible_keys()
        if self.debug:
            evaluation_case_solver.print_state_pairs()

        if self.debug:
            print('Attack {} round(s) to get {} possible key(s).'.format(statistics[1], statistics[0]))

        self.attacked_number_of_rounds = statistics[1]

        known_pairs = set()
        map_pairs = []

        self.recovered_keys = [[0 for i in range(64)] for j in range(max_possible_keys)]
        self.valid_recovered_keys = [True for i in range(max_possible_keys)]
        self.guessing_entropy = [0 for i in range(max_possible_keys)]

        for i in range(statistics[1]):
            if 1 == i:
                self.round1 = Round1(self.recovered_keys[0], state)
            if 2 == i:
                self.round2 = Round2(self.recovered_keys[0], state)
            if 3 == i:
                self.round3 = Round3(self.recovered_keys[0], state)

            for j in range(16):
                if 0 != state[i][j]:
                    index = 16 * i + j
                    if self.debug:
                        print('Attack subkey: {:2}'.format(index))

                    subkey_pairs = set(pairs[i][j])

                    if set(subkey_pairs) <= set(known_pairs):

                        if 0 == len(pairs[i][j]):
                            recovered_key, guessing_entropy = self.attack_subkey(index, evaluation_case, experiment)
                            for k in range(max_possible_keys):
                                self.recovered_keys[k][index] = recovered_key
                                self.guessing_entropy[k] += guessing_entropy
                        else:
                            is_index_mapped = False
                            for k in range(len(pairs[i][j])):
                                if index in map_pairs[pairs[i][j][k] - 1]:
                                    is_index_mapped = True
                                    break

                            if not is_index_mapped:
                                recovered_key = [None for i in range(32)]
                                delta = [0 for i in range(32)]
                                guessing_entropy = [0 for i in range(32)]

                                mask = 0
                                for pair in subkey_pairs:
                                    mask |= 2 ** (pair - 1)

                                for k in range(max_possible_keys):
                                    if recovered_key[k & mask] is None and self.valid_recovered_keys[k]:
                                        self.round2 = Round2(self.recovered_keys[k], state)
                                        self.round3 = Round3(self.recovered_keys[k], state)

                                        recovered_key[k & mask], delta[k & mask], guessing_entropy[k & mask] = \
                                            self.attack_subkey_delta(index, evaluation_case, experiment)

                                    self.recovered_keys[k][index] = recovered_key[k & mask]
                                    self.guessing_entropy[k] += guessing_entropy[k & mask]

                                if (1 == abs(state[i][j])) and (0 != len(pairs[i][j])):
                                    max_delta = -1
                                    for k in range(max_possible_keys):
                                        if max_delta < delta[k & mask]:
                                            max_delta = delta[k & mask]

                                    for k in range(max_possible_keys):
                                        if max_delta > delta[k & mask]:
                                            self.valid_recovered_keys[k] = False
                    else:
                        if 1 == len(subkey_pairs):
                            pair = list(subkey_pairs)[0]

                            [index1, index2] = self.get_pair_indexes(pairs[i], pair, i)
                            recovered_keys = self.attack_subkey2(index, evaluation_case, experiment)

                            mask = 2 ** (pair - 1)
                            for k in range(max_possible_keys):
                                if 0 == k & mask:
                                    self.recovered_keys[k][index1] = recovered_keys[0]
                                    self.recovered_keys[k][index2] = recovered_keys[1]
                                else:
                                    self.recovered_keys[k][index1] = recovered_keys[1]
                                    self.recovered_keys[k][index2] = recovered_keys[0]

                        elif 2 == len(subkey_pairs):
                            pair1 = list(subkey_pairs)[0]
                            pair2 = list(subkey_pairs)[1]

                            if set([pair1]) <= set(known_pairs):
                                new_pair = pair2
                                known_pair = pair1
                            else:
                                new_pair = pair1
                                known_pair = pair2

                            [index1, index2] = self.get_pair_indexes(pairs[i], new_pair, i)

                            direct = None
                            reverse = None

                            known_mask = 2 ** (known_pair - 1)
                            mask = 2 ** (new_pair - 1)
                            for k in range(max_possible_keys):
                                if 0 == k & known_mask:
                                    if direct is None:
                                        self.round1 = Round1(self.recovered_keys[k], state)
                                        self.round2 = Round2(self.recovered_keys[k], state)
                                        direct = self.attack_subkey2(index, evaluation_case, experiment)

                                    if 0 == k & mask:
                                        self.recovered_keys[k][index1] = direct[0]
                                        self.recovered_keys[k][index2] = direct[1]
                                    else:
                                        self.recovered_keys[k][index1] = direct[1]
                                        self.recovered_keys[k][index2] = direct[0]
                                else:
                                    if reverse is None:
                                        self.round1 = Round1(self.recovered_keys[k], state)
                                        self.round2 = Round2(self.recovered_keys[k], state)
                                        reverse = self.attack_subkey2(index, evaluation_case, experiment)

                                    if 0 == k & mask:
                                        self.recovered_keys[k][index1] = reverse[0]
                                        self.recovered_keys[k][index2] = reverse[1]
                                    else:
                                        self.recovered_keys[k][index1] = reverse[1]
                                        self.recovered_keys[k][index2] = reverse[0]

                        for pair in subkey_pairs:
                            if pair not in known_pairs:
                                known_pairs.add(pair)
                                map_pairs.append(self.get_pair_indexes(pairs[i], pair, i))

        correct_key_index = self.check_recovery(max_possible_keys, statistics[1])

        if self.debug:
            print('Number of CPA attacks: {}.'.format(self.number_of_cpa_attacks))

        return self.guessing_entropy[correct_key_index]

    def dump_data(self, evaluation_case, initial_state, experiments, traces_x, guessing_entropy_y,
                  minimum_number_of_traces, duration):
        f = open('./output/data_evaluation_case_{:02}.txt'.format(evaluation_case), 'w')

        f.write('Evaluation case: {}\n'.format(evaluation_case))
        f.write('Experiments: {}\n'.format(experiments))

        f.write('\n')

        f.write('Initial state: {}\n'.format(initial_state))
        f.write('Attacked number of rounds: {}\n'.format(self.attacked_number_of_rounds))
        f.write('CPA attacks: {}\n'.format(self.number_of_cpa_attacks))

        f.write('\n')

        f.write('Traces: {}\n'.format(traces_x))
        f.write('GE: {}\n'.format(guessing_entropy_y))
        f.write('Minimum number of traces: {}'.format(minimum_number_of_traces))

        f.write('\n')

        f.write('Duration: {}'.format(time.strftime('%H:%M:%S', time.gmtime(duration))))

        f.close()

    @staticmethod
    def get_minimum_number_of_traces(traces_x, guessing_entropy_y):
        minimum = -1

        for i in range(len(traces_x) - 1, -1, -1):
            if 0 != guessing_entropy_y[i]:
                break
            minimum = traces_x[i]

        return minimum

    def rename_files(self, evaluation_case, experiment):
        if not self.generate_traces:
            return

        destination_plaintext_file = self.plaintexts_file_format.format(evaluation_case, experiment)
        destination_traces_file = self.traces_file_format.format(evaluation_case, experiment)

        shutil.move(self.source_plaintexts_file, destination_plaintext_file)
        shutil.move(self.source_traces_file, destination_traces_file)

    def attack_guessing_entropy(self, evaluation_case, initial_state, start_traces, stop_traces, step_traces,
                                experiments=1):
        evaluation_case_start_time = time.time()

        traces_x = []
        guessing_entropy_y = []

        for experiment in range(experiments):
            # Get attack state
            evaluation_case_solver = EvaluationCaseSolver(initial_state)
            evaluation_case_solver.process()
            state = evaluation_case_solver.state

            if self.generate_traces:
                generator = Generator(state, stop_traces + step_traces, self.t_tables_implementation)
                generator.generate()

            key_schedule = ExpectedRoundKeysGenerator(state)
            self.expected_key = key_schedule.generate()

            # Rename leakage files
            self.rename_files(evaluation_case, experiment)

            for traces in range(start_traces, stop_traces + 1, step_traces):
                guessing_entropy = self.attack(initial_state, traces, evaluation_case, experiment)

                if 0 == experiment:
                    traces_x.append(traces)
                    guessing_entropy_y.append(guessing_entropy)
                else:
                    index = -1
                    for j in range(len(traces_x)):
                        if traces_x[j] == traces:
                            index = j
                            break

                    guessing_entropy_y[index] += (guessing_entropy - guessing_entropy_y[index]) / (traces + 1)

        Plotter.plot_guessing_entropy('{:02}'.format(evaluation_case), traces_x, guessing_entropy_y)

        evaluation_case_stop_time = time.time()
        duration = evaluation_case_stop_time - evaluation_case_start_time

        minimum_number_of_traces = self.get_minimum_number_of_traces(traces_x, guessing_entropy_y)

        self.dump_data(evaluation_case, initial_state, experiments, traces_x, guessing_entropy_y,
                       minimum_number_of_traces, duration)

    def attack_guessing_entropy_evaluation_cases(self):
        # Test extreme evaluation cases
        # """
        initial_states = [
            #  1 byte  controlled by attacker
            [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],

            # 16 bytes controlled by attacker
            [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
        ]
        # """

        # All 25 evaluation cases
        """
        initial_states = [
            #  1 byte  controlled by attacker
            [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],  # Case 0

            #  2 bytes controlled by attacker
            [1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],  # Case 1

            #  3 bytes controlled by attacker
            [1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],  # Case 2

            #  4 bytes controlled by attacker
            [1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],  # Case 3
            [1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],  # Case 4

            #  5 bytes controlled by attacker
            [1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],  # Case 5
            [1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],  # Case 6

            #  6 bytes controlled by attacker
            [1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],  # Case 7
            [1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0],  # Case 8

            #  7 bytes controlled by attacker
            [1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],  # Case 9
            [1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0],  # Case 10

            #  8 bytes controlled by attacker
            [1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0],  # Case 11
            [1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0],  # Case 12

            #  9 bytes controlled by attacker
            [1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0],  # Case 13
            [1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0],  # Case 14

            # 10 bytes controlled by attacker
            [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0],  # Case 15
            [1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0],  # Case 16

            # 11 bytes controlled by attacker
            [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0],  # Case 17
            [1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0],  # Case 18

            # 12 bytes controlled by attacker
            [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0],  # Case 19
            [1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1],  # Case 20

            # 13 bytes controlled by attacker
            [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0],  # Case 21

            # 14 bytes controlled by attacker
            [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0],  # Case 22

            # 15 bytes controlled by attacker
            [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0],  # Case 23

            # 16 bytes controlled by attacker
            [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]   # Case 24
        ]
        """

        # Step 1
        start_traces = 10
        stop_traces = 50
        step_traces = 10
        experiments = 10

        print('Run for {} evaluation cases; {} experiments for each evaluation case.'.format(len(initial_states),
                                                                                             experiments))

        evaluation_case = 0
        for initial_state in initial_states:
            print('Evaluation case {:2}: {}'.format(evaluation_case, initial_state))
            self.attack_guessing_entropy(evaluation_case, initial_state, start_traces, stop_traces, step_traces,
                                         experiments)
            evaluation_case += 1


def main():
    attacker = Attacker(generate_traces=True, t_tables_implementation=True, debug=False)
    attacker.attack_guessing_entropy_evaluation_cases()


if "__main__" == __name__:
    start_time = time.time()

    main()

    stop_time = time.time()

    print('Duration: {}'.format(time.strftime('%H:%M:%S', time.gmtime(stop_time - start_time))))
