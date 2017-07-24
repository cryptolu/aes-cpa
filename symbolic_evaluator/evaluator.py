from symbolic_evaluator.evaluation_case_solver import EvaluationCaseSolver


import operator
import time


class Evaluator:
    def __init__(self, debug=False):
        self.debug = debug

        # LaTeX tables
        self.latex_file_format = './data/table_{:02}.tex'

        # summary LaTeX table
        self.summary_latex_file = './data/summary_table.tex'

        self.best_case_possible_keys = []
        self.worst_case_possible_keys = []

        self.best_case_number_of_rounds = []
        self.worst_case_number_of_rounds = []

    @staticmethod
    def combinations(n, k):
        if k > n or n < 0 or k < 0:
            return 0
        top = n
        val = 1

        while top > n - k:
            val *= top
            top -= 1
        n = 1

        while n < k + 1:
            val /= n
            n += 1

        return val

    def get_states(self, controlled_bytes=0):
        if 0 == controlled_bytes:
            return self.get_states_0()
        elif 1 == controlled_bytes:
            return self.get_states_1()
        elif 2 == controlled_bytes:
            return self.get_states_2()
        elif 3 == controlled_bytes:
            return self.get_states_3()
        elif 4 == controlled_bytes:
            return self.get_states_4()
        elif 5 == controlled_bytes:
            return self.get_states_5()
        elif 6 == controlled_bytes:
            return self.get_states_6()
        elif 7 == controlled_bytes:
            return self.get_states_7()
        elif 8 == controlled_bytes:
            return self.get_states_8()
        elif 9 == controlled_bytes:
            return self.get_states_9()
        elif 10 == controlled_bytes:
            return self.get_states_10()
        elif 11 == controlled_bytes:
            return self.get_states_11()
        elif 12 == controlled_bytes:
            return self.get_states_12()
        elif 13 == controlled_bytes:
            return self.get_states_13()
        elif 14 == controlled_bytes:
            return self.get_states_14()
        elif 15 == controlled_bytes:
            return self.get_states_15()
        elif 16 == controlled_bytes:
            return self.get_states_16()

    def get_states_0(self):
        states = []
        initial_state = [0] * 16
        count = 0

        if self.debug:
            print('{:3}: {}'.format(count, initial_state))

        states.append(initial_state)

        return states

    def get_states_1(self):
        states = []
        initial_state = [0] * 16
        count = 0

        for index0 in range(16):
            initial_state[index0] = 1

            if self.debug:
                print('{:3}: {}'.format(count, initial_state))

            states.append(initial_state)

            count += 1
            initial_state = [0] * 16

        return states

    def get_states_2(self):
        states = []
        initial_state = [0] * 16

        count = 0
        for index0 in range(15):
            for index1 in range(index0 + 1, 16):
                initial_state[index0] = 1
                initial_state[index1] = 1

                if self.debug:
                    print('{:3}: {}'.format(count, initial_state))

                states.append(initial_state)

                count += 1
                initial_state = [0] * 16

        return states

    def get_states_3(self):
        states = []
        initial_state = [0] * 16
        count = 0

        for index0 in range(14):
            for index1 in range(index0 + 1, 15):
                for index2 in range(index1 + 1, 16):
                    initial_state[index0] = 1
                    initial_state[index1] = 1
                    initial_state[index2] = 1

                    if self.debug:
                        print('{:3}: {}'.format(count, initial_state))

                    states.append(initial_state)

                    count += 1
                    initial_state = [0] * 16

        return states

    def get_states_4(self):
        states = []
        initial_state = [0] * 16
        count = 0

        for index0 in range(13):
            for index1 in range(index0 + 1, 14):
                for index2 in range(index1 + 1, 15):
                    for index3 in range(index2 + 1, 16):
                        initial_state[index0] = 1
                        initial_state[index1] = 1
                        initial_state[index2] = 1
                        initial_state[index3] = 1

                        if self.debug:
                            print('{:3}: {}'.format(count, initial_state))

                        states.append(initial_state)

                        count += 1
                        initial_state = [0] * 16

        return states

    def get_states_5(self):
        states = []
        initial_state = [0] * 16
        count = 0

        for index0 in range(12):
            for index1 in range(index0 + 1, 13):
                for index2 in range(index1 + 1, 14):
                    for index3 in range(index2 + 1, 15):
                        for index4 in range(index3 + 1, 16):
                            initial_state[index0] = 1
                            initial_state[index1] = 1
                            initial_state[index2] = 1
                            initial_state[index3] = 1
                            initial_state[index4] = 1

                            if self.debug:
                                print('{:3}: {}'.format(count, initial_state))

                            states.append(initial_state)

                            count += 1
                            initial_state = [0] * 16

        return states

    def get_states_6(self):
        states = []
        initial_state = [0] * 16
        count = 0

        for index0 in range(11):
            for index1 in range(index0 + 1, 12):
                for index2 in range(index1 + 1, 13):
                    for index3 in range(index2 + 1, 14):
                        for index4 in range(index3 + 1, 15):
                            for index5 in range(index4 + 1, 16):
                                initial_state[index0] = 1
                                initial_state[index1] = 1
                                initial_state[index2] = 1
                                initial_state[index3] = 1
                                initial_state[index4] = 1
                                initial_state[index5] = 1

                                if self.debug:
                                    print('{:3}: {}'.format(count, initial_state))

                                states.append(initial_state)

                                count += 1
                                initial_state = [0] * 16

        return states

    def get_states_7(self):
        states = []
        initial_state = [0] * 16
        count = 0

        for index0 in range(10):
            for index1 in range(index0 + 1, 11):
                for index2 in range(index1 + 1, 12):
                    for index3 in range(index2 + 1, 13):
                        for index4 in range(index3 + 1, 14):
                            for index5 in range(index4 + 1, 15):
                                for index6 in range(index5 + 1, 16):
                                    initial_state[index0] = 1
                                    initial_state[index1] = 1
                                    initial_state[index2] = 1
                                    initial_state[index3] = 1
                                    initial_state[index4] = 1
                                    initial_state[index5] = 1
                                    initial_state[index6] = 1

                                    if self.debug:
                                        print('{:3}: {}'.format(count, initial_state))

                                    states.append(initial_state)

                                    count += 1
                                    initial_state = [0] * 16

        return states

    def get_states_8(self):
        states = []
        initial_state = [0] * 16
        count = 0

        for index0 in range(9):
            for index1 in range(index0 + 1, 10):
                for index2 in range(index1 + 1, 11):
                    for index3 in range(index2 + 1, 12):
                        for index4 in range(index3 + 1, 13):
                            for index5 in range(index4 + 1, 14):
                                for index6 in range(index5 + 1, 15):
                                    for index7 in range(index6 + 1, 16):
                                        initial_state[index0] = 1
                                        initial_state[index1] = 1
                                        initial_state[index2] = 1
                                        initial_state[index3] = 1
                                        initial_state[index4] = 1
                                        initial_state[index5] = 1
                                        initial_state[index6] = 1
                                        initial_state[index7] = 1

                                        if self.debug:
                                            print('{:3}: {}'.format(count, initial_state))

                                        states.append(initial_state)

                                        count += 1
                                        initial_state = [0] * 16

        return states

    def get_states_9(self):
        states = []
        initial_state = [0] * 16
        count = 0

        for index0 in range(8):
            for index1 in range(index0 + 1, 9):
                for index2 in range(index1 + 1, 10):
                    for index3 in range(index2 + 1, 11):
                        for index4 in range(index3 + 1, 12):
                            for index5 in range(index4 + 1, 13):
                                for index6 in range(index5 + 1, 14):
                                    for index7 in range(index6 + 1, 15):
                                        for index8 in range(index7 + 1, 16):
                                            initial_state[index0] = 1
                                            initial_state[index1] = 1
                                            initial_state[index2] = 1
                                            initial_state[index3] = 1
                                            initial_state[index4] = 1
                                            initial_state[index5] = 1
                                            initial_state[index6] = 1
                                            initial_state[index7] = 1
                                            initial_state[index8] = 1

                                            if self.debug:
                                                print('{:3}: {}'.format(count, initial_state))

                                            states.append(initial_state)

                                            count += 1
                                            initial_state = [0] * 16

        return states

    def get_states_10(self):
        states = []
        initial_state = [0] * 16
        count = 0

        for index0 in range(7):
            for index1 in range(index0 + 1, 8):
                for index2 in range(index1 + 1, 9):
                    for index3 in range(index2 + 1, 10):
                        for index4 in range(index3 + 1, 11):
                            for index5 in range(index4 + 1, 12):
                                for index6 in range(index5 + 1, 13):
                                    for index7 in range(index6 + 1, 14):
                                        for index8 in range(index7 + 1, 15):
                                            for index9 in range(index8 + 1, 16):
                                                initial_state[index0] = 1
                                                initial_state[index1] = 1
                                                initial_state[index2] = 1
                                                initial_state[index3] = 1
                                                initial_state[index4] = 1
                                                initial_state[index5] = 1
                                                initial_state[index6] = 1
                                                initial_state[index7] = 1
                                                initial_state[index8] = 1
                                                initial_state[index9] = 1

                                                if self.debug:
                                                    print('{:3}: {}'.format(count, initial_state))

                                                states.append(initial_state)

                                                count += 1
                                                initial_state = [0] * 16

        return states

    def get_states_11(self):
        states = []
        initial_state = [0] * 16
        count = 0

        for index0 in range(6):
            for index1 in range(index0 + 1, 7):
                for index2 in range(index1 + 1, 8):
                    for index3 in range(index2 + 1, 9):
                        for index4 in range(index3 + 1, 10):
                            for index5 in range(index4 + 1, 11):
                                for index6 in range(index5 + 1, 12):
                                    for index7 in range(index6 + 1, 13):
                                        for index8 in range(index7 + 1, 14):
                                            for index9 in range(index8 + 1, 15):
                                                for index10 in range(index9 + 1, 16):
                                                    initial_state[index0] = 1
                                                    initial_state[index1] = 1
                                                    initial_state[index2] = 1
                                                    initial_state[index3] = 1
                                                    initial_state[index4] = 1
                                                    initial_state[index5] = 1
                                                    initial_state[index6] = 1
                                                    initial_state[index7] = 1
                                                    initial_state[index8] = 1
                                                    initial_state[index9] = 1
                                                    initial_state[index10] = 1

                                                    if self.debug:
                                                        print('{:3}: {}'.format(count, initial_state))

                                                    states.append(initial_state)

                                                    count += 1
                                                    initial_state = [0] * 16

        return states

    def get_states_12(self):
        states = []
        initial_state = [0] * 16
        count = 0

        for index0 in range(5):
            for index1 in range(index0 + 1, 6):
                for index2 in range(index1 + 1, 7):
                    for index3 in range(index2 + 1, 8):
                        for index4 in range(index3 + 1, 9):
                            for index5 in range(index4 + 1, 10):
                                for index6 in range(index5 + 1, 11):
                                    for index7 in range(index6 + 1, 12):
                                        for index8 in range(index7 + 1, 13):
                                            for index9 in range(index8 + 1, 14):
                                                for index10 in range(index9 + 1, 15):
                                                    for index11 in range(index10 + 1, 16):
                                                        initial_state[index0] = 1
                                                        initial_state[index1] = 1
                                                        initial_state[index2] = 1
                                                        initial_state[index3] = 1
                                                        initial_state[index4] = 1
                                                        initial_state[index5] = 1
                                                        initial_state[index6] = 1
                                                        initial_state[index7] = 1
                                                        initial_state[index8] = 1
                                                        initial_state[index9] = 1
                                                        initial_state[index10] = 1
                                                        initial_state[index11] = 1

                                                        if self.debug:
                                                            print('{:3}: {}'.format(count, initial_state))

                                                        states.append(initial_state)

                                                        count += 1
                                                        initial_state = [0] * 16

        return states

    def get_states_13(self):
        states = []
        initial_state = [0] * 16
        count = 0

        for index0 in range(4):
            for index1 in range(index0 + 1, 5):
                for index2 in range(index1 + 1, 6):
                    for index3 in range(index2 + 1, 7):
                        for index4 in range(index3 + 1, 8):
                            for index5 in range(index4 + 1, 9):
                                for index6 in range(index5 + 1, 10):
                                    for index7 in range(index6 + 1, 11):
                                        for index8 in range(index7 + 1, 12):
                                            for index9 in range(index8 + 1, 13):
                                                for index10 in range(index9 + 1, 14):
                                                    for index11 in range(index10 + 1, 15):
                                                        for index12 in range(index11 + 1, 16):
                                                            initial_state[index0] = 1
                                                            initial_state[index1] = 1
                                                            initial_state[index2] = 1
                                                            initial_state[index3] = 1
                                                            initial_state[index4] = 1
                                                            initial_state[index5] = 1
                                                            initial_state[index6] = 1
                                                            initial_state[index7] = 1
                                                            initial_state[index8] = 1
                                                            initial_state[index9] = 1
                                                            initial_state[index10] = 1
                                                            initial_state[index11] = 1
                                                            initial_state[index12] = 1

                                                            if self.debug:
                                                                print('{:3}: {}'.format(count, initial_state))

                                                            states.append(initial_state)

                                                            count += 1
                                                            initial_state = [0] * 16

        return states

    def get_states_14(self):
        states = []
        initial_state = [0] * 16
        count = 0

        for index0 in range(3):
            for index1 in range(index0 + 1, 4):
                for index2 in range(index1 + 1, 5):
                    for index3 in range(index2 + 1, 6):
                        for index4 in range(index3 + 1, 7):
                            for index5 in range(index4 + 1, 8):
                                for index6 in range(index5 + 1, 9):
                                    for index7 in range(index6 + 1, 10):
                                        for index8 in range(index7 + 1, 11):
                                            for index9 in range(index8 + 1, 12):
                                                for index10 in range(index9 + 1, 13):
                                                    for index11 in range(index10 + 1, 14):
                                                        for index12 in range(index11 + 1, 15):
                                                            for index13 in range(index12 + 1, 16):
                                                                initial_state[index0] = 1
                                                                initial_state[index1] = 1
                                                                initial_state[index2] = 1
                                                                initial_state[index3] = 1
                                                                initial_state[index4] = 1
                                                                initial_state[index5] = 1
                                                                initial_state[index6] = 1
                                                                initial_state[index7] = 1
                                                                initial_state[index8] = 1
                                                                initial_state[index9] = 1
                                                                initial_state[index10] = 1
                                                                initial_state[index11] = 1
                                                                initial_state[index12] = 1
                                                                initial_state[index13] = 1

                                                                if self.debug:
                                                                    print('{:3}: {}'.format(count, initial_state))

                                                                states.append(initial_state)

                                                                count += 1
                                                                initial_state = [0] * 16

        return states

    def get_states_15(self):
        states = []
        initial_state = [0] * 16
        count = 0

        for index0 in range(2):
            for index1 in range(index0 + 1, 3):
                for index2 in range(index1 + 1, 4):
                    for index3 in range(index2 + 1, 5):
                        for index4 in range(index3 + 1, 6):
                            for index5 in range(index4 + 1, 7):
                                for index6 in range(index5 + 1, 8):
                                    for index7 in range(index6 + 1, 9):
                                        for index8 in range(index7 + 1, 10):
                                            for index9 in range(index8 + 1, 11):
                                                for index10 in range(index9 + 1, 12):
                                                    for index11 in range(index10 + 1, 13):
                                                        for index12 in range(index11 + 1, 14):
                                                            for index13 in range(index12 + 1, 15):
                                                                for index14 in range(index13 + 1, 16):
                                                                    initial_state[index0] = 1
                                                                    initial_state[index1] = 1
                                                                    initial_state[index2] = 1
                                                                    initial_state[index3] = 1
                                                                    initial_state[index4] = 1
                                                                    initial_state[index5] = 1
                                                                    initial_state[index6] = 1
                                                                    initial_state[index7] = 1
                                                                    initial_state[index8] = 1
                                                                    initial_state[index9] = 1
                                                                    initial_state[index10] = 1
                                                                    initial_state[index11] = 1
                                                                    initial_state[index12] = 1
                                                                    initial_state[index13] = 1
                                                                    initial_state[index14] = 1

                                                                    if self.debug:
                                                                        print('{:3}: {}'.format(count, initial_state))

                                                                    states.append(initial_state)

                                                                    count += 1
                                                                    initial_state = [0] * 16

        return states

    def get_states_16(self):
        states = []
        initial_state = [1] * 16
        count = 0

        if self.debug:
            print('{:3}: {}'.format(count, initial_state))

        states.append(initial_state)

        return states

    @staticmethod
    def check_values(expected_value, actual_value):
        if expected_value == actual_value:
            print('OK!')
        else:
            print('WRONG! Expected {}, but got {}!'.format(expected_value, actual_value))

    def check_generated_states(self):
        total_generated_states = 0

        for i in range(17):
            states = self.get_states(i)

            generated_states = len(states)
            total_generated_states += generated_states

            print('{:2} bytes in control: {:8}. '.format(i, generated_states), end='')
            self.check_values(self.combinations(16, i), generated_states)

        print('Total generated states: {}. '.format(total_generated_states), end='')
        self.check_values(2 ** 16, total_generated_states)

        print()

    @staticmethod
    def statistics(evaluation_set):
        min_possible_keys = min(evaluation_set, key=operator.itemgetter(0, 1))
        max_possible_keys = max(evaluation_set, key=operator.itemgetter(0, 1))

        min_number_of_rounds = min(evaluation_set, key=operator.itemgetter(1, 0))
        max_number_of_rounds = max(evaluation_set, key=operator.itemgetter(1, 0))

        print('Possible Keys')
        print('\t MIN: {} (in {} rounds)'.format(min_possible_keys[0], min_possible_keys[1]))
        print('\t MAX: {} (in {} rounds)'.format(max_possible_keys[0], max_possible_keys[1]))

        print()

        print('Number of Rounds')
        print('\t MIN: {} ({} possible keys)'.format(min_number_of_rounds[1], min_number_of_rounds[0]))
        print('\t MAX: {} ({} possible keys)'.format(max_number_of_rounds[1], max_number_of_rounds[0]))

        print()

    @staticmethod
    def get_pair_index(pair, evaluation_set):
        for index, value in enumerate(evaluation_set):
            if pair == value:
                return index

        return -1

    def detailed_statistics(self, states, evaluation_set):
        # detailed_states = {pair : (state, occurrences of pair)}, where pair = (possible_keys, number_of_rounds)
        detailed_states = {}

        for pair in evaluation_set:
            found = False
            for i in detailed_states.keys():
                if i == pair:
                    found = True
                    break

            if not found:
                index = self.get_pair_index(pair, evaluation_set)
                detailed_states[pair] = (states[index], 1)
            else:
                detailed_states[pair] = (detailed_states[pair][0], detailed_states[pair][1] + 1)

        sorted_detailed_states = sorted(detailed_states.items(), key=operator.itemgetter(0))

        print('keys | \t rounds | \t occurrences | \t state')
        print('-' * 85)
        for i in sorted_detailed_states:
            print('{:4} | \t {:6} | \t {:11} | \t {}'.format(i[0][0], i[0][1], i[1][1], i[1][0]))

        print()

    def latex_statistics(self, states, evaluation_set, controlled_bytes):
        # detailed_states = {pair : (state, occurrences of pair)}, where pair = (possible_keys, number_of_rounds)
        detailed_states = {}

        for pair in evaluation_set:
            found = False
            for i in detailed_states.keys():
                if i == pair:
                    found = True
                    break

            if not found:
                index = self.get_pair_index(pair, evaluation_set)
                detailed_states[pair] = (states[index], 1)
            else:
                detailed_states[pair] = (detailed_states[pair][0], detailed_states[pair][1] + 1)

        sorted_detailed_states = sorted(detailed_states.items(), key=operator.itemgetter(0))

        combinations = self.combinations(16, controlled_bytes)
        f = open(self.latex_file_format.format(controlled_bytes), 'w')

        # \usepackage{booktabs}
        f.write('\\begin{table}\n')
        f.write('  \\caption{{Possible attack results when {} out of the 16 input bytes are controlled by attacker.}}'
                '\n'.format(controlled_bytes))
        f.write('  \\label{{tab:controlled_bytes_{}}}\n'.format(controlled_bytes))
        f.write('  \\begin{center}\n')
        f.write('    \\begin{tabular}{rrrr}\n')
        f.write('      \\toprule\n')
        f.write('      Keys & Rounds & \multicolumn{2}{c}{Possible States} \\\\\n')
        f.write('       &  & Occurrences & \% \\\\\n')
        f.write('      \\midrule\n')

        for i in sorted_detailed_states:
            f.write('      {} & {} & {} & {:.2f} \\\\\n'.format(i[0][0], i[0][1], i[1][1],
                                                                i[1][1] * 100 / combinations))

        f.write('      \\bottomrule\n')
        f.write('    \\end{tabular}\n')
        f.write('  \\end{center}\n')
        f.write('\\end{table}\n')

        f.close()

    def best_worst_statistics(self, states, evaluation_set, controlled_bytes):
        # detailed_states = {pair : (state, occurrences of pair)}, where pair = (possible_keys, number_of_rounds)
        detailed_states = {}

        for pair in evaluation_set:
            found = False
            for i in detailed_states.keys():
                if i == pair:
                    found = True
                    break

            if not found:
                index = self.get_pair_index(pair, evaluation_set)
                detailed_states[pair] = (states[index], 1)
            else:
                detailed_states[pair] = (detailed_states[pair][0], detailed_states[pair][1] + 1)

        combinations = self.combinations(16, controlled_bytes)

        sorted_detailed_states = []
        for key, value in detailed_states.items():
            sorted_detailed_states.append((key[0], key[1], value[1]))

        # min, max - keys
        sorted_detailed_states = sorted(sorted_detailed_states, key=operator.itemgetter(0, 1, 2))
        min_keys = min(sorted_detailed_states, key=operator.itemgetter(0))
        max_keys = max(sorted_detailed_states, key=operator.itemgetter(0))

        self.best_case_possible_keys.append((min_keys[0], min_keys[1], min_keys[2] * 100 / combinations))
        self.worst_case_possible_keys.append((max_keys[0], max_keys[1], max_keys[2] * 100 / combinations))

        # min, max - rounds
        sorted_detailed_states = sorted(sorted_detailed_states, key=operator.itemgetter(1, 0, 2))
        min_rounds = min(sorted_detailed_states, key=operator.itemgetter(1))
        max_rounds = max(sorted_detailed_states, key=operator.itemgetter(1))

        self.best_case_number_of_rounds.append((min_rounds[0], min_rounds[1], min_rounds[2] * 100 / combinations))
        self.worst_case_number_of_rounds.append((max_rounds[0], max_rounds[1], max_rounds[2] * 100 / combinations))

    @staticmethod
    def format_percent(percent):
        if 100 == percent:
            return int(percent)
        return '{:.2f}'.format(percent)

    def summary_latex_table(self, controlled_bytes):
        f = open(self.summary_latex_file, 'w')

        # \usepackage{booktabs}
        f.write('\\begin{table}\n')
        f.write('  \\caption{Best and worst possible attack outcomes for different number of bytes controlled by '
                'attacker.}\n')
        f.write('  \\label{tab:summary_attack_outcomes}\n')
        f.write('  \\tiny\n')
        f.write('  \\begin{center}\n')

        f.write('    \\begin{{tabular}}{{r|{}}}\n'.format('r' * len(controlled_bytes)))

        f.write('      \\toprule\n')

        f.write('      Bytes ')
        for i in controlled_bytes:
            f.write('& {} '.format(i))
        f.write('\\\\\n')

        # best case possible keys
        f.write('      \\midrule\n')

        f.write('      min(Keys) ')
        for i in self.best_case_possible_keys:
            f.write('& {} '.format(i[0]))
        f.write('\\\\\n')

        f.write('      Rounds ')
        for i in self.best_case_possible_keys:
            f.write('& {} '.format(i[1]))
        f.write('\\\\\n')

        f.write('      \% ')
        for i in self.best_case_possible_keys:
            f.write('& {} '.format(self.format_percent(i[2])))
        f.write('\\\\\n')

        # worst case possible keys
        f.write('      \\midrule\n')

        f.write('      max(Keys) ')
        for i in self.worst_case_possible_keys:
            f.write('& {} '.format(i[0]))
        f.write('\\\\\n')

        f.write('      Rounds ')
        for i in self.worst_case_possible_keys:
            f.write('& {} '.format(i[1]))
        f.write('\\\\\n')

        f.write('      \% ')
        for i in self.worst_case_possible_keys:
            f.write('& {} '.format(self.format_percent(i[2])))
        f.write('\\\\\n')

        # best case number of rounds
        f.write('      \\midrule\n')
        f.write('      \\midrule\n')

        f.write('      Keys ')
        for i in self.best_case_number_of_rounds:
            f.write('& {} '.format(i[0]))
        f.write('\\\\\n')

        f.write('      min(Rounds) ')
        for i in self.best_case_number_of_rounds:
            f.write('& {} '.format(i[1]))
        f.write('\\\\\n')

        f.write('      \% ')
        for i in self.best_case_number_of_rounds:
            f.write('& {} '.format(self.format_percent(i[2])))
        f.write('\\\\\n')

        # worst case number of rounds
        f.write('      \\midrule\n')

        f.write('      Keys ')
        for i in self.worst_case_number_of_rounds:
            f.write('& {} '.format(i[0]))
        f.write('\\\\\n')

        f.write('      max(Rounds) ')
        for i in self.worst_case_number_of_rounds:
            f.write('& {} '.format(i[1]))
        f.write('\\\\\n')

        f.write('      \% ')
        for i in self.worst_case_number_of_rounds:
            f.write('& {} '.format(self.format_percent(i[2])))
        f.write('\\\\\n')

        f.write('      \\bottomrule\n')
        f.write('    \\end{tabular}\n')
        f.write('  \\end{center}\n')
        f.write('\\end{table}\n')
        f.close()

    def run(self, controlled_bytes):
        for i in controlled_bytes:
            if 0 == i:
                continue

            states = self.get_states(i)

            evaluation_set = []

            for initial_state in states:
                evaluation_case_solver = EvaluationCaseSolver(initial_state)
                evaluation_case_solver.process()
                evaluation_result = evaluation_case_solver.get_statistics()

                evaluation_set.append(evaluation_result)

            print('Bytes in control: {:2}'.format(i))
            print('=' * 20)
            self.statistics(evaluation_set)
            self.detailed_statistics(states, evaluation_set)
            print('\n\n')

            self.latex_statistics(states, evaluation_set, i)
            self.best_worst_statistics(states, evaluation_set, i)

        self.summary_latex_table(controlled_bytes)


def main():
    controlled_bytes = range(1, 17)

    evaluator = Evaluator()
    evaluator.check_generated_states()
    evaluator.run(controlled_bytes)


if '__main__' == __name__:
    start_time = time.time()

    main()

    stop_time = time.time()

    print('Duration: {}'.format(time.strftime('%H:%M:%S', time.gmtime(stop_time - start_time))))
