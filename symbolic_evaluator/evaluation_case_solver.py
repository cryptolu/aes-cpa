class EvaluationCaseSolver:
    def __init__(self, initial_state):
        self.state = [[0 for i in range(16)] for j in range(4)]
        self.pairs = [[[] for i in range(16)] for j in range(4)]

        self.pair_number = 0

        for i in range(16):
            self.state[0][i] = initial_state[i]

    def recovered(self, round_number):
        for i in range(16):
            if 0 >= self.state[round_number][i]:
                return False

        return True

    def variable_inputs(self, round_number, in_index0, in_index1, in_index2, in_index3):
        variable_inputs = 0

        if 0 != self.state[round_number - 1][in_index0]:
            variable_inputs += 1
        if 0 != self.state[round_number - 1][in_index1]:
            variable_inputs += 1
        if 0 != self.state[round_number - 1][in_index2]:
            variable_inputs += 1
        if 0 != self.state[round_number - 1][in_index3]:
            variable_inputs += 1

        return variable_inputs

    def independent_candidates(self, round_number, in_index0, in_index1, in_index2, in_index3):
        candidates = 1

        previous_pairs = self.combine_pairs(self.pairs[round_number - 1][in_index0],
                                            self.pairs[round_number - 1][in_index1],
                                            self.pairs[round_number - 1][in_index2],
                                            self.pairs[round_number - 1][in_index3])

        if 0 < len(previous_pairs):
            candidates = 2 ** len(previous_pairs)

        return candidates

    @staticmethod
    def combine_pairs(pair0, pair1, pair2='', pair3=''):
        pair0 = set(pair0)
        pair1 = set(pair1)
        pair2 = set(pair2)
        pair3 = set(pair3)

        new_pair = pair0.union(pair1)
        new_pair = new_pair.union(pair2)
        new_pair = new_pair.union(pair3)
        new_pair = list(new_pair)

        return new_pair

    def update(self, round_number, in_index0, in_index1, in_index2, in_index3,
               out_index0, out_index1, out_index2, out_index3):
        variable_inputs = self.variable_inputs(round_number, in_index0, in_index1, in_index2, in_index3)
        candidates = self.independent_candidates(round_number, in_index0, in_index1, in_index2, in_index3)

        previous_pairs = self.combine_pairs(self.pairs[round_number - 1][in_index0],
                                            self.pairs[round_number - 1][in_index1],
                                            self.pairs[round_number - 1][in_index2],
                                            self.pairs[round_number - 1][in_index3])

        self.pairs[round_number][out_index0] = previous_pairs
        self.pairs[round_number][out_index1] = previous_pairs
        self.pairs[round_number][out_index2] = previous_pairs
        self.pairs[round_number][out_index3] = previous_pairs

        if 0 == variable_inputs:
            self.state[round_number][out_index0] = 0
            self.state[round_number][out_index1] = 0
            self.state[round_number][out_index2] = 0
            self.state[round_number][out_index3] = 0
        elif 1 == variable_inputs:
            if 0 != self.state[round_number - 1][in_index0]:
                self.state[round_number][out_index0] = -1 * candidates
                self.state[round_number][out_index1] = -2 * candidates
                self.state[round_number][out_index2] = -2 * candidates
                self.state[round_number][out_index3] = -1 * candidates

                self.pair_number += 1
                self.pairs[round_number][out_index1] = self.combine_pairs(self.pairs[round_number][out_index1],
                                                                          [self.pair_number])
                self.pairs[round_number][out_index2] = self.combine_pairs(self.pairs[round_number][out_index2],
                                                                          [self.pair_number])
            if 0 != self.state[round_number - 1][in_index1]:
                self.state[round_number][out_index0] = -1 * candidates
                self.state[round_number][out_index1] = -1 * candidates
                self.state[round_number][out_index2] = -2 * candidates
                self.state[round_number][out_index3] = -2 * candidates

                self.pair_number += 1
                self.pairs[round_number][out_index2] = self.combine_pairs(self.pairs[round_number][out_index2],
                                                                          [self.pair_number])
                self.pairs[round_number][out_index3] = self.combine_pairs(self.pairs[round_number][out_index3],
                                                                          [self.pair_number])
            if 0 != self.state[round_number - 1][in_index2]:
                self.state[round_number][out_index0] = -2 * candidates
                self.state[round_number][out_index1] = -1 * candidates
                self.state[round_number][out_index2] = -1 * candidates
                self.state[round_number][out_index3] = -2 * candidates

                self.pair_number += 1
                self.pairs[round_number][out_index0] = self.combine_pairs(self.pairs[round_number][out_index0],
                                                                          [self.pair_number])
                self.pairs[round_number][out_index3] = self.combine_pairs(self.pairs[round_number][out_index3],
                                                                          [self.pair_number])
            if 0 != self.state[round_number - 1][in_index3]:
                self.state[round_number][out_index0] = -2 * candidates
                self.state[round_number][out_index1] = -2 * candidates
                self.state[round_number][out_index2] = -1 * candidates
                self.state[round_number][out_index3] = -1 * candidates

                self.pair_number += 1
                self.pairs[round_number][out_index0] = self.combine_pairs(self.pairs[round_number][out_index0],
                                                                          [self.pair_number])
                self.pairs[round_number][out_index1] = self.combine_pairs(self.pairs[round_number][out_index1],
                                                                          [self.pair_number])
        elif variable_inputs in [2, 3]:
            self.state[round_number][out_index0] = -1
            self.state[round_number][out_index1] = -1
            self.state[round_number][out_index2] = -1
            self.state[round_number][out_index3] = -1
        elif 4 == variable_inputs:
            self.state[round_number][out_index0] = 1
            self.state[round_number][out_index1] = 1
            self.state[round_number][out_index2] = 1
            self.state[round_number][out_index3] = 1

    def attack(self, round_number):
        if 0 == round_number:
            return

        self.update(round_number, 0, 5, 10, 15, 0, 1, 2, 3)
        self.update(round_number, 4, 9, 14, 3, 4, 5, 6, 7)
        self.update(round_number, 8, 13, 2, 7, 8, 9, 10, 11)
        self.update(round_number, 12, 1, 6, 11, 12, 13, 14, 15)

    def process(self):
        round_number = 0

        while True:
            self.attack(round_number)

            if self.recovered(round_number):
                break
            round_number += 1

    def get_possible_keys(self, i):
        return self.state[i][0]

    def get_statistics(self):
        possible_keys = -1
        number_of_rounds = -1

        for i in range(3, -1, -1):
            if self.recovered(i):
                possible_keys = self.get_possible_keys(i)
                number_of_rounds = i + 1
                break

        return possible_keys, number_of_rounds

    def max_possible_keys(self, pairs):
        pair1 = self.combine_pairs(pairs[0], pairs[1], pairs[2], pairs[3])
        pair2 = self.combine_pairs(pairs[4], pairs[5], pairs[6], pairs[7])
        pair3 = self.combine_pairs(pairs[8], pairs[9], pairs[10], pairs[11])
        pair4 = self.combine_pairs(pairs[12], pairs[13], pairs[14], pairs[15])
        independent_pairs = self.combine_pairs(pair1, pair2, pair3, pair4)

        return 2 ** len(independent_pairs)

    def get_max_possible_keys(self):
        for i in range(3, -1, -1):
            if self.recovered(i):
                return self.max_possible_keys(self.pairs[i])

        return -1

    def print_state(self, round_number=-1):
        if -1 == round_number:
            for i in range(4):
                self.print_state(i)
            return

        print('round {}: state'.format(round_number), end='')
        for i in range(4):
            print('\n\t', end='')
            for j in range(4):
                print('{:2} '.format(self.state[round_number][i + 4 * j]), end='')
        print()

    def print_pairs(self, round_number=-1):
        if -1 == round_number:
            for i in range(4):
                self.print_pairs(i)
            return

        print('round {}: pairs'.format(round_number), end='')
        for i in range(4):
            print('\n\t', end='')
            for j in range(4):
                print('{} '.format(self.pairs[round_number][i + 4 * j]), end='')
        print()

    def print_state_pairs(self, round_number=-1):
        if -1 == round_number:
            for i in range(4):
                self.print_state_pairs(i)
            return

        print('round {}: state \t\t\t pairs'.format(round_number), end='')
        for i in range(4):
            print('\n\t', end='')
            for j in range(4):
                print('{:2} '.format(self.state[round_number][i + 4 * j]), end='')
            print('\t ', end='')
            for j in range(4):
                print('{} '.format(self.pairs[round_number][i + 4 * j]), end='')
        print()

    def get_pair_indexes(self, pair, round_number):
        indexes = []

        for i in range(16):
            if pair in set(self.pairs[round_number][i]):
                indexes.append(16 * round_number + i)

        return indexes


def main():
    initial_state = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

    evaluation_case = EvaluationCaseSolver(initial_state)
    evaluation_case.process()

    # evaluation_case.print_state()
    # evaluation_case.print_pairs()
    evaluation_case.print_state_pairs()

    print()
    print('(keys, rounds) = {}'.format(evaluation_case.get_statistics()))


if "__main__" == __name__:
    main()
