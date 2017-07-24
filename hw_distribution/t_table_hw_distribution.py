from aes_cipher.constants import t0, t1, t2, t3
from leakage_model.hw_t_table import HwTTable


import matplotlib.pyplot
import numpy
import time


class TTableHwDistribution:
    def __init__(self, table_index=0):
        self.power_model = HwTTable()

        self.input_size = 8
        self.output_size = 32

        self.hw_distribution = None

        self.table = None
        self.init_table(table_index)

    def init_table(self, index):
        if 0 == index:
            self.table = t0
        elif 1 == index:
            self.table = t1
        elif 2 == index:
            self.table = t2
        elif 3 == index:
            self.table = t3

    def get_key_distribution(self, key):
        self.hw_distribution = [0 for i in range(self.output_size + 1)]

        for i in range(2 ** self.input_size):
            intermediate = self.table[i ^ key]
            power = self.power_model.leak(intermediate)
            self.hw_distribution[power] += 1

        return self.hw_distribution

    def get_distribution(self):
        self.hw_distribution = [0 for i in range(self.output_size + 1)]

        for k in range(2 ** self.input_size):
            for i in range(2 ** self.input_size):
                intermediate = self.table[i ^ k]
                power = self.power_model.leak(intermediate)
                self.hw_distribution[power] += 1

        return self.hw_distribution

    @property
    def is_symmetric(self):
        for i in range(self.output_size // 2):
            if self.hw_distribution[i] != self.hw_distribution[self.output_size - i]:
                return False
        return True

    def plot(self, title):
        number_of_values = len(self.hw_distribution)

        matplotlib.pyplot.bar(numpy.arange(number_of_values), self.hw_distribution, width=0.5, align='center')

        axes = matplotlib.pyplot.gca()
        axes.set_xlim([-1, number_of_values])
        matplotlib.pyplot.xticks(numpy.arange(0, number_of_values, 2))

        matplotlib.pyplot.savefig('./output/{}.png'.format(title))
        matplotlib.pyplot.close()

    def print_distribution(self, index):
        print('Distribution T{}'.format(index))
        print('=' * 15)

        for i in range(self.output_size + 1):
            print('{}: {}'.format(i, self.hw_distribution[i]))

        print('-' * 15)

    def generate(self):
        for i in range(4):
            self.init_table(i)
            self.get_distribution()
            self.plot('t_table_{}'.format(i))

            self.print_distribution(i)
            print('Symmetric: {}'.format(self.is_symmetric))
            print()


def main():
    distribution = TTableHwDistribution()
    distribution.generate()


if "__main__" == __name__:
    start_time = time.time()

    main()

    stop_time = time.time()

    print('Duration: {}'.format(time.strftime('%H:%M:%S', time.gmtime(stop_time - start_time))))
