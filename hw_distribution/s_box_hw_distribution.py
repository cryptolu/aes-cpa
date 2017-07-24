from aes_cipher.constants import s_box
from leakage_model.hw_s_box import HwSBox


import matplotlib.pyplot
import numpy
import time


class SBoxHwDistribution:
    def __init__(self):
        self.power_model = HwSBox()

        self.input_size = 8
        self.output_size = 8

        self.hw_distribution = None

    def get_key_distribution(self, key):
        self.hw_distribution = [0 for i in range(self.output_size + 1)]

        for i in range(2 ** self.input_size):
            intermediate = s_box[i ^ key]
            power = self.power_model.leak(intermediate)
            self.hw_distribution[power] += 1

        return self.hw_distribution

    def get_distribution(self):
        self.hw_distribution = [0 for i in range(self.output_size + 1)]

        for k in range(2 ** self.input_size):
            for i in range(2 ** self.input_size):
                intermediate = s_box[i ^ k]
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
        matplotlib.pyplot.xticks(numpy.arange(0, number_of_values, 1))

        matplotlib.pyplot.savefig('./output/{}.png'.format(title))
        matplotlib.pyplot.close()

    def print_distribution(self):
        print('Distribution')
        print('=' * 12)

        for i in range(self.output_size + 1):
            print('{}: {}'.format(i, self.hw_distribution[i]))

        print('-' * 12)

    def generate(self):
        self.get_distribution()
        self.plot('s_box')

        self.print_distribution()
        print('Symmetric: {}'.format(self.is_symmetric))


def main():
    distribution = SBoxHwDistribution()
    distribution.generate()


if "__main__" == __name__:
    start_time = time.time()

    main()

    stop_time = time.time()

    print('Duration: {}'.format(time.strftime('%H:%M:%S', time.gmtime(stop_time - start_time))))
