import matplotlib
import matplotlib.pyplot


class Plotter:
    def __init__(self):
        # Force matplotlib to not use any Xwindows backend.
        # Details: http://stackoverflow.com/questions/2801882/generating-a-png-with-matplotlib-when-display-is-undefined
        matplotlib.use('Agg')

    @staticmethod
    def plot_correlation_matrix(correlation_matrix, index, expected_key, possible_key_count):
        for i in range(correlation_matrix.shape[0]):
            matplotlib.pyplot.plot(correlation_matrix[i], 'g')

        matplotlib.pyplot.plot(correlation_matrix[expected_key], 'r')

        matplotlib.pyplot.title('Correlation Matrix')
        matplotlib.pyplot.xlabel('Sample')
        matplotlib.pyplot.ylabel('Correlation')

        axes = matplotlib.pyplot.gca()
        axes.set_xlim(0, correlation_matrix.shape[1])

        correlation_matrix_file = 'output/CM_{:02}_{}.png'.format(index, possible_key_count)
        matplotlib.pyplot.savefig(correlation_matrix_file, bbox_inches='tight')
        matplotlib.pyplot.close()

    @staticmethod
    def plot_guessing_entropy(title, x_traces, y_guessing_entropy):
        Plotter.plot_guessing_entropy_short(title, x_traces, y_guessing_entropy)
        Plotter.plot_guessing_entropy_long(title, x_traces, y_guessing_entropy)

    @staticmethod
    def plot_guessing_entropy_short(title, x_traces, y_guessing_entropy):
        matplotlib.pyplot.plot(x_traces, y_guessing_entropy, linewidth=2.0, color='r', marker='x', markersize=10)
        matplotlib.pyplot.axhline(y=0, color='k', ls='dashed')

        # matplotlib.pyplot.title('GE - {}'.format(title))
        matplotlib.pyplot.xlabel('Traces')
        matplotlib.pyplot.ylabel('GE')

        axes = matplotlib.pyplot.gca()
        axes.set_ylim([-1, 10])

        matplotlib.pyplot.savefig('./output/GE_short_{}.png'.format(title), bbox_inches='tight')
        matplotlib.pyplot.close()

    @staticmethod
    def plot_guessing_entropy_long(title, x_traces, y_guessing_entropy):
        matplotlib.pyplot.plot(x_traces, y_guessing_entropy, linewidth=2.0, color='r', marker='x', markersize=10)
        matplotlib.pyplot.axhline(y=0, color='k', ls='dashed')

        # matplotlib.pyplot.title('GE - {}'.format(title))
        matplotlib.pyplot.xlabel('Traces')
        matplotlib.pyplot.ylabel('GE')

        axes = matplotlib.pyplot.gca()
        axes.set_ylim([-1, 128])

        matplotlib.pyplot.savefig('./output/GE_long_{}.png'.format(title), bbox_inches='tight')
        matplotlib.pyplot.close()
