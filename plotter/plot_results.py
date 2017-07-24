import numpy
import matplotlib.pyplot


# \varphi_1 = S-box selection function
# \varphi_2 = T-table selection function

# (a) S-box implementation, S-box selection function
# (b) S-box implementation, T-table selection function
# (c) T-table implementation, T-table selection function
# (d) T-table implementation, S-box selection function


# Simulated - Implementation - Selection function
# 100 experiments
sim_s_box_s_box = numpy.array([
    20, 15, 14, 24, 13, 15, 14, 20, 11, 14, 11, 11, 10, 11, 12, 10, 10, 10, 11, 11, 11, 11, 11, 10, 10])
sim_s_box_t_table = numpy.array([
    34, 28, 32, 33, 31, 37, 33, 35, 39, 42, 32, 30, 33, 35, 39, 29, 33, 37, 33, 29, 39, 40, 35, 33, 30])

sim_t_table_t_table = numpy.array([
    19, 13, 16, 19, 19, 21, 12, 17, 8, 13, 8, 7, 7, 7, 7, 8, 8, 9, 9, 7, 9, 8, 8, 8, 7])
sim_t_table_s_box = numpy.array([
    40, 30, 29, 39, 33, 38, 35, 34, 40, 32, 40, 39, 36, 32, 33, 34, 35, 34, 32, 31, 39, 42, 37, 32, 30])


# Real - Implementation - Selection function
real_s_box_s_box = numpy.array([
    700, 620, 80, 430, 570, 390, 520, 280, 620, 380, 500, 500, 490, 410, 670, 430, 570, 380, 400, 420, 530, 490, 350,
    510, 240])
real_s_box_t_table = numpy.array([960, 760, 100, 700, 760, 660, 730, 540, 900, 590, 780, 570, 730, 670, 870, 500, 790,
                                  560, 590, 650, 910, 620, 670, 650, 310])

real_t_table_t_table = numpy.array([
    630, 600, 180, 790, 300, 820, 390, 790, 910, 800, 800, 640, 660, 1010, 800, 830, 1000, 780, 790, 820, 790, 720,
    640, 810, 590])
real_t_table_s_box = numpy.array([1120, 490, 80, 1060, 160, 1140, 690, 1290, 1170, 1160, 1190, 1220, 1590, 1240, 1210,
                                  1150, 1440, 1050, 1420, 990, 1460, 1130, 1200, 1200, 890])


def plot_short(line1, line2, name):
    ls_box_phi1 = matplotlib.pyplot.plot(line1, 'ro-')
    ls_box_phi2 = matplotlib.pyplot.plot(line2, 'go-')

    axes = matplotlib.pyplot.gca()
    axes.set_xlim([0, 24])
    axes.set_xticks(list(range(0, 24 + 1, 1)))

    matplotlib.pyplot.grid()

    fig = matplotlib.pyplot.gcf()
    fig.set_size_inches(11, 4)

    matplotlib.pyplot.legend([ls_box_phi1[0], ls_box_phi2[0]], ['$\\varphi_1$', '$\\varphi_2$'])

    matplotlib.pyplot.xlabel('Evaluation case')
    matplotlib.pyplot.ylabel('Number of traces')

    matplotlib.pyplot.savefig('./output/{}.png'.format(name), bbox_inches='tight')
    matplotlib.pyplot.close()


def plot(line1, line2, line3, line4, name):
    matplotlib.pyplot.plot(line1, 'ro-', label='(a)')
    matplotlib.pyplot.plot(line2, 'go-', label='(b)')

    matplotlib.pyplot.plot(line3, 'bo-', label='(c)')
    matplotlib.pyplot.plot(line4, 'yo-', label='(d)')

    axes = matplotlib.pyplot.gca()
    axes.set_xlim([0, 24])
    axes.set_xticks(list(range(0, 24 + 1, 1)))

    matplotlib.pyplot.grid()

    fig = matplotlib.pyplot.gcf()
    fig.set_size_inches(11, 4)

    matplotlib.pyplot.legend(bbox_to_anchor=(0., 1.02, 1., .102), loc=3, ncol=4, mode="expand", borderaxespad=0.)

    matplotlib.pyplot.xlabel('Evaluation case')
    matplotlib.pyplot.ylabel('Number of traces')

    matplotlib.pyplot.savefig('./output/{}.png'.format(name), bbox_inches='tight')
    matplotlib.pyplot.close()


def diff(line1, line2):
    difference = line2 - line1
    mean = numpy.mean(difference)

    print('Difference: {}'.format(difference))
    print('Mean: {}'.format(mean))


def get_avg():
    print('Simulated')
    print('Avg (a): {}'.format(int(round(numpy.mean(sim_s_box_s_box)))))
    print('Min    : {}'.format(numpy.amin(sim_s_box_s_box)))
    print('Max    : {}'.format(numpy.amax(sim_s_box_s_box)))

    print('Avg (b): {}'.format(int(round(numpy.mean(sim_s_box_t_table)))))
    print('Min    : {}'.format(numpy.amin(sim_s_box_t_table)))
    print('Max    : {}'.format(numpy.amax(sim_s_box_t_table)))

    print('Avg (c): {}'.format(int(round(numpy.mean(sim_t_table_t_table)))))
    print('Min    : {}'.format(numpy.amin(sim_t_table_t_table)))
    print('Max    : {}'.format(numpy.amax(sim_t_table_t_table)))

    print('Avg (d): {}'.format(int(round(numpy.mean(sim_t_table_s_box)))))
    print('Min    : {}'.format(numpy.amin(sim_t_table_s_box)))
    print('Max    : {}'.format(numpy.amax(sim_t_table_s_box)))

    print()

    print('Real')
    print('Avg (a): {}'.format(int(round(numpy.mean(real_s_box_s_box)))))
    print('Min    : {}'.format(numpy.amin(real_s_box_s_box)))
    print('Max    : {}'.format(numpy.amax(real_s_box_s_box)))

    print('Avg (b): {}'.format(int(round(numpy.mean(real_s_box_t_table)))))
    print('Min    : {}'.format(numpy.amin(real_s_box_t_table)))
    print('Max    : {}'.format(numpy.amax(real_s_box_t_table)))

    print('Avg (c): {}'.format(int(round(numpy.mean(real_t_table_t_table)))))
    print('Min    : {}'.format(numpy.amin(real_t_table_t_table)))
    print('Max    : {}'.format(numpy.amax(real_t_table_t_table)))

    print('Avg (d): {}'.format(int(round(numpy.mean(real_t_table_s_box)))))
    print('Min    : {}'.format(numpy.amin(real_t_table_s_box)))
    print('Max    : {}'.format(numpy.amax(real_t_table_s_box)))

    print()


def get_statistics():
    print('Simulated S-box')
    diff(sim_s_box_s_box, sim_s_box_t_table)
    print()

    print('Simulated T-table')
    diff(sim_t_table_t_table, sim_t_table_s_box)
    print()

    print('Real S-box')
    diff(real_s_box_s_box, real_s_box_t_table)
    print()

    print('Real T-table')
    diff(real_t_table_t_table, real_t_table_s_box)
    print()


def main():
    get_avg()
    get_statistics()

    plot_short(sim_s_box_s_box, sim_s_box_t_table, 'simulated_s_box')
    plot_short(sim_t_table_s_box, sim_t_table_t_table, 'simulated_t_table')

    plot_short(real_s_box_s_box, real_s_box_t_table, 'real_s_box')
    plot_short(real_t_table_s_box, real_t_table_t_table, 'real_t_table')

    plot(sim_s_box_s_box, sim_s_box_t_table, sim_t_table_t_table, sim_t_table_s_box, 'simulated')
    plot(real_s_box_s_box, real_s_box_t_table, real_t_table_t_table, real_t_table_s_box, 'real')


if "__main__" == __name__:
    main()
