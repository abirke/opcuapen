"""
Module for utility functions
"""

import logging


logger = logging.getLogger(__name__)

def compare_intervals(int1, int2):
    """ Check if two intervals overlap

    :param int1: one interval
    :param int2: another interval
    :return: string describing the overlap
    """
    (left1, right1) = int1
    (left2, right2) = int2
    if left1 > right1 or left2 > right2:
        return 'No valid intervals'

    left1_inner = left2 <= left1 <= right2
    right1_inner = left2 <= right1 <= right2

    output = ''

    if left1_inner and right1_inner:
        output = 'inside'
    if not left1_inner and not right1_inner:
        if left1 <= left2 and right1 >= right2:
            output = 'surrounding'
        if left1 <= left2:
            output = 'outside left'
        if right1 >= right2:
            output = 'outside right'
    if left1_inner:
        output = 'half-out right'
    if right1_inner:
        output = 'half-out left'
    return output

def print_byte_string(byte_string, logfct=None):
    """ Print a byte string

    :param byte_string: byte string to print
    :param logfct: log function to use instead of logger.debug
    """
    log_str = ' '.join(['{:02x}'.format(single_byte) for single_byte in byte_string])
    if not logfct:
        logger.debug(log_str)
    else:
        logfct(log_str)

def merge_intervals(previous_intervals, new_intervals):
    """ Merge two sets of intervals and return pairwise intersections

    :param previous_intervals: existing set of intervals
    :param new_intervals: new set of intervals
    :return: set of intervals containing pairwise intersections
    """
    Mnext = set()

    # Keep only intervals which are compatible with previous intervals
    for MMnew in new_intervals:
        anew, bnew = MMnew
        for MM in previous_intervals:
            a, b = MM
            if (bnew >= a and bnew <= b) \
                or (anew >= a and anew <= b) \
                or (anew >= a and bnew <= b and anew <= bnew) \
                or (anew <= a and bnew >= b):
                Mnext.add((max([a, anew]), min([b, bnew])))
    return Mnext

def find_bounds_from_s(intervals, N, B, s):
    """ Find bounds for the s variable

    :param intervals: intervals found so far
    :param N: RSA modulus
    :param B: :math:`2^{8*(k-2)}`
    :param s: value of s
    :return: new intervals that are compatible with existing ones
    """
    Mnew = set()
    # Use that 2*B+r*N <= ms <= 3*B-1+r*N
    # is equivalent to (a*s-3*B-1)/N <= r <= (b*s-2*B)/N
    # 3.
    for MM in intervals:
        a, b = MM
        rmax = (b * s - 2 * B) // N
        rmin = -(-(a * s - 3 * B - 1) // N)
        # for all possible pairs (s,r) we obtain bounds
        # (2*B+r*N)/s) <= m <= (3*B+1+r*N)/s) on m.
        # Add bounds only if they make sense, i.e., if a < b.
        for r in range(rmin, rmax + 1):
            anew = (2 * B + r * N) // s
            # floor the division
            bnew = -(-(3 * B - 1 + r * N) // s)
            if anew < bnew:
                Mnew.add((anew, bnew))
    return Mnew
