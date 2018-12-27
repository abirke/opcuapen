"""
Module for bisection utility functions
"""

def insertion_point(new, x, before=None):
    """ Find insertion point in a list using bisection

    :param new: element to insert
    :param x: list to insert into
    :param before: _smaller than_-function taking to elements of the list
    :return: list index at which to insert the element
    """
    if not before:
        before = lambda x, y: x < y

    a = 0
    b = len(x)

    while a < b:
        c = (a+b) // 2
        if before(x[c], new):
            a = c+1
        else:
            b = c
    return a
