from opcuapen.bisect import insertion_point

def test_insertion_point():
    lst = []
    lst.insert(insertion_point(-2, lst), -2)
    lst.insert(insertion_point(8, lst), 8)
    lst.insert(insertion_point(17, lst), 17)
    lst.insert(insertion_point(0, lst), 0)
    lst.insert(insertion_point(15, lst), 15)
    lst.insert(insertion_point(-30, lst), -30)
    lst.insert(insertion_point(15, lst), 15)
    
    # assert ascending order of the list
    for i in range(len(lst)-1):
        assert lst[i] <= lst[i+1]
