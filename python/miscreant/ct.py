"""ct.py: Constant time(ish) functions"""

def select(subject, result_if_one, result_if_zero):
    """Perform a constant time(-ish) branch operation"""
    return (~(subject - 1) & result_if_one) | ((subject - 1) & result_if_zero)
