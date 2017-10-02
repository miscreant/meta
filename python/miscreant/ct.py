"""ct.py: Constant time(ish) functions"""

# WARNING: Pure Python is not amenable to the implementation of truly
# constant time cryptography. For more information, please see the
# "Security Notice" section in python/README.md.

def select(subject, result_if_one, result_if_zero):
    """Perform a constant time(-ish) branch operation"""
    return (~(subject - 1) & result_if_one) | ((subject - 1) & result_if_zero)
