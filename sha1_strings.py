
def add_mod(a, b):
    added = '{:032b}'.format(int(a, 2) + int(b, 2))
    return added[-32:]


def ascii2bin(string):
    return ''.join('{:08b}'.format(ord(char)) for char in string)


def hex2bin(hx):
    return ''.join('{:04b}'.format(int(h, 16)) for h in hx)


def bin2hex(bn):
    return ''.join('{:0x}'.format(int(bn[i:i + 4], 2)) for i in range(0, len(bn), 4))


def pad(msg):
    bin_msg = ascii2bin(msg)
    l = len(bin_msg)
    # k = 512 - 64 - 1 - l
    k = 448 - (l + 1) % 512
    # padded output should be 512 bits
    padded = bin_msg + '1' + ('0' * k) + '{:064b}'.format(l)
    return padded


def rol(word, shift):
    assert len(word) == 32
    return word[shift:] + word[:shift]


def xor_2(a, b):
    '''Computes XOR for given two binary words'''
    return ''.join(['0' if x == y else '1' for x, y in zip(a, b)])


def xor(*words):
    '''Compute XOR of multiple binary words'''
    first, *words = words
    res = first
    for word in words:
        res = xor_2(res, word)
    assert len(res) == len(first)
    return res


def message_schedule(msg):

    # dividing the padded message
    msg_blocks = [msg[i:i + 32] for i in range(0, len(msg), 32)]
    assert len(msg_blocks) == 16

    # expanding message blocks
    schedule = []
    for j in range(0, 16):
        schedule.append(msg_blocks[j])

    for j in range(16, 80):
        word = xor(schedule[j - 16], schedule[j - 14], schedule[j - 8], schedule[j - 3])
        word = rol(word, 1)
        schedule.append(word)

    schedule = [schedule[i:i + 20] for i in range(0, len(schedule), 20)]
    assert len(schedule) == 4 and len(schedule[0]) == 20 and len(schedule[0][0]) == 32
    return schedule


def f1(B, C, D):
    B = int(B, 2)
    C = int(C, 2)
    D = int(D, 2)
    # using alternate to avoid negation
    value = D ^ (B & (C ^ D))
    b_value = '{:032b}'.format(value)
    return b_value


def f2(B, C, D):
    return xor(B, C, D)


def f3(B, C, D):
    B = int(B, 2)
    C = int(C, 2)
    D = int(D, 2)
    value = (B & C) | (B & D) | (C & D)
    return '{:32b}'.format(value)


def f4(B, C, D):
    return xor(B, C, D)


f_funcs = [f1, f2, f3, f4]
K = ['5A827999', '6ED9EBA1', '8F1BBCDC', 'CA62C1D6']
K = list(map(hex2bin, K))
assert len(K) == 4


def _round(data, t, msg):
    A, B, C, D, E = data
    assert len(A) == len(B) == len(C) == len(D) == len(E) == 32
    ft = f_funcs[t](B, C, D)
    assert len(ft) == 32

    add1 = add_mod(E, ft)
    add2 = add_mod(add1, rol(A, 5))
    add3 = add_mod(add2, msg)
    add4 = add_mod(add3, K[t])

    return [add4, A, rol(B, 30), C, D]



# initial values of H0
# A 160-bit buffer is used to hold the initial hash value for the first iteration.
A = '67452301'
B = 'EFCDAB89'
C = '98BADCFE'
D = '10325476'
E = 'C3D2E1F0'

initial_values = [A, B, C, D, E]
initial_data = list(map(hex2bin, initial_values))
data = initial_data


def compression_function(message, data):
    initial = data
    schedule = message_schedule(message)
    for t in range(4):
        for j in range(20):
            data = _round(data, t, schedule[t][j])

    data = list(map(add_mod, data, initial))
    return data


hash_this = input('Enter string to hash with SHA-1: ')
padded = pad(hash_this)
blocks = [padded[i:i + 512] for i in range(0, len(padded), 512)]


for block in blocks:
    data = compression_function(block, data)

data = ''.join(data)
hash_value = bin2hex(data)
print('SHA-1 result:', hash_value)
