class SHA1():
    '''SHA1 Class'''

    def __init__(self):
        '''Computes SHA1 hashed value of given string'''
        self.f_funcs = [self.f1, self.f2, self.f3, self.f4]
        K = ['5A827999', '6ED9EBA1', '8F1BBCDC', 'CA62C1D6']
        self.K = list(map(self.hex2bin, K))


    def __str__(self):
        return 'SHA1 Computer'


    def add_mod(self, a, b):
        '''Addition modulo 2**32, returns the least 32 bytes of addition result'''
        added = '{:032b}'.format(int(a, 2) + int(b, 2))
        return added[-32:]


    def ascii2bin(self, string):
        '''Convert ascii string to bitstring'''
        return ''.join('{:08b}'.format(ord(char)) for char in string)


    def hex2bin(self, hx):
        '''Convert hex string to bitstring'''
        return ''.join('{:04b}'.format(int(h, 16)) for h in hx)


    def bin2hex(self, bn):
        '''Convert bitstring to hex string'''
        return ''.join('{:0x}'.format(int(bn[i:i + 4], 2)) for i in range(0, len(bn), 4))


    def pad(self, msg):
        '''Pad message with '1' followed by '0's'''
        bin_msg = self.ascii2bin(msg)
        l = len(bin_msg)
        # k = 512 - 64 - 1 - l
        k = 448 - (l + 1) % 512
        # padded output should be 512 bits
        padded = bin_msg + '1' + ('0' * k) + '{:064b}'.format(l)
        return padded


    def _split(self, message, size):
        '''Split data into blocks of given size'''
        return [message[i:i+size] for i in range(0, len(message), size)]


    def rol(self, word, shift):
        '''Rotate left word with given shift'''
        assert len(word) == 32
        return word[shift:] + word[:shift]


    def xor_2(self, a, b):
        '''Compute XOR value of given two binary strings'''
        return ''.join(['0' if x == y else '1' for x, y in zip(a, b)])


    def xor(self, *words):
        '''Compute XOR of multiple binary words'''
        first, *words = words
        res = first
        for word in words:
            res = self.xor_2(res, word)
        assert len(res) == len(first)
        return res


    def message_schedule(self, msg):
        ''' preprocess messag and return message schedule of given message'''

        # dividing the padded message
        msg_blocks = [msg[i:i + 32] for i in range(0, len(msg), 32)]
        assert len(msg_blocks) == 16

        # expanding message blocks
        schedule = []
        for j in range(0, 16):
            schedule.append(msg_blocks[j])

        for j in range(16, 80):
            word = self.xor(schedule[j - 16], schedule[j - 14], schedule[j - 8], schedule[j - 3])
            word = self.rol(word, 1)
            schedule.append(word)

        schedule = [schedule[i:i + 20] for i in range(0, len(schedule), 20)]
        assert len(schedule) == 4 and len(schedule[0]) == 20 and len(schedule[0][0]) == 32
        return schedule


    def f1(self, B, C, D):
        ''' f1 function used in stage1 (0 .. 19) rounds'''
        B = int(B, 2)
        C = int(C, 2)
        D = int(D, 2)
        # using alternate to avoid negation
        value = D ^ (B & (C ^ D))
        b_value = '{:032b}'.format(value)
        return b_value


    def f2(self, B, C, D):
        ''' f2 function used in stage2 (20 .. 39) rounds'''
        return self.xor(B, C, D)


    def f3(self, B, C, D):
        ''' f3 function used in stage3 (40 .. 59) rounds'''
        B = int(B, 2)
        C = int(C, 2)
        D = int(D, 2)
        value = (B & C) | (B & D) | (C & D)
        return '{:32b}'.format(value)


    def f4(self, B, C, D):
        ''' f4 function used in stage4 (60 .. 79) rounds'''
        return self.xor(B, C, D)


    def _round(self, data, t, msg):
        A, B, C, D, E = data
        assert len(A) == len(B) == len(C) == len(D) == len(E) == 32
        ft = self.f_funcs[t](B, C, D)
        assert len(ft) == 32

        add1 = self.add_mod(E, ft)
        add2 = self.add_mod(add1, self.rol(A, 5))
        add3 = self.add_mod(add2, msg)
        add4 = self.add_mod(add3, self.K[t])

        return [add4, A, self.rol(B, 30), C, D]


    def compression_function(self, message, data):
        '''Compression function with 80 rounds as in Merkle-Damgård construction'''
        initial = data
        schedule = self.message_schedule(message)
        for t in range(4):
            for j in range(20):
                data = self._round(data, t, schedule[t][j])

        data = list(map(self.add_mod, data, initial))
        return data


    def compute_hash(self, message):
        '''Compute SHA1 hash of given message'''
        padded = self.pad(message)
        message_blocks = self._split(padded, 512)

        # initial values of H0
        # A 160-bit buffer is used to hold the initial hash value for the first iteration.
        A = '67452301'
        B = 'EFCDAB89'
        C = '98BADCFE'
        D = '10325476'
        E = 'C3D2E1F0'

        initial_values = [A, B, C, D, E]
        # converting hex to bitstring
        initial_data = list(map(self.hex2bin, initial_values))
        data = initial_data

        for block in message_blocks:
            # computing hash of each block as in CBC mode
            data = self.compression_function(block, data)

        hashed = ''.join(data)
        hex_hash = self.bin2hex(hashed)
        return hex_hash

if __name__ == '__main__':
    hasher = SHA1()                 # initializing a SHA1 object
    # test words
    hash_these = [ 'Hello World!',
                   'Hello world!',
                   'Hello World,',
                   'Hello world,',
                   'hello world ',
                   'hello w0rld*',
                   'hello world.']

    for word in hash_these:
        hashed = hasher.compute_hash(word)
        print(word, hashed)
