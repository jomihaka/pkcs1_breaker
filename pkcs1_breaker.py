import sys
import random
import gmpy2


class Oracle:
    """This class should be implemented according to the specific situation"""
    OK = 0
    ERROR_PADDING_HEADER = 1

    def __call__(self, ciphertext):
        """Asks oracle a one question

        returns
            OK for good result
            ERROR_PADDING_HEADER if the first two bytes were incorrect"""
        raise NotImplementedError("This should be implemented")

class BB98_Attack:
    def __init__(self, n, e, ciphertext, oracle):
        self.n = n
        self.e = e
        self.c = OS2IP(ciphertext)
        self.oracle = oracle
        self.bits = n.bit_length()
        k = cdiv(self.bits, 8)
        self.B = pow(2, 8*(k-2))
        self.B2 = 2*self.B
        self.B3 = 3*self.B
        self.m = None
        self.queries = [0, 0, 0, 0]

    def find_message(self):
        if self.m == None:
            self._run()
        return I2OSP(self.m, self.bits)

    def stats(self):
        return "{}\n{}\n{}\n{}".format(
            "Step  1: {} total queries".format(self.queries[0]),
            "Step 2a: {} total queries".format(self.queries[1]),
            "Step 2b: {} total queries".format(self.queries[2]),
            "Step 2c: {} total queries".format(self.queries[3])
        )

    def _run(self):
        print("Working.", end='', file=sys.stderr, flush=True)
        c0, s0 = self._step_1()
        M = [(self.B2, self.B3 - 1)]
        print(".", end='', file=sys.stderr, flush=True)
        s = self._step_2a(c0)
        while True:
            print(".", end='', file=sys.stderr, flush=True)
            M = self._step_3(s, M)
            print(".", end='', file=sys.stderr, flush=True)
            if len(M) == 1:
                if M[0][0] == M[0][1]:
                    # step 4
                    self.m = divm(M[0][0], s0, self.n)
                    print(file=sys.stderr)
                    return
                s = self._step_2c(s, M, c0)
            else:
                s = self._step_2b(s, c0)

    def _step_1(self):
        # Theoretically the algorithm could loop here forever, if no good random s0 is found.
        # This is because the pseudorandom generator has finite precision
        # that we are extending for n-bits.
        # Unlikely of course (53-bits are a lot), but improvements would be nice.
        # E.g. it's not necessary to have the whole range [2,n] for tries
        # Also, if the message is not blinded, s0 = 1 will of course work
        s0 = 1
        while True:
            self.queries[0] += 1
            c0 = RSA_mult(self.n, self.e, self.c, s0)
            if self.oracle(I2OSP(c0, self.bits)) == Oracle.OK:
                return c0, s0
            s0 = random.randrange(2, self.n)

    def _step_2a(self, c0):
        s = cdiv(self.n, self.B3)
        while True:
            self.queries[1] += 1
            cs = RSA_mult(self.n, self.e, c0, s)
            if self.oracle(I2OSP(cs, self.bits)) == Oracle.OK:
                return s
            s += 1

    def _step_2b(self, s, c0):
        while True:
            self.queries[2] += 1
            s += 1
            c0s = RSA_mult(self.n, self.e, c0, s)
            if self.oracle(I2OSP(c0s, self.bits)) == Oracle.OK:
                return s

    def _step_2c(self, s, M, c0):
        a, b = M[0]
        r = cdiv(2*(b*s - self.B2), self.n)
        while True:
            s_first = cdiv((self.B2 + r*self.n), b)
            s_below = cdiv((self.B3 + r*self.n), a)
            for s in range(s_first, s_below):
                self.queries[3] += 1
                c0s = RSA_mult(self.n, self.e, c0, s)
                if self.oracle(I2OSP(c0s, self.bits)) == Oracle.OK:
                    return s
            r += 1

    def _step_3(self, s, M):
        M_new = []
        for a, b in M:
            r_first = cdiv((a*s - self.B3 + 1), self.n)
            r_last = fdiv((b*s - self.B2), self.n)
            for r in range(r_first, r_last + 1):
                low = max(a, cdiv((self.B2 + r*self.n), s))
                high = min(b, fdiv((self.B3 - 1 + r*self.n), s))
                if low <= high:
                    append_interval(M_new, (low, high))
        return M_new


### needed math
def divm(a, b, n):
    """Modular multiplicative inverse

    Return x such that b*x == a mod n.
    """
    return gmpy2.divm(a, b, n).__int__()

def cdiv(a, b):
    """Integer division with rounding towards +inf"""
    return gmpy2.c_div(a, b).__int__()

def fdiv(a, b):
    """Integer division with rounding towards -inf"""
    return a // b

### useful primitives from RFC 3447
def OS2IP(bytestr):
    return int.from_bytes(bytestr, byteorder='big')

def I2OSP(x, bits):
    return x.to_bytes(cdiv(bits, 8), byteorder='big')

def RSAEP(n, e, m):
    return pow(m, e, n)

def RSADP(n, d, c):
    return pow(c, d, n)

###
def RSA_mult(n, e, c, s):
    """The homomorphic multiplication of ciphertext c with s (as numbers)"""
    return (RSAEP(n, e, s) * c) % n

def append_interval(M, new):
    """Appends an interval to list M while keeping the list minimized"""
    while True:
        for i, val in enumerate(M):
            if val[1] < new[0] or new[1] < val[0]:
                continue
            new = (min(val[0], new[0]), max(val[1], new[1]))
            del M[i]
            break
        else:
            M.append(new)
            return

