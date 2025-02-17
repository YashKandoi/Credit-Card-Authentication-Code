import random
import functions

class PrivateKey:
    """
    PrivateKey object contains lamda and meu
    in accordance to the Paillier Cryptosystem
    
    args:
        p: a prime number
        q: another prime number
        (p and q are of equal length)
        n: product of p and q
        
    attributes:
        lamda: lowest common multiple of p-1 and q-1
        ∵ p and q are of equal length we can use the simplification,
        meu: modular multiplicative inverse of lamda and n
    """
    
    def __init__(self, p, q, n):

        self.lamda = functions.lcm( p-1, q-1)
        self.meu = functions.multiplicative_inverse( self.lamda, n)
        
    def __repr__(self):
        return ("---\nPrivate Key :\nlamda:\t"+str(self.lamda) +"\nmeu:\t"+str(self.meu) +"\n---")
    

class PublicKey:
    """
    Public Key object contains n and g
    in accordance to the Paillier Cryptosystem
    
    args:
        n: product of two equal lenght prime numbers
    
    attributes:
        n: product of two primes
        g: a random number such that,
        multiplicative order of g in n^2 is a multiple of n
        
        ∵ p and q are of equal length we can use a simplification of g = n+1
    """
    def __init__(self, n):
        self.n = n
        self.nsq = n * n
        self.g = n+1
    
    def __repr__(self):
        return ("---\nPublic Key :\nn:\t"+ str(self.n) +"\n---")
    
def generate_keys():
    """
    
    returns Public Private key pair as a tuple from two large numbers prime numbers p and q of 313-digits
    (PublicKey, PrivateKey)
    """
    
    p = 3130000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001183811000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000313
    q = 3136666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666313
    n = p * q
    return (PublicKey(n), PrivateKey(p, q, n))

def Encrypt(public_key, plaintext):
    """
    Encrypt( public_key, plaintext)
    
    args:
        public_key: Paillier Publickey object
        plaintext: number to be encrypted
        
    returns:
        ciphertext: encryption of plaintext
        such that ciphertext = (g ^ plaintext) * (r ^ n) (mod n ^ 2)
        where, r is a random number in n such that r and n are coprime
    """
    
    r = random.randint( 1, public_key.n-1)
    while not functions.gcd(r, public_key.n) == 1:
        r = random.randint( 1, public_key.n)
        
    a = pow(public_key.g, plaintext, public_key.nsq)
    b = pow(r, public_key.n, public_key.nsq)
    
    ciphertext = (a * b) % public_key.nsq
    return ciphertext

def Decrypt(public_key, private_key, ciphertext):
    """
    Decrypt( publick_key, private_key, ciphertext)
    
    args:
        public_key: Paillier PublicKey object
        private_key: Paillier PrivateKey object
        ciphertext: Encrypted Integer which was ecnrypted using the public_key
        
    returns:
        plaintext: decryption of ciphertext
        such that plaintext = L(ciphertext ^ lamda) * meu (mod n ^ 2)
        where, L(x) = (x - 1) / n
    """
    
    x = pow(ciphertext, private_key.lamda, public_key.nsq)
    L = lambda x: (x - 1) // public_key.n
    
    plaintext = (L(x) * private_key.meu) % public_key.n 
    return plaintext

def homomorphic_add(public_key, a, b):
    """
    adds encrypted integer a to encrypted integer b 
    
    args:
        public_key
        encryption of integer a
        encryption of integer b
    returns:
        encryption of sum of a and b
    """
    return (a * b) % public_key.nsq

def homomorphic_mult_constant(public_key, a, k):
    """
    multiplies a plaintext k to encrypted integer a
    
    args:
        public_key
        encryption of integer a
        plaintext k
    returns:
        encryption of product of a and k
    """
    return pow(a, k, public_key.nsq)

def homomorphic_subtract(public_key, a, b):
    """
    Subtracts encrypted integer b from encrypted integer a 
    
    args:
        public_key: Paillier PublicKey object
        a: encryption of integer a
        b: encryption of integer b
    returns:
        encryption of the difference of a and b (a - b)
    """
    b_inverse = pow(b, public_key.n - 1, public_key.nsq)
    return (a * b_inverse) % public_key.nsq