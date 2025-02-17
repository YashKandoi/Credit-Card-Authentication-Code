import math
import hashlib

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def lcm(a, b):
    """
    lcm(a, b)

    returns Lowest Common Multiple of a and b
    """
    return (a * b) // gcd(a, b)

def multiplicative_inverse(a, modulus):
    """
    multiplicative_inverse(a, modulus)

    returns x: multiplicative inverse of a
    such that, a * x = 1 (mod modulus)
    """
    if math.gcd(a, modulus) != 1:
        raise Exception('modular inverse does not exist')
    else:
        return pow(a, -1, modulus)
    

def pseudo_random_number_generator(seed, iterations, max_value=99999999):
    """
    Blum Blum Shub pseudo-random number generator
    
    args:
        seed: initial seed value
        max_value: maximum value for the generated number (exclusive)
        iterations: Number of iterations the generator will perform
    
    returns:
        A pseudo-random integer between 0 (inclusive) and max_value (exclusive)
    """
    # Use the given primes
    p = 2131131137
    q = 8106089891
    n = p * q
    
    seed = seed % n
    if math.gcd(seed, n) != 1:
        seed += 1
    
    x = seed
    for _ in range(iterations):
        x = pow(x, 2, n)
    
    result = x % max_value
    
    return result

def sha256_hash(number):
    """
    Compute the SHA-256 hash of a given number
    
    args:
        number: The input number to be hashed
    
    returns:
        A decimal integer representation of the SHA-256 hash
    """
    # Convert the number to a byte string
    number_bytes = str(number).encode('utf-8')
    
    # Create a SHA-256 hash object
    sha256 = hashlib.sha256()
    
    # Update the hash object with the byte string
    sha256.update(number_bytes)
    
    # Get the decimal representation of the hash
    hash_decimal = int.from_bytes(sha256.digest(), byteorder='big')
    
    return hash_decimal