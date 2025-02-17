import functions as func
import paillier_functions as paillier
import time

class User:
    def __init__(self, credit_card_number, session_id):
        self.Co = credit_card_number
        self.session_id = session_id
        self.Po = func.pseudo_random_number_generator(self.Co, self.session_id)
        self.Ho = func.sha256_hash(self.Po)
        self.C1 = self.Ho
        
    def generate_C2_and_K(self, operation):
        if operation == "add":
            self.K = 10
            self.C2 = self.C1 + self.K
        elif operation == "subtract":
            self.K = 10
            self.C2 = self.C1 - self.K
        elif operation == "divide":
            # Find smallest prime factor of C1 to use as K
            K = 2
            while K * K <= self.C1:
                if self.C1 % K == 0:
                    break
                K += 1 if K == 2 else 2
            if K * K > self.C1:
                K = self.C1
            self.K = K
            self.C2 = self.C1 // self.K
        return self.C2

class Retailer:
    def __init__(self):
        pass
        
    def receive_encrypted_C2(self, E1):
        self.E1 = E1
        return self.E1

class Bank:
    def __init__(self):
        start_time = time.time()
        self.public_key, self.private_key = paillier.generate_keys()
        self.key_gen_time = time.time() - start_time
        
    def store_C1(self, C1):
        self.C1 = C1
        start_time = time.time()
        self.Eo = paillier.Encrypt(self.public_key, self.C1)
        self.encryption_time = time.time() - start_time
        
    def generate_OTP(self, K):
        start_time = time.time()
        otp = paillier.Encrypt(self.public_key, K)
        self.otp_gen_time = time.time() - start_time
        return otp
        
    def verify_transaction(self, E1, OTP, operation):
        start_time = time.time()
        if operation == "add":
            homomorphic_start = time.time()
            diff_cipher_1 = paillier.homomorphic_subtract(self.public_key, E1, OTP)
            diff_cipher_2 = paillier.homomorphic_subtract(self.public_key, OTP, E1)
            self.homomorphic_time = time.time() - homomorphic_start
            
            decrypt_start = time.time()
            diff_plain_1 = paillier.Decrypt(self.public_key, self.private_key, diff_cipher_1)
            diff_plain_2 = paillier.Decrypt(self.public_key, self.private_key, diff_cipher_2)
            decrypted_Eo = paillier.Decrypt(self.public_key, self.private_key, self.Eo)
            self.decryption_time = time.time() - decrypt_start
            
            self.verification_time = time.time() - start_time
            return diff_plain_1 == decrypted_Eo or diff_plain_2 == decrypted_Eo
            
        elif operation == "subtract":
            homomorphic_start = time.time()
            add_cipher = paillier.homomorphic_add(self.public_key, E1, OTP)
            self.homomorphic_time = time.time() - homomorphic_start
            
            decrypt_start = time.time()
            add_plain = paillier.Decrypt(self.public_key, self.private_key, add_cipher)
            decrypted_Eo = paillier.Decrypt(self.public_key, self.private_key, self.Eo)
            self.decryption_time = time.time() - decrypt_start
            
            self.verification_time = time.time() - start_time
            return add_plain == decrypted_Eo
            
        elif operation == "divide":
            decrypt_start = time.time()
            K = paillier.Decrypt(self.public_key, self.private_key, OTP)
            self.decryption_time_otp = time.time() - decrypt_start
            
            homomorphic_start = time.time()
            mult_cipher = paillier.homomorphic_mult_constant(self.public_key, E1, K)
            self.homomorphic_time = time.time() - homomorphic_start
            
            decrypt_start = time.time()
            mult_plain = paillier.Decrypt(self.public_key, self.private_key, mult_cipher)
            decrypted_Eo = paillier.Decrypt(self.public_key, self.private_key, self.Eo)
            self.decryption_time = time.time() - decrypt_start
            
            self.verification_time = time.time() - start_time
            return mult_plain == decrypted_Eo

def main():
    # Lists to store timing data
    total_times = []
    key_gen_times = []
    initial_encryption_times = []
    c2_encryption_times = []
    otp_gen_times = []
    homomorphic_times = []
    decryption_times = []
    verification_times = []
    
    operation_list = ["add", "subtract", "divide"]
    operation = operation_list[0]
    print(f"\nSelected Operation: {operation}")
    
    for i in range(5):
        print(f"\nIteration {i+1}:")
        total_start_time = time.time()
        
        # Initialize entities
        user = User(12345678, 3)
        retailer = Retailer()
        bank = Bank()
        
        print(f"Credit Card Number (Co): {user.Co}")
        print(f"Session ID: {user.session_id}")
        print(f"Generated Pseudo-Random Number (Po): {user.Po}")
        print(f"Generated SHA 256 Hash (Ho): {user.Ho}")
        print(f"C1 = Ho: {user.C1}")
        
        key_gen_times.append(bank.key_gen_time)
        
        # Store C1 in bank
        bank.store_C1(user.C1)
        initial_encryption_times.append(bank.encryption_time)
        
        # User generates C2 and K
        C2 = user.generate_C2_and_K(operation)
        print(f"K value: {user.K}")
        print(f"C2 = {C2}")
        
        # Encrypt C2 for retailer
        encrypt_start = time.time()
        E1 = paillier.Encrypt(bank.public_key, C2)
        c2_encryption_times.append(time.time() - encrypt_start)
        
        # Retailer receives E1
        E1 = retailer.receive_encrypted_C2(E1)
        
        # Bank generates OTP
        OTP = bank.generate_OTP(user.K)
        otp_gen_times.append(bank.otp_gen_time)
        
        # Bank verifies transaction
        is_authentic = bank.verify_transaction(E1, OTP, operation)
        homomorphic_times.append(bank.homomorphic_time)
        decryption_times.append(bank.decryption_time)
        verification_times.append(bank.verification_time)
        
        total_times.append(time.time() - total_start_time)
        
        print("Authentication Check:")
        if is_authentic:
            print("Authentication Successful. Transaction can be processed")
        else:
            print("Authentication Denied")
    
    # Calculate and display averages
    print("\nAverage Timing Results:")
    print(f"Average Key Generation Time: {sum(key_gen_times)/5:.8f} seconds")
    print(f"Average Initial Encryption Time: {sum(initial_encryption_times)/5:.8f} seconds")
    print(f"Average C2 Encryption Time: {sum(c2_encryption_times)/5:.8f} seconds")
    print(f"Average OTP Generation Time: {sum(otp_gen_times)/5:.8f} seconds")
    print(f"Average Decryption Time: {sum(decryption_times)/5:.8f} seconds")
    print(f"Average Homomorphic Operation Time: {sum(homomorphic_times)/5:.8f} seconds")
    print(f"Average Verification Time: {sum(verification_times)/5:.8f} seconds")
    print(f"Average Total Transaction Time: {sum(total_times)/5:.8f} seconds")

main()