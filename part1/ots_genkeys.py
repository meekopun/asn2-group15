import os, hashlib

def chain_hash(data, w):
    """Applies the SHA-256 hash function to the input data w times."""
    for i in range(w):
        data = hashlib.sha256(data).digest()
    return data

def generate_private_key():
    """Generates num_key random private keys of key_size bytes, and applies the chain hash w times."""
    secret_keys = []
    for i in range(64):
        # Generate a random 32-byte secret key
        seed = os.urandom(32)
        secret_keys.append(seed)
    return secret_keys
        

if __name__ == "__main__":
    # Generate 64 random 32-byte secret keys
    sk = generate_private_key()
    
    # Save the private keys to a file in binary format
    with open("part1/private_key.ots", "wb") as f:
        for key in sk:
            f.write(key)
    
    # Generate the corresponding public keys by applying the chain hash w=16 times to each private key
    pk = []
    for key in sk:
        pk.append(chain_hash(key, 16))
        
    # Save the public keys to a file in binary format
    with open("part1/public_key.ots", "wb") as f:
        for key in pk:
            f.write(key)

