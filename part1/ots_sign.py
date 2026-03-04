import os, hashlib, sys

def chain_hash(data, w):
    """Applies the SHA-256 hash function to the input data w times."""
    for i in range(w):
        data = hashlib.sha3_256(data).digest()
    return data

def main():
    message_file = sys.argv[1]
    private_key_file = sys.argv[2]
    
    message = open(message_file, "rb").read()
    hash_message = hashlib.sha3_256(message).digest()
    
    d = []
    for i in range(32):
        d.append((hash_message[i] >> 4) & 0x0F)  # Get the upper 4 bits
        d.append(hash_message[i] & 0x0F)         # Get the lower 4 bits
    
    # Read the private keys from the file
    with open(private_key_file, "rb") as f:
        private_keys = [f.read(32) for i in range(64)]
        
    signature = []
    for i in range(64):
        signature.append(chain_hash(private_keys[i], d[i]))
    
    # Write the signature to a file
    with open("signature.ots", "wb") as f:
        for h in signature:
            f.write(h)

if __name__ == "__main__":
    main()