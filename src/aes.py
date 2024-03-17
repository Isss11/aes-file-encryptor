from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
import sys

# This is the functionality to implement the 3 desired functions.

# Valid Argument Counts
requiredArguments = {
    "keygen": 3,
    "enc": 5,
    "dec": 5
}

# Default IV Path
ivPath = "../data/iv.txt"

# Generates a Secret Key using AES and writes it to the specified file.
def keygen(keyPath):
    # Generates a random key of 32 bytes (256 bits)
    sk = get_random_bytes(32)
    
    print(sk.hex())
    
    writeValues(sk.hex(), keyPath) 
  
# Reads a secret key from the specified file, generates an IV and encrypts the the plaintext from the specified file to ciphertext, and stores 
# that in the specified ciphertext file.   
def enc(keyPath, plaintextPath, ciphertextPath):
    sk = bytes.fromhex(readValues(keyPath))
    
    # Generate IV and write it to the file (must be 16 bytes in pycryptodome for MODE_CBC)
    iv = get_random_bytes(16)
    
    writeValues(iv.hex(), ivPath)
    
    # Create cipher
    cipher = AES.new(sk, AES.MODE_CBC, iv=iv)
    
    # Perform Encryption on Specified Plaintext
    plaintext = readValues(plaintextPath)
    
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), 16))
    
    writeValues(ciphertext.hex(), ciphertextPath)
    
# Reads a secret key from the specified file, an IV from the specified file, and a ciphertext from the specified file and then outputs a plaintext 
# file with the decrypted ciphertext (should be back to original plaintext).
def dec(keyPath, ciphertextPath, resultPlaintextPath):
    # Read in secret key, initialization vector and ciphertext as byte values
    sk = bytes.fromhex(readValues(keyPath))
    iv = bytes.fromhex(readValues(ivPath))
    ciphertext = bytes.fromhex(readValues(ciphertextPath))
    
    cipher = AES.new(sk, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), 16).decode('UTF-8')
    
    # Write string version of bytes to file
    fp = open(resultPlaintextPath, "w")
    fp.write(str(plaintext))
    fp.close()
    
# Helper function to read in secret key and return it
def readValues(path):
    fp = open(path, "r")
    sk = fp.read()
    fp.close()
    
    return sk    

# Helper function to write byte values to a file with a specified path
def writeValues(values, path):
    fp = open(path, "w")
    fp.write(values)
    fp.close()  
    
# Checks if the number of arguments are valid and prints out an error message if they aren't.
def validateArguments(functionName, argv):
    if len(argv) < requiredArguments[functionName]:
        print("You didn't provide all the required arguments.")
        
        return False
    
    return True


if __name__ == "__main__":
    functionName = sys.argv[1]
    
    if functionName == "keygen":
        if (validateArguments(functionName, sys.argv)):
            keygen(sys.argv[2])
    elif functionName == "enc":
        if (validateArguments(functionName, sys.argv)):
            enc(sys.argv[2], sys.argv[3], sys.argv[4])
    elif functionName == "dec":
        if (validateArguments(functionName, sys.argv)):
            dec(sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        print("You did not enter a valid function name.")
    