import string
# Print vigenere table
ALPHABET = string.ascii_uppercase
out = []
for i in range(len(ALPHABET)):
    out.append(ALPHABET[i:] + ALPHABET[:i])
print('\n'.join(out))