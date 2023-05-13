from Crypto.PublicKey import RSA, ECC

GENERATE_RSA = True
GENERATE_ECC = True

filename = "private_key.pem"

if GENERATE_RSA:
    # Generate a new RSA key
    key = RSA.generate(2048)

    # Save the private key
    with open('rsa_'+filename , "wb") as f:
        f.write(key.export_key("PEM"))

if GENERATE_ECC:
    # Generate a new ECC key
    key = ECC.generate(curve='ed25519')

    # Save the private key
    with open('ecc_'+filename, "wt") as f:
        f.write(key.export_key(format="PEM"))