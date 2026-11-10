#Declare global variables 
original_msg = b"I transferred 1000 dollars today"

#Test altered message by changing contents of the message and verifying that the verify function returns false 
def test_altered_message(adapterClass): 
    algorithm_cls = adapterClass()
    signature = algorithm_cls.sign(original_msg)
    assert algorithm_cls.verify(b"I transferred 2000 dollars today",signature) is False

#Test corrupted ciphertext by changing 32 bits of the ciphertext and verifying that the decrypting the corrupted ciphertext doesn't match original_msg 
def test_corrupted_ciphertext(adapterClass): 
    algorithm_cls = adapterClass()
    ciphertext = algorithm_cls.encrypt(original_msg)
    corrupted = bytearray(ciphertext)
    for i in range(1, 33):
        corrupted[-i] ^= 0xFF
    corrupted_ciphertext = bytes(corrupted)
    decrypted_msg = algorithm_cls.decrypt(corrupted_ciphertext)
    assert decrypted_msg != original_msg

#Test invalid signature by having a different signer sign the message and verifying that the verify function returns false 
def test_invalid_signature(adapterClass): 
    algorithm_cls = adapterClass()
    attacker_cls = adapterClass()
    signature = attacker_cls.sign(original_msg)
    assert algorithm_cls.verify(original_msg,signature) is False 

#Test tampered signature by changing the signature by one bit(start, middle, or end) and verifying that the verify function returns false 
def test_tampering_signature(adapterClass): 
    algorithm_cls = adapterClass()
    signature = algorithm_cls.sign(original_msg)

    #Flip one bit in the start, middle, and end of the signature 
    signature_length = len(signature)
    for i in (0,signature_length//2,signature_length-1): 
        tampered = bytearray(signature)
        tampered[i]^=0x01
        tampered_signature = bytes(tampered)
        assert algorithm_cls.verify(original_msg,tampered_signature) is False 
    
#Test wrong key by signing message with a key pair and verifying that using a different key will have the verify function return false 
def test_wrong_key_signature(adapterClass): 
    algorithm_cls = adapterClass()
    signature = algorithm_cls.sign(original_msg)
    attacker_cls = adapterClass()
    assert attacker_cls.verify(original_msg,signature) is False 

#Test wrong key by encrypting with wrong key and decryping with another key 
def test_wrong_key_encryption(adapterClass): 
    algorithm_cls = adapterClass()
    ciphertext = algorithm_cls.encrypt(original_msg)
    attacker_cls = adapterClass()
    decrypted_msg = attacker_cls.decrypt(ciphertext)
    assert decrypted_msg != original_msg

#Tests the KEM part and the AES-GCM payload 
def test_hybrid_corrupted_ciphertext(adapterClass):
    algorithm_cls = adapterClass()
    enc = algorithm_cls.encrypt(original_msg)
    for part in ("kem", "payload"):
        assert algorithm_cls.decrypt(algorithm_cls.corrupt(enc, part)) != original_msg

#Test tampered hybrid signature by corrupting each half separately and verifying that verify returns false
def test_hybrid_tampered_signature(adapterClass):
    algorithm_cls = adapterClass()
    sig = algorithm_cls.sign(original_msg)

    assert algorithm_cls.verify(original_msg, algorithm_cls.corrupt(sig, "classical")) is False
    assert algorithm_cls.verify(original_msg, algorithm_cls.corrupt(sig, "pq")) is False

#Test expired certificate by providing an expired certificate and seeing if it returns "expired" as expected
def test_expired_certificate(adapterClass):
    algorithm_cls = adapterClass()
    assert "expired" in algorithm_cls.validate_expired()

#Test untrusted certificate by using a different root ca that didn't validate the certificate chain and seeing if it returns "no-trust-anchor" as expected
def test_untrusted_certificate(adapterClass):
    algorithm_cls = adapterClass()
    assert "no-trust-anchor" in algorithm_cls.validate_untrusted()

#Test incorrectly signed certificate by using an attacker's signed certificate and seeing if it returns "signature" as expected
def test_incorrectly_signed_certificate(adapterClass):
    algorithm_cls = adapterClass()
    assert "signature" in algorithm_cls.validate_forged()

#Test invalid certificate by using the leaf's certificate to sign (not a ca) and seeing if it returns "not-a-ca" as expected
def test_invalid_certificate(adapterClass):
    algorithm_cls = adapterClass()
    assert "not-a-ca" in algorithm_cls.validate_leaf_as_ca()


#Categorize all of the attacks into their own arrays to be ran inside of the run-test-attacks file 
signature_attacks = [test_altered_message, test_invalid_signature,test_tampering_signature, test_wrong_key_signature]
encryption_attacks = [test_corrupted_ciphertext,test_wrong_key_encryption]
hybrid_kem_attacks = [test_hybrid_corrupted_ciphertext, test_wrong_key_encryption]
hybrid_sig_attacks = [test_altered_message, test_invalid_signature,test_wrong_key_signature, test_hybrid_tampered_signature]
pki_attacks = [test_expired_certificate, test_untrusted_certificate,test_incorrectly_signed_certificate, test_invalid_certificate]