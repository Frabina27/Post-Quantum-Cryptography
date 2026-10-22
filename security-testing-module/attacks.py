
#Declare global variables 
original_msg = b"I transferred 100 dollars"

#Test altered message by changing contents of the message and verifying that the verify function returns false 
def test_altered_message(adapterClass): 
    algorithm_cls = adapterClass()
    signature = algorithm_cls.sign(original_msg)
    assert algorithm_cls.verify(b"I transferred 1000 dollars",signature) is False

#Test corrupted ciphertext by changing one bit of the ciphertext and verifying that the decrypting the corrupted ciphertext doesn't match original_msg 
def test_corrupted_ciphertext(adapterClass): 
    algorithm_cls = adapterClass()
    ciphertext = algorithm_cls.encrypt(original_msg)
    corrupted = bytearray(ciphertext)
    corrupted[0] ^=0x01 
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
def test_wrong_key(adapterClass): 
    algorithm_cls = adapterClass()
    signature = algorithm_cls.sign(original_msg)
    attacker_cls = adapterClass()
    
    assert attacker_cls.verify(original_msg,signature) is False 

#Categorize all of the attacks into their own arrays to be ran inside of the run-test-attacks file 
signature_attacks = [test_altered_message, test_invalid_signature,test_tampering_signature, test_wrong_key]
encryption_attacks = [test_corrupted_ciphertext]