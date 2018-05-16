from umbral.signers import ECDSASigner

def test_ECDSA_Signer():
    signer = ECDSASigner()

    data = b'Test message'

    signature = signer.sign(data)

    assert signer.verify(signature, data)
    assert not signer.verify(signature, b'Different input')
