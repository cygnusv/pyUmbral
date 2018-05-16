from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.exceptions import InvalidSignature

class ECDSASigner:
	def __init__(self, private_key=None):
		if private_key:
			self._private_key = private_key
		else:
			self._private_key = ec.generate_private_key(ec.SECP256K1(), 
														default_backend())
		self.public_key = self._private_key.public_key()

	def get_signature_size(self):
		return 2 * 256//8 

	def sign(self, data: bytes):
		signature = self._private_key.sign(data, ec.ECDSA(hashes.SHA256()))
		(r, s) = decode_dss_signature(signature)
		size = self.get_signature_size()//2
		return r.to_bytes(size, 'big') + s.to_bytes(size, 'big')

	def verify(self, signature: bytes, data: bytes):
		size = self.get_signature_size()//2
		r = int.from_bytes(signature[:size], 'big')
		s = int.from_bytes(signature[size:], 'big')
		signature = encode_dss_signature(r,s)

		try:
			self.public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
		except InvalidSignature:
			return False
		else:
			return True
