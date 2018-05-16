from umbral import pre
from umbral.config import default_curve
from umbral.fragments import KFrag, CapsuleFrag

def test_kfrag_serialization(alices_keys):
    priv_key_alice, pub_key_alice = alices_keys

    kfrags = pre.split_rekey(priv_key_alice, pub_key_alice, 1, 2)
    kfrag_bytes = kfrags[0].to_bytes()

    curve = default_curve()
    assert len(kfrag_bytes) == KFrag.get_size(curve)

    new_frag = pre.KFrag.from_bytes(kfrag_bytes)
    assert new_frag._id == kfrags[0]._id
    assert new_frag._bn_key == kfrags[0]._bn_key
    assert new_frag._point_noninteractive == kfrags[0]._point_noninteractive
    assert new_frag._point_commitment == kfrags[0]._point_commitment
    assert new_frag._point_xcoord == kfrags[0]._point_xcoord
    assert new_frag._signature == kfrags[0]._signature


def test_cfrag_serialization_with_proof_and_metadata(alices_keys):
    priv_key_alice, pub_key_alice = alices_keys

    _unused_key, capsule = pre._encapsulate(pub_key_alice.point_key)
    kfrags = pre.split_rekey(priv_key_alice, pub_key_alice, 1, 2)

    # Example of potential metadata to describe the re-encryption request
    metadata = b'This is an example of metadata for re-encryption request' 

    cfrag = pre.reencrypt(kfrags[0], capsule, provide_proof=True, metadata=metadata)
    cfrag_bytes = cfrag.to_bytes()

    proof = cfrag.proof
    assert proof is not None
    assert proof.metadata is not None

    new_cfrag = pre.CapsuleFrag.from_bytes(cfrag_bytes)
    assert new_cfrag._point_e1 == cfrag._point_e1
    assert new_cfrag._point_v1 == cfrag._point_v1
    assert new_cfrag._kfrag_id == cfrag._kfrag_id
    assert new_cfrag._point_noninteractive == cfrag._point_noninteractive

    new_proof = new_cfrag.proof
    assert new_proof is not None
    assert new_proof._point_e2 == proof._point_e2
    assert new_proof._point_v2 == proof._point_v2
    assert new_proof._point_kfrag_commitment == proof._point_kfrag_commitment
    assert new_proof._point_kfrag_pok == proof._point_kfrag_pok
    assert new_proof._kfrag_signature == proof._kfrag_signature
    assert new_proof._bn_sig == proof._bn_sig
    assert new_proof.metadata == metadata
    assert new_proof.metadata == proof.metadata


def test_cfrag_serialization_with_proof_but_no_metadata(alices_keys):
    priv_key_alice, pub_key_alice = alices_keys

    _unused_key, capsule = pre._encapsulate(pub_key_alice.point_key)
    kfrags = pre.split_rekey(priv_key_alice, pub_key_alice, 1, 2)

    cfrag = pre.reencrypt(kfrags[0], capsule, provide_proof=True)
    cfrag_bytes = cfrag.to_bytes()

    proof = cfrag.proof
    assert proof is not None
    assert proof.metadata is None

    # A CFrag can be represented as the 131 total bytes of three Points (33 each) and a CurveBN (32).
    # TODO: Figure out final size for CFrags with proofs
    #assert len(cfrag_bytes) == 33 + 33 + 33 + 32 == 131

    new_cfrag = pre.CapsuleFrag.from_bytes(cfrag_bytes)
    assert new_cfrag._point_e1 == cfrag._point_e1
    assert new_cfrag._point_v1 == cfrag._point_v1
    assert new_cfrag._kfrag_id == cfrag._kfrag_id
    assert new_cfrag._point_noninteractive == cfrag._point_noninteractive

    new_proof = new_cfrag.proof
    assert new_proof is not None
    assert new_proof._point_e2 == proof._point_e2
    assert new_proof._point_v2 == proof._point_v2
    assert new_proof._point_kfrag_commitment == proof._point_kfrag_commitment
    assert new_proof._point_kfrag_pok == proof._point_kfrag_pok
    assert new_proof._kfrag_signature == proof._kfrag_signature
    assert new_proof._bn_sig == proof._bn_sig
    assert new_proof.metadata is None

def test_cfrag_serialization_no_proof_no_metadata(alices_keys):
    priv_key_alice, pub_key_alice = alices_keys

    _unused_key, capsule = pre._encapsulate(pub_key_alice.point_key)
    kfrags = pre.split_rekey(priv_key_alice, pub_key_alice, 1, 2)

    cfrag = pre.reencrypt(kfrags[0], capsule, provide_proof=False)
    cfrag_bytes = cfrag.to_bytes()

    proof = cfrag.proof
    assert proof is None

    curve = default_curve()
    assert len(cfrag_bytes) == CapsuleFrag.get_size(curve)

    new_cfrag = pre.CapsuleFrag.from_bytes(cfrag_bytes)
    assert new_cfrag._point_e1 == cfrag._point_e1
    assert new_cfrag._point_v1 == cfrag._point_v1
    assert new_cfrag._kfrag_id == cfrag._kfrag_id
    assert new_cfrag._point_noninteractive == cfrag._point_noninteractive

    new_proof = new_cfrag.proof
    assert new_proof is None
