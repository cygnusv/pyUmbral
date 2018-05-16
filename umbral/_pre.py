from typing import Callable
from io import BytesIO

from umbral.curvebn import CurveBN
from umbral.config import default_params
from umbral.params import UmbralParameters


def prove_cfrag_correctness(cfrag: "CapsuleFrag",
                            kfrag: "KFrag",
                            capsule: "Capsule",
                            metadata: bytes=None,
                            params: UmbralParameters=None
                            ) -> "CorrectnessProof":
    params = params if params is not None else default_params()

    rk = kfrag._bn_key
    t = CurveBN.gen_rand(params.curve)
    ####
    ## Here are the formulaic constituents shared with `assess_cfrag_correctness`.
    ####
    e = capsule._point_e
    v = capsule._point_v

    e1 = cfrag._point_e1
    v1 = cfrag._point_v1

    u = params.u
    u1 = kfrag._point_commitment

    e2 = t * e
    v2 = t * v
    u2 = t * u

    hash_input = (e, e1, e2, v, v1, v2, u, u1, u2)
    if metadata is not None:
        hash_input += (metadata,)
    h = CurveBN.hash(*hash_input, params=params)

    kfrag_signature = kfrag._signature

    z3 = t + h * rk
    ########

    cfrag.attach_proof(e2, v2, u1, u2, kfrag_signature, z3, metadata)

    # Check correctness of original ciphertext (check nº 2) at the end
    # to avoid timing oracles
    if not capsule.verify(params):
        raise capsule.NotValid("Capsule verification failed.")


def assess_cfrag_correctness(cfrag,
                             capsule: "Capsule",
                             pubkey_a_point,
                             pubkey_b_point,
                             params: UmbralParameters = None,
                             signature_verifier: Callable=None):
    params = params if params is not None else default_params()

    ####
    ## Here are the formulaic constituents shared with `prove_cfrag_correctness`.
    ####
    e = capsule._point_e
    v = capsule._point_v

    e1 = cfrag._point_e1
    v1 = cfrag._point_v1

    u = params.u
    u1 = cfrag.proof._point_kfrag_commitment

    e2 = cfrag.proof._point_e2
    v2 = cfrag.proof._point_v2
    u2 = cfrag.proof._point_kfrag_pok

    hash_input = (e, e1, e2, v, v1, v2, u, u1, u2)
    if cfrag.proof.metadata is not None:
        hash_input += (cfrag.proof.metadata,)
    h = CurveBN.hash(*hash_input, params=params)

    kfrag_signature = cfrag.proof._kfrag_signature

    z3 = cfrag.proof._bn_sig
    ########

    ni = cfrag._point_noninteractive
    xcoord = cfrag._point_xcoord
    kfrag_id = cfrag._kfrag_id

    g = params.g

    signature_input = (kfrag_id, pubkey_a_point, pubkey_b_point, u1, ni, xcoord)
    valid_kfrag_signature = verify_kfrag_signature(signature_input,
                                                   kfrag_signature,
                                                   signature_verifier,
                                                   pubkey_a_point,
                                                   params)

    correct_reencryption_of_e = z3 * e == e2 + (h * e1)

    correct_reencryption_of_v = z3 * v == v2 + (h * v1)

    correct_rk_commitment = z3 * u == u2 + (h * u1)

    return valid_kfrag_signature \
           & correct_reencryption_of_e \
           & correct_reencryption_of_v \
           & correct_rk_commitment

def verify_kfrag_signature(signature_input, kfrag_signature,
                           signature_verifier: Callable, 
                           pubkey_a_point,
                           params):
    if signature_verifier:
        signature_input = b''.join(map(bytes,signature_input))
        return signature_verifier(signature_input. kfrag_signature)
    else:
        bn_size = CurveBN.get_size(params.curve)
        kfrag_signature = BytesIO(kfrag_signature)
        z1 = CurveBN.from_bytes(kfrag_signature.read(bn_size), params.curve)
        z2 = CurveBN.from_bytes(kfrag_signature.read(bn_size), params.curve)

        # We check the Schnorr signature over the kfrag components
        g_y = (z2 * params.g) + (z1 * pubkey_a_point)
        signature_input += (g_y, ) 
        return z1 == CurveBN.hash(*signature_input, params=params)

def verify_kfrag(kfrag,
                pubkey_a_point,
                pubkey_b_point,
                params: UmbralParameters = None,
                signature_verifier: Callable=None):

    params = params if params is not None else default_params()

    u = params.u

    id = kfrag._id
    key = kfrag._bn_key
    u1 = kfrag._point_commitment
    ni = kfrag._point_noninteractive
    xcoord = kfrag._point_xcoord    

    # We check that the commitment u1 is well-formed
    correct_commitment = u1 == key * u

    # We check the signature of the KFrag components
    signature_input = (id, pubkey_a_point, pubkey_b_point, u1, ni, xcoord)
    valid_kfrag_signature = verify_kfrag_signature(signature_input,
                                                   kfrag._signature,
                                                   signature_verifier,
                                                   pubkey_a_point,
                                                   params)

    return correct_commitment & valid_kfrag_signature
