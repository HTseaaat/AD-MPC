from adkg.poly_commit_hybrid_GFE import PolyCommitHybrid
from pytest import mark, fixture
import logging
from adkg.polynomial import polynomials_over
from adkg.admpc import ADMPC
import asyncio
import numpy as np
import uvloop
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
from pypairing import ZR, blsmultiexp as multiexp, dotprod
# from pypairing import ZR, G1, blsmultiexp as multiexp, dotprod
# from pypairing import Curve25519ZR as ZR, Curve25519G as G1, curve25519multiexp as multiexp, curve25519dotprod as dotprod

from adkg.field import GF, GFElement
from adkg.ntl import vandermonde_batch_evaluate
from adkg.elliptic_curve import Subgroup
    
import time

logger = logging.getLogger(__name__)
logger.setLevel(logging.NOTSET)

@fixture(scope="session")
def num(pytestconfig):
    return pytestconfig.getoption("num")

@fixture(scope="session")
def ths(pytestconfig):
    return pytestconfig.getoption("ths")

@fixture(scope="session")
def deg(pytestconfig):
    return pytestconfig.getoption("deg")

@fixture(scope="session")
def curve(pytestconfig):
    return pytestconfig.getoption("curve")


def get_avss_params(n, G1, ZR):
    g, h = G1.rand(b'g'), G1.rand(b'h')
    public_keys, private_keys = [None] * n, [None] * n
    for i in range(n):
        private_keys[i] = ZR.hash(str(i).encode())
        public_keys[i] = pow(g, private_keys[i])
    return g, h, public_keys, private_keys


def gen_vector(t, deg, n, ZR):
    coeff_1 = np.array([[ZR(i+1)**j for j in range(t+1)] for i in range(n)])
    coeff_2 = np.array([[ZR(i+1)**j for j in range(t+1, deg+1)] for i in range(n)])
    hm_1 = np.array([[ZR(i+1)**j for j in range(n)] for i in range(t+1)])
    hm_2 = np.array([[ZR(i+1)**j for j in range(n)] for i in range(deg-t)])
    rm_1 = np.matmul(coeff_1, hm_1)
    rm_2 = np.matmul(coeff_2, hm_2)

    return (rm_1.tolist(), rm_2.tolist())

def get_avss_params_GFE(n, G1):
    print(f"G1 type: {type(G1)}")
    field_type = ZR
    g, h = G1.random(), G1.random()
    print(f"g type: {type(g)}")
    public_keys, private_keys = [None] * n, [None] * n
    for i in range(n):
        private_keys[i] = ZR.hash(str(i).encode())
        print(f"private_keys[i] type: {type(private_keys[i])}")
        private_keys[i] = int(private_keys[i])
        print(f"private_keys[i] type: {type(private_keys[i])}")
        private_keys[i] = G1(private_keys[i])
        print(f"private_keys[i] type: {type(private_keys[i])}")
        # public_keys[i] = G1.pow(g, private_keys[i])
        public_keys[i] = g ** private_keys[i].value
        print(f"public_keys[i] type: {type(public_keys[i])}")
        # public_keys[i] = ZR(public_keys[i].value)
        # print(f"public_keys[i] type: {type(public_keys[i])}")
    return g, h, public_keys, private_keys

def gen_vector_GFE(t, deg, n, G1):
    coeff_1 = np.array([[G1(i+1)**j for j in range(t+1)] for i in range(n)])
    # print(f"coeff_1[0][0] type: {type(coeff_1[0][0])}")
    coeff_2 = np.array([[G1(i+1)**j for j in range(t+1, deg+1)] for i in range(n)])
    hm_1 = np.array([[G1(i+1)**j for j in range(n)] for i in range(t+1)])
    hm_2 = np.array([[G1(i+1)**j for j in range(n)] for i in range(deg-t)])
    rm_1 = np.matmul(coeff_1, hm_1)
    rm_2 = np.matmul(coeff_2, hm_2)

    return (rm_1.tolist(), rm_2.tolist())


@mark.asyncio
async def test_admpc(test_router, num, ths, deg, curve):
    t = int(ths)
    deg = int(deg)
    n = int(num)  
    
    assert n > 3*t and deg < n-t
    
    logging.info(f"ADKG Experiment with n:{n}, t:{t}, deg:{deg}")

    G1 = GF(Subgroup.BLS12_381)

    g, h, pks, sks = get_avss_params_GFE(n, G1)
    # g, h, pks, sks = get_avss_params(n, G1, ZR)
    sends, recvs, _ = test_router(n, maxdelay=0.01)
    pc = PolyCommitHybrid(g, h, ZR, multiexp)
    mat1, mat2 = gen_vector_GFE(t, deg, n, G1)

    dkg_tasks = [None] * n # async task for adkg
    dkg_list = [None] * n #

    start_time = time.time()
    print(f"test_admpc type(ZR): {type(ZR)}")
    curve_params = (ZR, G1, multiexp, dotprod)

    for i in range(n):
        dkg = ADMPC(pks, sks[i], g, h, n, t, deg, i, sends[i], recvs[i], pc, curve_params, (mat1, mat2))
        dkg_list[i] = dkg
        dkg_tasks[i] = asyncio.create_task(dkg.run_adkg(start_time))
    
    outputs = await asyncio.gather(
        *[dkg_list[i].output_queue.get() for i in range(n)]
    )
    for dkg in dkg_list:
        dkg.kill()
    for task in dkg_tasks:
        task.cancel()
    
    
    shares = []
    i = 1
    for _, _, sk, _ in outputs:
        shares.append([i, sk])
        i = i + 1

    poly = polynomials_over(ZR)
    msk = poly.interpolate_at(shares,0)
    mpk = g**msk

    for i in range(n):
        assert(mpk == outputs[i][3])

    mks_set = outputs[0][1]
    for i in range(1, n):
        assert mks_set == outputs[i][1]

    mks_sum = ZR(0)
    for node in mks_set:
        mks_sum = mks_sum + outputs[node][0]
    assert msk == mks_sum

    def check_degree(claimed_degree, points):
        dual_code = gen_dual_code(n, claimed_degree, poly)
        check = dot(points, dual_code)
        return check == ZR(0)

    def gen_dual_code(n, degree, poly):
        def get_vi(i, n):
            out = ZR(1)
            for j in range(1, n+1):
                if j != i:
                    out = out / (i-j)
            return out
        q = poly.random(n -degree -2)
        q_evals = [q(i+1) for i in range(n)]
        return [q_evals[i] * get_vi(i+1, n) for i in range(n)]
    

    def dot(a, b):
        res = ZR(0)
        for i in range(len(a)):
            res = res + a[i][1]*b[i]
        return res
    

    assert not check_degree(deg-1, shares)
    assert check_degree(deg, shares)