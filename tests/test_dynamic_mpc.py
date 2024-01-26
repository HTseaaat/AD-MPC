from adkg.poly_commit_hybrid import PolyCommitHybrid
from pytest import mark, fixture
import logging
from adkg.polynomial import polynomials_over
from adkg.adkg import ADKG
import asyncio
import numpy as np
import uvloop
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
from pypairing import ZR, G1, blsmultiexp as multiexp, dotprod  
from adkg.dynamic_admpc import ADMPC
# from pypairing import ZR, G1, blsmultiexp as multiexp, dotprod
# from pypairing import Curve25519ZR as ZR, Curve25519G as G1, curve25519multiexp as multiexp, curve25519dotprod as dotprod
    
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


def get_avss_params(n):
    g, h = G1.rand(b'g'), G1.rand(b'h')
    public_keys, private_keys = [None] * n, [None] * n
    for i in range(n):
        private_keys[i] = ZR.random()
        public_keys[i] = pow(g, private_keys[i])
    return g, h, public_keys, private_keys


def gen_vector(t, n, ZR):

    vm = np.array([[ZR(i+1)**j for j in range(n)] for i in range(n-t)])

    return (vm.tolist())

@mark.asyncio
async def test_adkg(test_router, num, ths, deg, curve):
    t = int(ths)
    deg = int(deg)
    n = int(num)

   
        
   
    
    assert n > 3*t and deg < n-t
    
    logging.info(f"ADKG Experiment with n:{n}, t:{t}, deg:{deg}")
    n = 4
    layer_num = 2
    committee_size = int(n/layer_num)

    g, h, pks, sks = get_avss_params(n*layer_num)
    sends, recvs, _ = test_router(n*layer_num, maxdelay=0.01)
    pc = PolyCommitHybrid(g, h, ZR, multiexp)
    mat = gen_vector(t, committee_size, ZR)

    start_time = time.time()
    curve_params = (ZR, G1, multiexp, dotprod)

    admpc_tasks = [[None for _ in range(n)] for _ in range(layer_num)]
    admpc_lists = [[None for _ in range(n)] for _ in range(layer_num)]

    # admpc_tasks = [None] * n
    # admpc_lists = [None] * n

    start_time = time.time()
    curve_params = (ZR, G1, multiexp, dotprod)

    # for i in range(n): 
    #     admpc = ADMPC(pks, sks[i], g, h, committee_size, t, deg, i, sends[i], recvs[i], pc, curve_params, mat)
    #     admpc_lists[i] = admpc
    #     admpc_tasks[i] = asyncio.create_task(admpc.run_admpc(start_time))
    # await asyncio.gather(*admpc_tasks)

    for layer in range(layer_num): 
        for node in range(n):
            admpc = ADMPC(pks[layer*n:layer*n+n], sks[layer*n+node], g, h, n, t, deg, node, sends[layer*n+node], recvs[layer*n+node], pc, curve_params, mat)
            # admpc = ADMPC(pks, sks[node], g, h, n, t, deg, node, sends[node], recvs[node], pc, curve_params, mat)
            admpc_lists[layer][node] = admpc
            admpc_tasks[layer][node] = asyncio.create_task(admpc.run_admpc(start_time, layer))
    
    for layer in range(layer_num):
        await asyncio.gather(*admpc_tasks[layer])

    # g, h, pks, sks = get_avss_params(n)
    # sends, recvs, _ = test_router(n, maxdelay=0.01)
    # pc = PolyCommitHybrid(g, h, ZR, multiexp)
    # mat = gen_vector(t, n, ZR)

    # start_time = time.time()
    # curve_params = (ZR, G1, multiexp, dotprod)

    # admpc_tasks = [None] * n # async task for adkg
    # admpc_list = [None] * n #

    # start_time = time.time()
    # curve_params = (ZR, G1, multiexp, dotprod)

    # for i in range(n):
    #     admpc = ADMPC(pks, sks[i], g, h, n, t, deg, i, sends[i], recvs[i], pc, curve_params, mat)
    #     admpc_list[i] = admpc
    #     admpc_tasks[i] = asyncio.create_task(admpc.run_admpc(start_time))
    # await asyncio.gather(*admpc_tasks)

    outputs = await asyncio.gather(
        *[admpc_lists[i].output_queue.get() for i in range(n)]
    )
    
    for dkg in admpc_lists:
        dkg.kill()
    for task in admpc_tasks:
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

    
    
    