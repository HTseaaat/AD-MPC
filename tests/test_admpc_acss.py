"""
hbMPC tutorial 1. Running sample MPC programs in the testing simulator
"""
import asyncio
from adkg.mpc import TaskProgramRunner
from adkg.progs.mixins.dataflow import Share
from adkg.preprocessing import (
    PreProcessedElements as FakePreProcessedElements,
)
from adkg.utils.typecheck import TypeCheck
from adkg.progs.mixins.share_arithmetic import (
    MixinConstants,
    BeaverMultiply,
    BeaverMultiplyArrays,
)

from adkg.poly_commit_hybrid import PolyCommitHybrid
from pytest import mark
from random import randint
from adkg.polynomial import polynomials_over
from adkg.acss_ht import ACSS_HT
from adkg.utils.misc import print_exception_callback
import asyncio
import math

import numpy as np

from pypairing import ZR, G1, blsmultiexp as multiexp

config = {
    MixinConstants.MultiplyShareArray: BeaverMultiplyArrays(),
    MixinConstants.MultiplyShare: BeaverMultiply(),
}


@TypeCheck()
async def beaver_multiply(ctx, x: Share, y: Share):
    """The hello world of MPC: beaver multiplication
     - Linear operations on Share objects are easy
     - Shares of random values are available from preprocessing
     - Opening a Share returns a GFElementFuture
    """
    a, b, ab = ctx.preproc.get_triples(ctx)
    # X = await x.open()
    # print("X: ", X)
    # A = await a.open()
    # B = await b.open()
    # C = await ab.open()
    # print("A: ", A)
    # print("B: ", B)
    # mulAB = A * B
    # print("A*B: ", mulAB)
    # print("C: ", C)
    D = await (x - a).open()
    # print("D: ", D)
    E = await (y - b).open()

    # D*E is multiplying GFElements
    # D*b, E*a are multiplying GFElement x Share -> Share
    # ab is a Share
    # overall the sum is a Share

    xy = (D * E) + (D * b) + (E * a) + ab
    return xy


async def random_permute_pair(ctx, x, y):
    """
    Randomly permute a pair of secret shared values.
    Input: `x`, `y` are `Share` objects
    Output: A pair of `Share` objects `(o1,o2)`, which are fresh
       shares that take on the value `(x,y)` or `(y,x)` with equal
       probability
    Preprocessing:
    - One random bit
    - One beaver multiplication
    """
    b = ctx.preproc.get_bit(ctx)
    # just a local scalar multiplication
    one_or_minus_one = ctx.field(2) * b - ctx.field(1)
    m = one_or_minus_one * (x - y)
    o1 = (x + y + m) * (1 / ctx.field(2))
    o2 = (x + y - m) * (1 / ctx.field(2))
    return (o1, o2)


# Working with arrays
def dot_product(ctx, x_shares, y_shares):
    """Although the above example of Beaver multiplication is perfectly valid,
    you can also just use the `*` operator of the Share object, which does
    the same thing.

    This is also an example of dataflow programming. The return value of this
    operation is a `ShareFuture`, which defines addition and multiplication
    operations as well (like in Viff). As a result, all of these multiplications
    can take place in parallel.
    """
    res = ctx.ShareFuture()
    res.set_result(ctx.Share(0))
    for x, y in zip(x_shares, y_shares):
        res += x * y
    return res


def get_avss_params(n, t):
    g, h = G1.rand(b'g'), G1.rand(b'h')
    public_keys, private_keys = [None] * n, [None] * n
    for i in range(n):
        private_keys[i] = ZR.random()
        public_keys[i] = pow(g, private_keys[i])
    return g, h, public_keys, private_keys

async def gather_outputs(acss_list):
    return await asyncio.gather(
        *[acss.output_queue.get() for acss in acss_list if acss is not None]
    )

def gen_vector(t, deg, n, ZR):
    coeff_1 = np.array([[ZR(i+1)**j for j in range(t+1)] for i in range(n)])
    coeff_2 = np.array([[ZR(i+1)**j for j in range(t+1, deg+1)] for i in range(n)])
    hm_1 = np.array([[ZR(i+1)**j for j in range(n)] for i in range(t+1)])
    hm_2 = np.array([[ZR(i+1)**j for j in range(n)] for i in range(deg-t)])
    rm_1 = np.matmul(coeff_1, hm_1)
    rm_2 = np.matmul(coeff_2, hm_2)

    return (rm_1.tolist(), rm_2.tolist())

# 这里是 acss 的测试代码
async def prog(ctx):
    print(f"ctx.N: {ctx.N}")
    t = ctx.t
    deg = t
    n = ctx.N
    sc = math.ceil(deg/t) + 1
    myid = ctx.myid

    g, h, public_keys, private_key = ctx.g, ctx.h, ctx.public_keys, ctx.private_key
    pc = PolyCommitHybrid(g, h, ZR, multiexp)

    values = [ZR(3), ZR(5)]

    avss_tasks = ctx.avss_tasks
    dealer_id = ctx.dealer_id
    shares = ctx.shares
    acss_list = ctx.acss_list

    # print(f"myid: {ctx.myid} ctx.send: {ctx.send}")
    # print(f"myid: {ctx.myid} ctx.recv: {ctx.recv}")
    # 这里异步延迟的设置可能还没有考虑
    acss = ACSS_HT(public_keys, private_key, g, h, n, t, deg, sc, myid, ctx.send, ctx.recv, pc, ZR, G1)
    acss_list[myid] = acss
    if myid == dealer_id: 
        avss_tasks[myid] = asyncio.create_task(acss.avss(0, values=values))
    else: 
        avss_tasks[myid] = asyncio.create_task(acss.avss(0, dealer_id=dealer_id))
    avss_tasks[myid].add_done_callback(print_exception_callback)

    # outputs = await gather_outputs(acss_list)
    # print(f"outputs: {outputs}")
    # shares = [output[2][0] for output in outputs]


async def tutorial_1():
    # Create a test network of 4 nodes (no sockets, just asyncio tasks)
    n, t = 4, 1
    pp = FakePreProcessedElements()
    pp.generate_zeros(100, n, t)
    pp.generate_triples(100, n, t)
    pp.generate_bits(100, n, t)
    program_runner = TaskProgramRunner(n, t, config)
    program_runner.add(prog)
    results = await program_runner.join()
    print(f"results: {results}")
    return results


def main():
    # Run the tutorials
    asyncio.set_event_loop(asyncio.new_event_loop())
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tutorial_1())
    # loop.run_until_complete(tutorial_2())


if __name__ == "__main__":
    main()
    print("Tutorial 1 ran successfully")
