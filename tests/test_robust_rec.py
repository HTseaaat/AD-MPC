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
import time

from adkg.rand import Rand
from adkg.robust_rec import Robust_Rec

from pypairing import ZR, G1, blsmultiexp as multiexp, dotprod

config = {
    MixinConstants.MultiplyShareArray: BeaverMultiplyArrays(),
    MixinConstants.MultiplyShare: BeaverMultiply(),
}

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

# 这里是 protocol Robust-Rec 的测试代码
async def prog(ctx):
    print(f"my id: {ctx.myid} ctx.N: {ctx.N}")
    t = ctx.t
    deg = t
    n = ctx.N
    myid = ctx.myid

    g, h, public_keys, private_key = ctx.g, ctx.h, ctx.public_keys, ctx.private_key
    pc = PolyCommitHybrid(g, h, ZR, multiexp)

    # 假设原始多项式为 f(x) = 2x + 3
    share = ZR(2 * (myid + 1) + 3)
    
    rec_tasks = ctx.avss_tasks
    rec_list = ctx.acss_list

    curve_params = (ZR, G1, multiexp, dotprod)

    # x = ctx.Share(4) + ctx.preproc.get_zero(ctx)
    # X = await x.open()
    
    # 这里异步延迟的设置可能还没有考虑
    rec = Robust_Rec(public_keys, private_key, g, h, n, t, deg, myid, ctx.send, ctx.recv, pc, curve_params)
    rec_list[myid] = rec
    rec_tasks[myid] = asyncio.create_task(rec.run_robust_rec(share))
    

async def tutorial_1():
    # Create a test network of 4 nodes (no sockets, just asyncio tasks)
    n, t = 4, 1
    pp = FakePreProcessedElements()
    pp.generate_zeros(100, n, t)
    pp.generate_triples(100, n, t)
    pp.generate_bits(100, n, t)
    program_runner = TaskProgramRunner(n, t, config)
    program_runner.add(prog)
    # program_runner.join 这个函数设计的有问题，注释掉里面的代码程序部分函数不调用了，可能会影响到 aprep 协议的输出
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
