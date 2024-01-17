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
from adkg.aprep import APREP
from adkg.router import SimpleRouter
from adkg.admpc import ADMPC
import time

from adkg.trans import Trans

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


def gen_vector(t, n, ZR):
    # 这里的 coeff 是系数，重点！！也就是论文的逻辑是各方 acss 得到的随机数先跟 Vandermonde Matrix 相乘，再根据不同参与方添加不同的系数 x
    # 但这里的逻辑是 先提前生成好系数矩阵，再拿系数矩阵与 Vandermonde Matrix 相乘，最后再去乘以 随机数矩阵，得到的输出自然就包含不同参与方的不同系数
    # coeff_1 = np.array([[ZR(i+1)**j for j in range(t+1)] for i in range(n)])
    # print(f"coeff_1: {coeff_1}")
    # coeff_2 = np.array([[ZR(i+1)**j for j in range(t+1, deg+1)] for i in range(n)])
    # 这里 hm 是 Vandermonde Matrix 
    # hm_1 = np.array([[ZR(i+1)**j for j in range(n)] for i in range(t+1)])
    # hm_2 = np.array([[ZR(i+1)**j for j in range(n)] for i in range(deg-t)])
    # print(f"hm_1: {hm_1}")
    # rm_1 = np.matmul(coeff_1, hm_1)
    # rm_2 = np.matmul(coeff_2, hm_2)
    # print(f"rm_1: {rm_1}")
    # print(f"rm_1.tolist(): {rm_1.tolist()}")

    vm = np.array([[ZR(i+1)**j for j in range(n)] for i in range(n-t)])
    # print(f"vm: {vm}")

    return (vm.tolist())

async def tutorial_1():
    # Create a test network of 4 nodes (no sockets, just asyncio tasks)
    n, t = 16, 5

    g, h, pks, sks = get_avss_params(n, t)
    router = SimpleRouter(n)
    pc = PolyCommitHybrid(g, h, ZR, multiexp)
    deg = t
    mat = gen_vector(t, n, ZR)

    admpc_tasks = [None] * n # async task for adkg
    admpc_list = [None] * n #

    start_time = time.time()
    curve_params = (ZR, G1, multiexp, dotprod)

    for i in range(n):
        admpc = ADMPC(pks, sks[i], g, h, n, t, deg, i, router.sends[i], router.recvs[i], pc, curve_params, mat)
        admpc_list[i] = admpc
        admpc_tasks[i] = asyncio.create_task(admpc.run_admpc(start_time))
    await asyncio.gather(*admpc_tasks)

    # n, t = 4, 1

    # program_lists = [None] * n
    # program_tasks = [None] * n

    # for i in range(n): 
    #     program_tasks[i] = asyncio.create_task(program(i, n, t))

    
    # program_runner = TaskProgramRunner(n, t, config)
    # program_runner.add(prog)
    # # program_runner.join 这个函数设计的有问题，注释掉里面的代码程序部分函数不调用了，可能会影响到 aprep 协议的输出
    # results = await program_runner.join()
    # print(f"results: {results}")
    # return results


def main():
    # Run the tutorials
    asyncio.set_event_loop(asyncio.new_event_loop())
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tutorial_1())
    # loop.run_until_complete(tutorial_2())


if __name__ == "__main__":
    main()
    print("Tutorial 1 ran successfully")
