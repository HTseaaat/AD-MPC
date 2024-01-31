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
from adkg.admpc_dynamic import ADMPC_Dynamic, ADMPC_Multi_Layer_Control
import time

from adkg.trans import Trans

from pypairing import ZR, G1, blsmultiexp as multiexp, dotprod

config = {
    MixinConstants.MultiplyShareArray: BeaverMultiplyArrays(),
    MixinConstants.MultiplyShare: BeaverMultiply(),
}

async def tutorial_1():
    # Create a test network of 4 nodes (no sockets, just asyncio tasks)
    n, t = 4, 1
    layer_num = 10
    total_cm = 100
    deg = t
    start_time = time.time()
    multi_mpc_instance = ADMPC_Multi_Layer_Control(n=n, t=t, deg=deg, layer_num=layer_num, total_cm=total_cm)
    await multi_mpc_instance.add()
    prog_time = time.time() - start_time
    print(f"admpc time: {prog_time}")

async def main():
    # Run the tutorials
    await tutorial_1()

if __name__ == "__main__":
    asyncio.run(main())
    print("Tutorial 1 ran successfully")
