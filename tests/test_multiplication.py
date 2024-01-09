from adkg.poly_commit_hybrid_GFE import PolyCommitHybrid
from adkg.mpc import TaskProgramRunner
from pytest import mark, fixture
import logging
from adkg.polynomial import polynomials_over
from adkg.admpc import ADMPC
import asyncio
import numpy as np
import uvloop
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
from pypairing import ZR, blsmultiexp as multiexp, dotprod
from adkg.preprocessing import PreProcessedElements

from adkg.field import GF, GFElement
from adkg.ntl import vandermonde_batch_evaluate
from adkg.elliptic_curve import Subgroup

@mark.asyncio
async def test_multiplication():
    n, t = 4, 1
    num_triples = 2
    pp_elements = PreProcessedElements()
    pp_elements.generate_triples(num_triples, n, t)

    async def _prog(ctx):
        for _ in range(num_triples):
            a_sh, b_sh, ab_sh = ctx.preproc.get_triples(ctx)
            a, b, ab = await a_sh.open(), await b_sh.open(), await ab_sh.open()
            assert a * b == ab

    program_runner = TaskProgramRunner(n, t)
    program_runner.add(_prog)
    await program_runner.join()