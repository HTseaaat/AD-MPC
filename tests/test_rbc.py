from random import randint, shuffle
from adkg.polynomial import polynomials_over
from pypairing import ZR, G1, blsmultiexp as multiexp, dotprod
# from pypairing import Curve25519ZR as ZR, Curve25519G as G1, curve25519multiexp as multiexp, curve25519dotprod as dotprod

from adkg.broadcast.tylerba import tylerba
from adkg.broadcast.optqrbc import optqrbc

from adkg.preprocessing import PreProcessedElements

from adkg.mpc import TaskProgramRunner
from adkg.utils.serilization import Serial

from adkg.poly_commit_hybrid import PolyCommitHybrid

import asyncio

class ADKGMsgType:
    ACSS = "A"
    RBC = "R"
    ABA = "B"
    PREKEY = "P"
    KEY = "K"

def get_avss_params(n, t):
    g, h = G1.rand(b'g'), G1.rand(b'h')
    public_keys, private_keys = [None] * n, [None] * n
    for i in range(n):
        private_keys[i] = ZR.random()
        public_keys[i] = pow(g, private_keys[i])
    return g, h, public_keys, private_keys


async def test_rbc():

    t = 1
    n = 4
    g, h, pks, sks = get_avss_params(n, t)
    pc = PolyCommitHybrid(g, h, ZR, multiexp)
    value = ZR(3)
    value_hat = ZR(4)
    c = pc.commit_alpha(value, value_hat)

    serialized_masked_values = sr.serialize_f(masked_values)
    serialized_masked_values_hat = sr.serialize_f(masked_values_hat)
    serialized_c = sr.serialize_g(c)
    rbc_masked_input = serialized_masked_values + serialized_masked_values_hat + serialized_c

    leader = 0
    rbc_tasks = [None] * n
    rbc_list = [None] * n

    rbc_outputs = [asyncio.Queue() for _ in range(self.n)]

    work_tasks = await asyncio.gather(*[_setup(j) for j in range(n)])
    rbc_signal = asyncio.Event()
    # print(f"{self.my_id} rbc_outputs: {rbc_outputs}")
    rbc_values = [None for i in range(n)]
        

    async def predicate(serialized_masked_input):
        sr = Serial(G1)
        g_size = sr.g_size
        f_size = sr.f_size
        serialized_masked_values = serialized_masked_input[:f_size]
        serialized_masked_values_hat = serialized_masked_input[f_size:2*f_size]
        serialized_c = serialized_masked_input[2*f_size:2*f_size+g_size]

        masked_values = sr.deserialize_f(serialized_masked_values)
        masked_values_hat = sr.deserialize_f(serialized_masked_values_hat)
        c = sr.deserialize_g(serialized_c)

            
        kp = Bitmap(self.n, _key_proposal)
        kpl = []
        for ii in range(self.n):
            if kp.get_bit(ii):
                kpl.append(ii)
        if len(kpl) <= self.t:
            return False
        
        while True:
            subset = True
            for kk in kpl:
                if kk not in acss_outputs.keys():
                    subset = False
            if subset:
                acss_signal.clear()    
                return True
            acss_signal.clear()
            await acss_signal.wait()

    async def _setup(j):
        
        # starting RBC
        rbctag =ADKGMsgType.RBC + str(j) # (R, msg)
        rbcsend, rbcrecv = self.get_send(rbctag), self.subscribe_recv(rbctag)

        rbc_input = None
        if j == self.my_id: 
            rbc_input = rbc_masked_input

        # rbc_outputs[j] = 
        asyncio.create_task(
            optqrbc(
                rbctag,
                self.my_id,
                self.n,
                self.t,
                j,
                predicate,
                rbc_input,
                rbc_outputs[j].put_nowait,
                rbcsend,
                rbcrecv,
            )
        )


    