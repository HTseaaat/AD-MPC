from adkg.polynomial import polynomials_over, EvalPoint
from adkg.utils.poly_misc import interpolate_g1_at_x
from adkg.utils.misc import wrap_send, subscribe_recv
import asyncio
import hashlib, time
from math import ceil
import logging
from adkg.utils.bitmap import Bitmap
from adkg.acss import ACSS

from adkg.broadcast.tylerba import tylerba
from adkg.broadcast.optqrbc import optqrbc

from adkg.preprocessing import PreProcessedElements

from adkg.mpc import TaskProgramRunner
from adkg.utils.serilization import Serial
from adkg.robust_rec import Robust_Rec
from adkg.field import GF, GFElement
from adkg.robust_reconstruction import robust_reconstruct_admpc
from adkg.elliptic_curve import Subgroup

import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.NOTSET)

class ADKGMsgType:
    ACSS = "A"
    RBC = "R"
    ABA = "B"
    PREKEY = "P"
    KEY = "K"
    MASK = "M"
    GENRAND = "GR"
    ROBUSTREC = "RR"
    

class Computation:
    def __init__(self, public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params):
        self.public_keys, self.private_key, self.g, self.h = (public_keys, private_key, g, h)
        self.n, self.t, self.deg, self.my_id = (n, t, deg, my_id)
        self.send, self.recv, self.pc = (send, recv, pc)
        self.ZR, self.G1, self.multiexp, self.dotprod = curve_params
        self.poly = polynomials_over(self.ZR)
        self.poly.clear_cache() #FIXME: Not sure why we need this.
        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)
        self.get_send = _send
        self.output_queue = asyncio.Queue()

        rectag = ADKGMsgType.ROBUSTREC
        recsend, recrecv = self.get_send(rectag), self.subscribe_recv(rectag)
        curve_params = (self.ZR, self.G1, self.multiexp, self.dotprod)
        self.rec = Robust_Rec(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.my_id, recsend, recrecv, self.pc, curve_params)


        self.benchmark_logger = logging.LoggerAdapter(
            logging.getLogger("benchmark_logger"), {"node_id": self.my_id}
        )
            
    def kill(self):
        try:
            self.subscribe_recv_task.cancel()
            for task in self.acss_tasks:
                task.cancel()
            self.acss.kill()
            self.acss_task.cancel()
        except Exception:
            logging.info("ADKG task finished")
        

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self
    
    async def robust_rec_step(self, rec_shares, rec_signal):                
        
        
        rec_values = await self.rec.run_robust_rec(0, rec_shares)
        print(f"my id: {self.my_id} rec_values: {rec_values}")

        rec_signal.set()
        return rec_values
    
    async def mult(self, mult_values, mult_triples): 
        gamma = mult_values[0] - mult_triples[0]
        epsilon = mult_values[1] - mult_triples[1]

        robust_rec_signal = asyncio.Event()
        rec_gamma = await self.robust_rec_step(gamma, robust_rec_signal)
        await robust_rec_signal.wait()
        robust_rec_signal.clear()
        rec_epsilon = await self.robust_rec_step(epsilon, robust_rec_signal)
        await robust_rec_signal.wait()
        robust_rec_signal.clear()

        mult_output = mult_triples[2] + rec_gamma * mult_triples[1] + rec_epsilon * mult_triples[0] + rec_gamma * rec_epsilon
        return mult_output

    
    async def run_computation(self, inputs, gate_tape, mult_triples):
        self.gates_num = int(len(inputs)/2)
        # 这里根据当前层门的数量对输入进行划分
        gate_input_values = [[self.ZR(0) for _ in range(2) for _ in range(self.gates_num)]]
        for i in range(self.gates_num): 
            for j in range(2): 
                gate_input_values[i][j] = inputs[i+j]
        # 输出存在这里
        gate_output_values = [None] * self.gates_num
        triple_num = 0
        for i in range(self.gates_num): 
            # 这是加法
            if gate_tape[i] == 0: 
                gate_output_values[i] = gate_input_values[i][0] + gate_input_values[i][1]
            # 这是乘法
            else: 
                gate_output_values[i] = await self.mult(gate_input_values[i], mult_triples[triple_num])
                triple_num += 1

        # self.output_queue.put_nowait(gate_output_values)
        return gate_output_values

        # self.output_queue.put_nowait(gate_output_values)
        
