from adkg.polynomial import polynomials_over
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
from adkg.robust_rec import robust_reconstruct_admpc, Robust_Rec
from adkg.trans import Trans
from adkg.rand import Rand
from adkg.aprep import APREP
import math

import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.NOTSET)

class ADKGMsgType:
    ACSS = "A"
    RBC = "R"
    ABA = "B"
    PREKEY = "P"
    KEY = "K"
    GENRAND = "GR"
    ROBUSTREC = "RR"
    TRANS = "TR"
    APREP = "AP"
    

class ADMPC:
    def __init__(self, public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, matrices):
        self.public_keys, self.private_key, self.g, self.h = (public_keys, private_key, g, h)
        self.n, self.t, self.deg, self.my_id = (n, t, deg, my_id)
        self.send, self.recv, self.pc = (send, recv, pc)
        self.ZR, self.G1, self.multiexp, self.dotprod = curve_params
        self.curve_params = curve_params
        print(f"type(self.ZR): {type(self.ZR)}")
        self.poly = polynomials_over(self.ZR)
        self.poly.clear_cache() #FIXME: Not sure why we need this.
        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)
        self.matrix = matrices

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
    
    async def run_admpc(self, start_time):


        acss_start_time = time.time()

        # 首先缺失了由上一层接收到的 shares
        # 这里先假设收到的输入存在 inputs 列表中
        inputs = [self.ZR(2*(self.my_id+1)+3), self.ZR(3*(self.my_id+1)+2)]
        # gate_tape 表示当前层的电路门的 tape，0 代表加法，1 代表乘法
        gate_tape = [1]
        # 这里缺失了由上一层提供的随机数，乘法三元组，以及上一层计算的输出
        # 先假设大家接收到的乘法三元组是 a() = x+5 b()=3x+2 c()=2x+10
        mult_triples = [[self.ZR((self.my_id+1)+5), self.ZR(3*(self.my_id+1)+2), self.ZR(2*(self.my_id+1)+10)]]
        # 先假设生成的随机数 alpha()=2x+5
        rand_values = [self.ZR(2*(self.my_id+1)+5)]


        # 这里是 execution stage 的 step 1，执行当前层的计算

        gate_outputs = await self.run_computation(inputs, gate_tape, mult_triples)
        print(f"my id: {self.my_id} outputs: {gate_outputs}")


        # 这里是 execution stage 的 step 2，调用 rand 协议为下一层生成随机数
        # w 是需要生成的随机数的数量
        w = 3

        if w > self.n - self.t: 
            rounds = math.ceil(w / (self.n - self.t))
        else: 
            rounds = 1

        randtag = ADKGMsgType.GENRAND
        randsend, randrecv = self.get_send(randtag), self.subscribe_recv(randtag)
        rand = Rand(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.my_id, randsend, randrecv, self.pc, self.curve_params, self.matrix)
        rand_shares = await rand.run_rand(w, rounds)
        print(f"rand_shares: {rand_shares}")

        # 这里是 execution stage 的 step 3，调用 Aprep 协议为下一层生成乘法三元组
        cm = 2

        apreptag = ADKGMsgType.APREP
        aprepsend, apreprecv = self.get_send(apreptag), self.subscribe_recv(apreptag)
        aprep = APREP(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.my_id, aprepsend, apreprecv, self.pc, self.curve_params, self.matrix)
        new_mult_triples = await aprep.run_aprep(cm)
        print(f"new_mult_triples: {new_mult_triples}")


        # 这里是 execution stage 的 step 4，调用 Trans 协议将当前层的电路输出传输到下一层
        transtag = ADKGMsgType.TRANS
        transsend, transrecv = self.get_send(transtag), self.subscribe_recv(transtag)
        trans = Trans(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.my_id, transsend, transrecv, self.pc, self.curve_params)
        new_shares = await trans.run_trans(gate_outputs, rand_values)
        print(new_shares)