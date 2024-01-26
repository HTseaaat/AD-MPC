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
from adkg.broadcast.optqrbc import optqrbc, optqrbc_dynamic

from adkg.preprocessing import PreProcessedElements

from adkg.mpc import TaskProgramRunner
from adkg.robust_rec import robust_reconstruct_admpc, Robust_Rec
from adkg.trans import Trans
from adkg.rand import Rand, Rand_Pre, Rand_Foll
from adkg.aprep import APREP
from adkg.utils.serilization import Serial

import math

import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.NOTSET)

class ADMPCMsgType:
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

        rectag = ADMPCMsgType.ROBUSTREC
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

    async def run_admpc(self, start_time, layer):
        if layer == 0: 

            w = 1
            if w > self.n - self.t: 
                rounds = math.ceil(w / (self.n - self.t))
            else: 
                rounds = 1

            if self.my_id == 0: 
                rbc_list = [0,4,5,6,7]
                broadcast_msg = None
                rbctag = f"{0}-B-RBC"
                send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
                logger.debug("[%d] Starting reliable broadcast", self.my_id)
                async def predicate(_m):
                    return True
                values = self.ZR(1)
                sr = Serial(self.G1)
                broadcast_msg = sr.serialize_f(values)
                output = asyncio.Queue()
                asyncio.create_task(
                optqrbc_dynamic(
                    rbctag,
                    self.my_id,
                    self.n+1,
                    self.t,
                    0,
                    predicate,
                    broadcast_msg,
                    output.put_nowait,
                    send,
                    recv,
                    rbc_list
                ))
                rbc_msg = await output.get()
                print(f"dealer id: 0 my id: {self.my_id} {rbc_msg}")
        else: 
        # elif self.my_id > 3:
            rbc_list = [0,4,5,6,7]
            broadcast_msg = None
            rbctag = f"{0}-B-RBC"
            send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
            logger.debug("[%d] Starting reliable broadcast", self.my_id)
            async def predicate(_m):
                return True

            output = asyncio.Queue()
            asyncio.create_task(
            optqrbc_dynamic(
                rbctag,
                self.my_id+1,
                self.n+1,
                self.t,
                0,
                predicate,
                broadcast_msg,
                output.put_nowait,
                send,
                recv,
                rbc_list
            ))
            
            rbc_msg = await output.get()
            print(f"dealer id: 0 my id: {self.my_id} {rbc_msg}")



            

            
            

            # step2_start_time = time.time()
            # randtag = ADMPCMsgType.GENRAND
            # randsend, randrecv = self.get_send(randtag), self.subscribe_recv(randtag)
            # rand = Rand_Pre(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.my_id, randsend, randrecv, self.pc, self.curve_params, self.matrix)
            # await rand.run_rand(w, rounds)
            # step2_time = time.time() - step2_start_time
            # print(f"step 2 time: {step2_time}")
            
            # w, rounds = 1, 1
            # step2_start_time = time.time()
            # randtag = ADMPCMsgType.GENRAND
            # randsend, randrecv = self.get_send(randtag), self.subscribe_recv(randtag)
            # rand = Rand_Foll(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.my_id, randsend, randrecv, self.pc, self.curve_params, self.matrix)
            
            # # 这里的应该根据上一层 dealer 的个数来构建一个数组，并行调用 Rand_foll 的 run_rand，这里的 2 是因为我们测试的时候 dealer 只有 2 个
            # rand_foll_tasks = [None] * 2
            # for i in range(2): 
            #     rand_foll_tasks[i] = asyncio.create_task(rand.run_rand(w, rounds, i))
            # await asyncio.gather(*rand_foll_tasks)
            # # await rand.run_rand(w, rounds)
            # step2_time = time.time() - step2_start_time
            # print(f"step 2 time: {step2_time}")

        # 这里是 execution stage 的 step 2，调用 rand 协议为下一层生成随机数
        # w 是需要生成的随机数的数量
        # if self.my_id < 2:

        #     w = 1

        #     if w > self.n - self.t: 
        #         rounds = math.ceil(w / (self.n - self.t))
        #     else: 
        #         rounds = 1

            

        #     step2_start_time = time.time()
        #     randtag = ADMPCMsgType.GENRAND
        #     randsend, randrecv = self.get_send(randtag), self.subscribe_recv(randtag)
        #     rand = Rand_Pre(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.my_id, randsend, randrecv, self.pc, self.curve_params, self.matrix)
        #     await rand.run_rand(w, rounds)
        #     step2_time = time.time() - step2_start_time
        #     print(f"step 2 time: {step2_time}")
        # else: 
            
            
        #     w, rounds = 1, 1
        #     step2_start_time = time.time()
        #     randtag = ADMPCMsgType.GENRAND
        #     randsend, randrecv = self.get_send(randtag), self.subscribe_recv(randtag)
        #     rand = Rand_Foll(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.my_id, randsend, randrecv, self.pc, self.curve_params, self.matrix)
            
        #     # 这里的应该根据上一层 dealer 的个数来构建一个数组，并行调用 Rand_foll 的 run_rand，这里的 2 是因为我们测试的时候 dealer 只有 2 个
        #     rand_foll_tasks = [None] * 2
        #     for i in range(2): 
        #         rand_foll_tasks[i] = asyncio.create_task(rand.run_rand(w, rounds, i))
        #     await asyncio.gather(*rand_foll_tasks)
        #     # await rand.run_rand(w, rounds)
        #     step2_time = time.time() - step2_start_time
        #     print(f"step 2 time: {step2_time}")

        