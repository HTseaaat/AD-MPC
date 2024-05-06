from adkg.polynomial import polynomials_over, EvalPoint
from adkg.utils.poly_misc import interpolate_g1_at_x
from adkg.utils.misc import wrap_send, subscribe_recv
import asyncio
import hashlib, time
from math import ceil
import logging
from adkg.utils.bitmap import Bitmap
from adkg.acss import ACSS, ACSS_Foll, ACSS_Pre, ACSS_Fluid_Pre, ACSS_Fluid_Foll
from adkg.router import SimpleRouter

from adkg.broadcast.tylerba import tylerba
from adkg.broadcast.optqrbc import optqrbc, optqrbc_dynamic

from adkg.preprocessing import PreProcessedElements

from adkg.mpc import TaskProgramRunner
from adkg.robust_rec import robust_reconstruct_admpc, Robust_Rec
from adkg.trans import Trans, Trans_Pre, Trans_Foll, Trans_Fluid_Foll, Trans_Fluid_Pre
from adkg.rand import Rand, Rand_Pre, Rand_Foll, Rand_Fluid_Pre, Rand_Fluid_Foll
from adkg.aprep import APREP, APREP_Pre, APREP_Foll
import math

from adkg.utils.serilization import Serial
from adkg.field import GF, GFElement
from adkg.elliptic_curve import Subgroup

import random
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

    async def robust_rec_step(self, rec_shares, index):         

        # self.rectasks = [None] * len(rec_shares)
        # for i in range(len(rec_shares)): 
        #     self.rectasks[i] = asyncio.create_task(self.rec.run_robust_rec(i, rec_shares[i]))
        # rec_values = await asyncio.gather(*self.rectasks)
        # print(f"my id: {self.my_id} rec_values: {rec_values}")

        # return rec_values
        rec_values = await self.rec.batch_run_robust_rec(index, rec_shares)

        # # rec_signal.set()
        return rec_values
    
    async def mult(self, mult_values, mult_triples): 
        gamma_list, epsilon_list = [None] * len(mult_values), [None] * len(mult_values)
        
        batch_rec_list = []
        for i in range(len(mult_values)): 
            gamma_list[i] = mult_values[i][0] - mult_triples[i][0]
            epsilon_list[i] = mult_values[i][1] - mult_triples[i][1]
            batch_rec_list.append(gamma_list[i])
            batch_rec_list.append(epsilon_list[i])
        # gamma = mult_values[0] - mult_triples[0]
        # epsilon = mult_values[1] - mult_triples[1]

        # batch_rec_list = []
        # batch_rec_list.append(gamma_list)
        # batch_rec_list.append(epsilon_list)

        # robust_rec_signal = asyncio.Event()
        sttime = time.time()
        # rec_gamma = await self.robust_rec_step(gamma, 0)
        
        # await robust_rec_signal.wait()
        # robust_rec_signal.clear()
        # rec_epsilon = await self.robust_rec_step(epsilon, 1)
        # await robust_rec_signal.wait()
        # robust_rec_signal.clear()

        rec_values = await self.robust_rec_step(batch_rec_list, 0)
        num = 0
        rec_gamma_list, rec_epsilon_list = [], []
        for i in range(len(mult_values)):
            rec_gamma_list.append(rec_values[num])
            rec_epsilon_list.append(rec_values[num+1])
            num += 2
        mult_outputs = [None] * len(mult_values)
        for i in range(len(mult_values)):
            mult_outputs[i] = mult_triples[i][2] + rec_gamma_list[i] * mult_triples[i][1] + rec_epsilon_list[i] * mult_triples[i][0] + rec_gamma_list[i] * rec_epsilon_list[i]

        # rec_gamma, rec_epsilon = await asyncio.gather(self.robust_rec_step(gamma, 0), self.robust_rec_step(epsilon, 1))  
        print(f"sttime: {time.time()-sttime}")

        # mult_output = mult_triples[2] + rec_gamma * mult_triples[1] + rec_epsilon * mult_triples[0] + rec_gamma * rec_epsilon
        return mult_outputs

    
    async def run_computation(self, inputs, gate_tape, mult_triples):
        self.gates_num = int(len(inputs)/2)
        # 这里根据当前层门的数量对输入进行划分
        gate_input_values = [[self.ZR(0) for _ in range(2)] for _ in range(self.gates_num)]
        for i in range(self.gates_num): 
            for j in range(2): 
                gate_input_values[i][j] = inputs[i*2+j]
        # 输出存在这里
        gate_output_values = [None] * self.gates_num
        # 这两个用来记录当前层的乘法门位置和数量，用来做当前层乘法门的批处理
        batch_mult_gates, mult_pos = [], []
        triple_num = 0
        for i in range(self.gates_num): 
            # 这是加法
            if gate_tape[i] == 0: 
                gate_output_values[i] = gate_input_values[i][0] + gate_input_values[i][1]
            # 这是乘法
            else: 
                batch_mult_gates.append(gate_input_values[i])
                mult_pos.append(i)
                # gate_output_values[i] = await self.mult(gate_input_values[i], mult_triples[triple_num])
                # triple_num += 1
        batch_mult_outputs = await self.mult(batch_mult_gates, mult_triples)
        for i in range(len(mult_pos)): 
            gate_output_values[mult_pos[i]] = batch_mult_outputs[i]

        # self.output_queue.put_nowait(gate_output_values)
        return gate_output_values
    
    async def run_admpc(self, start_time):

        # 首先缺失了由上一层接收到的 shares
        # 这里先假设收到的输入存在 inputs 列表中
        # inputs = [self.ZR(2*(self.my_id+1)+3), self.ZR(3*(self.my_id+1)+2)]
        # gate_tape 表示当前层的电路门的 tape，0 代表加法，1 代表乘法
        # gate_tape = [1]
        # 这里缺失了由上一层提供的随机数，乘法三元组，以及上一层计算的输出
        # 先假设大家接收到的乘法三元组是 a() = x+5 b()=3x+2 c()=2x+10
        # mult_triples = [[self.ZR((self.my_id+1)+5), self.ZR(3*(self.my_id+1)+2), self.ZR(2*(self.my_id+1)+10)]]
        # 先假设生成的随机数 alpha()=2x+5
        # rand_values = [self.ZR(2*(self.my_id+1)+5)]

        tape_num = 4
        inputs = []
        gate_tape = []
        mult_triples = []
        rand_values = []
        for i in range(tape_num): 
            inputs.append(self.ZR(2*(self.my_id+1)+3))
            inputs.append(self.ZR(3*(self.my_id+1)+2))
            gate_tape.append(1)
            mult_triples.append([self.ZR((self.my_id+1)+5), self.ZR(3*(self.my_id+1)+2), self.ZR(2*(self.my_id+1)+10)])
            rand_values.append(self.ZR(2*(self.my_id+1)+5))



        # 这里是 execution stage 的 step 1，执行当前层的计算

        step1_start_time = time.time()
        gate_outputs = await self.run_computation(inputs, gate_tape, mult_triples)
        step1_time = time.time() - step1_start_time
        print(f"step 1 output: {gate_outputs}")

        # 这里是 execution stage 的 step 2，调用 rand 协议为下一层生成随机数
        # w 是需要生成的随机数的数量
        w = 100

        if w > self.n - self.t: 
            rounds = math.ceil(w / (self.n - self.t))
        else: 
            rounds = 1

        step2_start_time = time.time()
        randtag = ADMPCMsgType.GENRAND
        randsend, randrecv = self.get_send(randtag), self.subscribe_recv(randtag)
        rand = Rand(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.my_id, randsend, randrecv, self.pc, self.curve_params, self.matrix)
        rand_shares = await rand.run_rand(w, rounds)
        step2_time = time.time() - step2_start_time
        print(f"step 2 output: {rand_shares}")
        # print(f"rand_shares: {rand_shares}")

        # 这里是 execution stage 的 step 3，调用 Aprep 协议为下一层生成乘法三元组
        cm = 2

        step3_start_time = time.time()
        apreptag = ADMPCMsgType.APREP
        aprepsend, apreprecv = self.get_send(apreptag), self.subscribe_recv(apreptag)
        aprep = APREP_Pre(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.my_id, aprepsend, apreprecv, self.pc, self.curve_params, self.matrix)
        new_mult_triples = await aprep.run_aprep(cm)
        step3_time = time.time() - step3_start_time
        print(f"step 3 output: {new_mult_triples}")
        print(f"time: {step3_time}")
        # print(f"new_mult_triples: {new_mult_triples}")


        # 这里是 execution stage 的 step 4，调用 Trans 协议将当前层的电路输出传输到下一层
        step4_start_time = time.time()
        transtag = ADMPCMsgType.TRANS
        transsend, transrecv = self.get_send(transtag), self.subscribe_recv(transtag)
        trans = Trans(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.my_id, transsend, transrecv, self.pc, self.curve_params)
        new_shares = await trans.run_trans(gate_outputs, rand_values)
        step4_time = time.time() - step4_start_time
        print(f"step 4 output: {new_shares}")
        print(f"time: {step4_time}")
        # print(new_shares)
        # parallel_start_time = time.time()
        # rand_shares, new_shares = await asyncio.gather(rand.run_rand(w, rounds), trans.run_trans(gate_outputs, rand_values))
        # await asyncio.gather(rand.run_rand(w, rounds), trans.run_trans(gate_outputs, rand_values))
        # parallel_time = time.time() - parallel_start_time
        admpc_time = time.time() - start_time
        logging.info(f"admpc finished! n: {self.n} Node {self.my_id}, tape_num: {tape_num} step1_time: {step1_time}, w: {w} step2_time: {step2_time}, cm: {cm} step3_time: {step3_time}, step4_time: {step4_time} time: {admpc_time}")
        # logging.info(f"admpc finished! n: {self.n} Node {self.my_id}, tape_num: {tape_num} step1_time: {step1_time}, w: {w} parallel_time: {parallel_time} time: {admpc_time}")

from pypairing import ZR, G1, blsmultiexp as multiexp, dotprod
from adkg.router import SimpleRouter
from adkg.poly_commit_hybrid import PolyCommitHybrid
import numpy as np

def get_avss_params(n):
    g, h = G1.rand(b'g'), G1.rand(b'h')
    public_keys, private_keys = [None] * n, [None] * n
    for i in range(n):
        private_keys[i] = ZR.random()
        public_keys[i] = pow(g, private_keys[i])
    return g, h, public_keys, private_keys

def gen_vector(t, n, ZR):
    vm = np.array([[ZR(i+1)**j for j in range(n)] for i in range(n-t)])
    # print(f"vm: {vm}")
    print(f"vm.tolist(): {vm.tolist()}")

    return (vm.tolist())


# 管理所有的MPC实例
class ADMPC_Multi_Layer_Control():
    def __init__(self, n=None, t= None, deg=None, layer_num=None, total_cm=None, pks=None):
        # 初始化
        self.n = n
        self.t = t
        self.deg = deg
        self.layer_num = layer_num
        self.total_cm = total_cm
        self.control_signal = asyncio.Event()
        self.pks_all = [[None] * self.n for _ in range(self.layer_num)]
        if pks is not None: 
            for layerID in range(self.layer_num): 
                self.pks_all[layerID] = pks[self.n*layerID:self.n*layerID+self.n]

    async def add(self):
        """生成 layer_num * n 个mpc instances(存在self.admpc_lists中,具体的run_admpc存在admpc_tasks中)"""
        # 初始化公钥组（包含所有mpc instance的公钥）
        self.pks_all = [[None] * self.n for _ in range(self.layer_num)]      # 存储格式是：pks_all = [[第一层所有公钥]，[第二层所有公钥],...,[最后一层公钥]]
        # 初始化admpc_lists(存储所有mpc instances)
        self.admpc_lists = [[None] * self.n for _ in range(self.layer_num)]
        self.admpc_tasks = [[None] * self.n for _ in range(self.layer_num)]

        # router应该同id共用一个吗？
        router = SimpleRouter(self.n * self.layer_num)

        curve_params = (ZR, G1, multiexp, dotprod)

        start_time = time.time()

        g, h, pks, sks = get_avss_params(self.n * self.layer_num)
        pc = PolyCommitHybrid(g, h, ZR, multiexp)
        mat = gen_vector(self.t, self.n, ZR)

        # 生成所有 MPC 实例
        for layerID in range(self.layer_num):
            # 生成每一层的mpc instances
            self.pks_all[layerID] = pks[self.n*layerID:self.n*layerID+self.n]
            
            # 生成 layerID 层中的每一个MPC实例
            for i in range(self.n):
                # 这里的 pks 可能会有问题，由于不知道上一层的 dealer 的 pk 从而在 predicate 那里验证错误
                admpc = ADMPC_Dynamic(self.pks_all[layerID], sks[self.n * layerID + i], 
                                      g, h, self.n, self.t, self.deg, i, 
                                      router.sends[self.n * layerID + i], router.recvs[self.n * layerID + i], 
                                      pc, curve_params, mat, layerID, admpc_control_instance=self)
                self.admpc_lists[layerID][i] = admpc
                self.admpc_tasks[layerID][i] = asyncio.create_task(admpc.run_admpc(start_time))
            
        # TODO:我应该在哪里await？(应不应该移动到循环外)
        for layerID in range(self.layer_num):
            await asyncio.gather(*(self.admpc_tasks[layerID]))
        # await asyncio.gather(*(self.admpc_tasks[1]))

    

# 增加一个ADMPC的子类
# 我们需要在这个子类中能够引用控制所有MPC的ADMPC_Multi_Layer_Control 实例
# 而且每个Node要知道自己在第几层
class ADMPC_Dynamic(ADMPC):
    def __init__(self, public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, matrices, total_cm, layerID = None, admpc_control_instance=None):
        # 给每个MPC实例增加了self.admpc_control_instance的属性，使得能够通过这个属性访问控制所有MPC实例的类，从而访问对应的公钥组等
        self.admpc_control_instance = admpc_control_instance if admpc_control_instance is not None else ADMPC_Multi_Layer_Control(n=n, t=t, deg=deg, layer_num=int(len(public_keys)/n), total_cm=total_cm, pks=public_keys)
        self.layer_ID = layerID
        # self.public_keys = public_keys[n*layerID:n*layerID+n]
        self.sc = ceil((deg+1)/(t+1)) + 1
        # 往自己signal_list里面放一个signal
        self.Signal = asyncio.Event()
        super().__init__(public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, matrices)

    async def robust_rec_step(self, rec_shares, index):         

        # self.rectasks = [None] * len(rec_shares)
        # for i in range(len(rec_shares)): 
        #     self.rectasks[i] = asyncio.create_task(self.rec.run_robust_rec(i, rec_shares[i]))
        # rec_values = await asyncio.gather(*self.rectasks)
        # print(f"my id: {self.my_id} rec_values: {rec_values}")

        # return rec_values
        member_list = []
        for i in range(self.n): 
            member_list.append(self.n * (self.layer_ID) + i)
        rec_values = await self.rec.batch_run_robust_rec(index, rec_shares, member_list)

        # # rec_signal.set()
        return rec_values
    
    async def mult(self, mult_values, mult_triples): 
        gamma_list, epsilon_list = [None] * len(mult_values), [None] * len(mult_values)
        
        batch_rec_list = []
        for i in range(len(mult_values)): 
            gamma_list[i] = mult_values[i][0] - mult_triples[i][0]
            epsilon_list[i] = mult_values[i][1] - mult_triples[i][1]
            batch_rec_list.append(gamma_list[i])
            batch_rec_list.append(epsilon_list[i])
        # gamma = mult_values[0] - mult_triples[0]
        # epsilon = mult_values[1] - mult_triples[1]

        # batch_rec_list = []
        # batch_rec_list.append(gamma_list)
        # batch_rec_list.append(epsilon_list)

        # robust_rec_signal = asyncio.Event()
        sttime = time.time()
        # rec_gamma = await self.robust_rec_step(gamma, 0)
        
        # await robust_rec_signal.wait()
        # robust_rec_signal.clear()
        # rec_epsilon = await self.robust_rec_step(epsilon, 1)
        # await robust_rec_signal.wait()
        # robust_rec_signal.clear()

        rec_values = await self.robust_rec_step(batch_rec_list, 0)
        num = 0
        rec_gamma_list, rec_epsilon_list = [], []
        for i in range(len(mult_values)):
            rec_gamma_list.append(rec_values[num])
            rec_epsilon_list.append(rec_values[num+1])
            num += 2
        mult_outputs = [None] * len(mult_values)
        for i in range(len(mult_values)):
            mult_outputs[i] = mult_triples[i][2] + rec_gamma_list[i] * mult_triples[i][1] + rec_epsilon_list[i] * mult_triples[i][0] + rec_gamma_list[i] * rec_epsilon_list[i]

        # rec_gamma, rec_epsilon = await asyncio.gather(self.robust_rec_step(gamma, 0), self.robust_rec_step(epsilon, 1))  
        print(f"sttime: {time.time()-sttime}")

        # mult_output = mult_triples[2] + rec_gamma * mult_triples[1] + rec_epsilon * mult_triples[0] + rec_gamma * rec_epsilon
        return mult_outputs

    
    async def run_computation(self, inputs, gate_tape, mult_triples):
        # 这里简化一下，后面的代码是正常的执行计算的过程，这里为了方便测试作了简化，只计算乘法
        self. gates_num = len(gate_tape)
        gate_input_values = [[self.ZR(0) for _ in range(2)] for _ in range(self.gates_num)]
        for i in range(self.gates_num): 
            for j in range(2): 
                gate_input_values[i][j] = inputs[j]
        # 输出存在这里
        gate_output_values = [None] * self.gates_num
        # 这两个用来记录当前层的乘法门位置和数量，用来做当前层乘法门的批处理
        batch_mult_gates, mult_pos = [], []
        triple_num = 0
        for i in range(self.gates_num): 
            # 这是加法
            if gate_tape[i] == 0: 
                gate_output_values[i] = gate_input_values[i][0] + gate_input_values[i][1]
            # 这是乘法
            else: 
                batch_mult_gates.append(gate_input_values[i])
                mult_pos.append(i)
                # gate_output_values[i] = await self.mult(gate_input_values[i], mult_triples[triple_num])
                # triple_num += 1
        batch_mult_outputs = await self.mult(batch_mult_gates, mult_triples)
        for i in range(len(mult_pos)): 
            gate_output_values[mult_pos[i]] = batch_mult_outputs[i]

        # self.output_queue.put_nowait(gate_output_values)
        return gate_output_values


        # self.gates_num = int(len(inputs)/2)
        # # 这里根据当前层门的数量对输入进行划分
        # gate_input_values = [[self.ZR(0) for _ in range(2)] for _ in range(self.gates_num)]
        # for i in range(self.gates_num): 
        #     for j in range(2): 
        #         gate_input_values[i][j] = inputs[i*2+j]
        # # 输出存在这里
        # gate_output_values = [None] * self.gates_num
        # # 这两个用来记录当前层的乘法门位置和数量，用来做当前层乘法门的批处理
        # batch_mult_gates, mult_pos = [], []
        # triple_num = 0
        # for i in range(self.gates_num): 
        #     # 这是加法
        #     if gate_tape[i] == 0: 
        #         gate_output_values[i] = gate_input_values[i][0] + gate_input_values[i][1]
        #     # 这是乘法
        #     else: 
        #         batch_mult_gates.append(gate_input_values[i])
        #         mult_pos.append(i)
        #         # gate_output_values[i] = await self.mult(gate_input_values[i], mult_triples[triple_num])
        #         # triple_num += 1
        # batch_mult_outputs = await self.mult(batch_mult_gates, mult_triples)
        # for i in range(len(mult_pos)): 
        #     gate_output_values[mult_pos[i]] = batch_mult_outputs[i]

        # # self.output_queue.put_nowait(gate_output_values)
        # return gate_output_values
    
    
    async def commonsubset(self, rbc_out, rbc_signal, rbc_values, coin_keys, aba_in, aba_out):
        assert len(rbc_out) == self.n
        assert len(aba_in) == self.n
        assert len(aba_out) == self.n

        aba_inputted = [False]*self.n
        aba_values = [0]*self.n

        async def _recv_rbc(j):
            # rbc_values[j] = await rbc_out[j]
            rbcl = await rbc_out[j].get()
            # print(f"rbcl: {rbcl}")
            rbcb = Bitmap(self.n, rbcl)
            # print(f"rbcb: {rbcb}")
            rbc_values[j] = []
            # for i in range(self.n): 
            #     print(f"{self.my_id} receives {i} {rbcb.get_bit(i)}")
            for i in range(self.n):
                if rbcb.get_bit(i):
                    rbc_values[j].append(i)
            # print(f"rbc_values[{j}]: {rbc_values[j]}")        
            
            if not aba_inputted[j]:
                aba_inputted[j] = True
                aba_in[j](1)
            
            subset = True
            # while True:
            #     acss_signal.clear()
            #     for k in rbc_values[j]:
            #         if k not in acss_outputs.keys():
            #             subset = False
            #     if subset:
            #         coin_keys[j]((acss_outputs, rbc_values[j]))
            #         return
            #     await acss_signal.wait()

        r_threads = [asyncio.create_task(_recv_rbc(j)) for j in range(self.n)]

        async def _recv_aba(j):
            aba_values[j] = await aba_out[j]()  # May block

            if sum(aba_values) >= 1:
                # Provide 0 to all other aba
                for k in range(self.n):
                    if not aba_inputted[k]:
                        aba_inputted[k] = True
                        aba_in[k](0)
        
        await asyncio.gather(*[asyncio.create_task(_recv_aba(j)) for j in range(self.n)])
        # assert sum(aba_values) >= self.n - self.t  # Must have at least N-f committed
        assert sum(aba_values) >= 1  # Must have at least N-f committed

        # Wait for the corresponding broadcasts
        for j in range(self.n):
            if aba_values[j]:
                await r_threads[j]
                assert rbc_values[j] is not None
            else:
                r_threads[j].cancel()
                rbc_values[j] = None

        rbc_signal.set()
    
    async def agreement(self, key_proposal):
        
        aba_inputs = [asyncio.Queue() for _ in range(self.n)]
        aba_outputs = [asyncio.Queue() for _ in range(self.n)]
        rbc_outputs = [asyncio.Queue() for _ in range(self.n)]
        
        coin_keys = [asyncio.Queue() for _ in range(self.n)]

        member_list = []
        for i in range(self.n): 
            member_list.append(self.n * (self.layer_ID) + i)

        async def predicate(_key_proposal):
            kp = Bitmap(self.n, _key_proposal)
            kpl = []
            for ii in range(self.n):
                if kp.get_bit(ii):
                    kpl.append(ii)
            # print(f"kpl: {kpl}")
            # print(f"de_masked_value: {de_masked_value}")
            if len(kpl) <= self.t:
                return False
            
            
            return True

        async def _setup(j):
            
            # starting RBC
            rbctag = ADMPCMsgType.RBC + str(j) # (R, msg)
            # rbctag = TRANSMsgType.RBC + str(j)
            rbcsend, rbcrecv = self.get_send(rbctag), self.subscribe_recv(rbctag)

            rbc_input = None
            if j == self.my_id: 
                # print(f"key_proposal: {key_proposal}")
                riv = Bitmap(self.n)
                for k in key_proposal: 
                    riv.set_bit(k)
                rbc_input = bytes(riv.array)

            # rbc_outputs[j] = 
            asyncio.create_task(
                optqrbc_dynamic(
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
                    member_list
                )
            )

            abatag = ADMPCMsgType.ABA + str(j) # (B, msg)
            # abatag = TRANSMsgType.ABA + str(j)
            # abatag = j # (B, msg)
            abasend, abarecv =  self.get_send(abatag), self.subscribe_recv(abatag)

            def bcast(o):
                for i in range(len(member_list)):
                    abasend(member_list[i], o)
                
            aba_task = asyncio.create_task(
                tylerba(
                    abatag,
                    self.my_id,
                    self.n,
                    self.t,
                    coin_keys[j].get,
                    aba_inputs[j].get,
                    aba_outputs[j].put_nowait,
                    bcast,
                    abarecv,
                )
            )
            return aba_task

        work_tasks = await asyncio.gather(*[_setup(j) for j in range(self.n)])
        
        rbc_signal = asyncio.Event()
        rbc_values = [None for i in range(self.n)]

        return (
            self.commonsubset(
                rbc_outputs,
                rbc_signal,
                rbc_values,
                [_.put_nowait for _ in coin_keys],
                [_.put_nowait for _ in aba_inputs],
                [_.get for _ in aba_outputs],
            ),
            self.new_subset(
                rbc_values,
                rbc_signal,
                
            ),
            work_tasks,
        )

    async def new_subset(self, rbc_values, rbc_signal):
        await rbc_signal.wait()
        rbc_signal.clear()

        # 这一步是将所有 rbc_values 转化成一个公共子集 mks
        # print(f"rbc_values: {rbc_values}")
        self.mks = set() # master key set
        for ks in  rbc_values:
            if ks is not None:
                self.mks = self.mks.union(set(list(ks)))
                if len(self.mks) >= self.n-self.t:
                    break

        mks_list = sorted(self.mks)
        

        return mks_list

    # async def masked_values(): 
    
    
    async def run_admpc(self, start_time):
        acss_start_time = time.time()
        self.public_keys = self.public_keys[self.n*self.layer_ID:self.n*self.layer_ID+self.n]
        cm = int(self.admpc_control_instance.total_cm/(self.admpc_control_instance.layer_num-4))
        # 这里电路宽度还是 cm * 2，额外多的两个 MAC check的单独加
        w = cm * 2
        # 这里 input_num 指的是除了要计算原始电路以外，还要计算带 MAC 的电路，rz1+rz2
        input_num = w * 2
        print(f"cm: {cm} total_cm: {self.admpc_control_instance.total_cm}")

        # 这里测试每个 committee 中的 my_id = 9 的节点是拜占庭节点，他不发送消息
        # if self.my_id != 9: 
        # 计算每层的时间
        layer_time = time.time()

        # 我们假设 layer_ID = 0 时是 clients 提供输入给 servers
        if self.layer_ID == 0:

            # 客户端的输入的 values 数目要等于 2 * w
            inputs_num = int((2*(w))/self.n) + 1
            clients_inputs = []
            for i in range(inputs_num):
                clients_inputs.append(self.ZR.rand())
            
            # # clients step 1 传递输入给下一层
            # clients_inputs = [self.ZR.rand()]

            # 此处传递的公钥应该是下一层的公钥
            acss_pre_time = time.time()
            pks_next_layer = self.admpc_control_instance.pks_all[self.layer_ID + 1]       # 下一层的公钥组

            # 这里 ADKGMsgType.ACSS 都是 acss 有可能会和接下来的 trans 协议冲突
            acsstag = ADMPCMsgType.ACSS + str(self.layer_ID+1) + str(self.my_id)
            acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

            self.acss = ACSS_Fluid_Pre(pks_next_layer, 
                                self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                                acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                                mpc_instance=self
                            )
            self.acss_tasks = [None] * self.n
            # 在上一层中只需要创建一次avss即可        
            self.acss_tasks[self.my_id] = asyncio.create_task(self.acss.avss(0, values=clients_inputs))
            await self.acss_tasks[self.my_id]
            acss_pre_time = time.time() - acss_pre_time
            print(f"layer ID: {self.layer_ID} acss_pre_time: {acss_pre_time}")

            # clients step 2 调用 Rand 协议传递随机数给下一层
            # w 是需要生成的随机数的数量
            # 由于 Fluid MPC 的特性，要再加个2
            rand_pre_time = time.time()
            mac_keys = w + 2
            if mac_keys > self.n - self.t: 
                rounds = math.ceil(mac_keys / (self.n - self.t))
            else: 
                rounds = 1

            randtag = ADMPCMsgType.GENRAND + str(self.layer_ID+1)
            randsend, randrecv = self.get_send(randtag), self.subscribe_recv(randtag)

            rand_pre = Rand_Fluid_Pre(self.public_keys, self.private_key, 
                                self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                                randsend, randrecv, self.pc, self.curve_params, self.matrix, mpc_instance=self)
            rand_pre_task = asyncio.create_task(rand_pre.run_rand(mac_keys, rounds))
            await rand_pre_task
            rand_pre_time = time.time() - rand_pre_time
            print(f"layer ID: {self.layer_ID} rand_pre_time: {rand_pre_time}")

            
            # 没有办法用 signal 来控制不同层的传输，因此这里先设置一个 sleep 信号，后面得改
            # await asyncio.sleep(30)

        elif self.layer_ID == 1: 
            # servers 在执行当前层的计算之前需要：1. 接收来自上一层的输入（这里注意区分layer=1的情况）2.接收上一层的随机数，3.接收上一层的三元组
            # await self.admpc_control_instance.control_signal.wait()
            # self.admpc_control_instance.control_signal.clear()
            # 这是 step 1 接收上一层的输出（这里注意区分layer=1的情况）
            recv_input_time = time.time()
            self.acss_tasks = [None] * self.n
            # for dealer_id in range(self.n - 1, -1, -1): 
            for dealer_id in range(self.n): 
                # 这里 ADKGMsgType.ACSS 都是 acss 有可能会和接下来的 trans 协议冲突
                acsstag = ADMPCMsgType.ACSS + str(self.layer_ID) + str(dealer_id)
                acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

                # 此时传递的是本层的公私钥
                self.acss = ACSS_Fluid_Foll(self.public_keys, self.private_key, 
                                    self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                                    acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                                    mpc_instance=self
                                )
                # 这里的 rounds 也是手动更改的
                rounds = 13
                self.acss_tasks[dealer_id] = asyncio.create_task(self.acss.avss(0, dealer_id, rounds))


                # 对于每一个dealer ID，下一层都要创一个来接受这个dealer ID分发的ACSS实例
            # results = await asyncio.gather(*self.acss_tasks)
            # for result in results: 
            #     (dealer, _, shares, commitments) = result
            #     print(f"in for layer ID: {self.layer_ID} my id: {self.my_id} dealer: {dealer}")
            # dealer, _, shares, commitments = zip(*results)
            # print(f"layer ID: {self.layer_ID} my id: {self.my_id} dealer: {dealer}")
                
            done, pending = await asyncio.wait(self.acss_tasks, return_when=asyncio.ALL_COMPLETED)
    
            # 从完成的任务中收集结果
            results = [task.result() for task in done]
            dealer, _, shares, commitments = zip(*results)
            print(f"layer ID: {self.layer_ID} my id: {self.my_id} dealers: {dealer}")
                
            # 这里增加的代码是改进的 Fluid MPC 的代码，增加了MVBA 的过程，来共识一个公共子集
            # 这一步是 MVBA 的过程
            fluid_mvba_time = time.time()
            key_proposal = []
            # for i in range(self.n - self.t): key_proposal.append(dealer[i])
            key_proposal = random.sample(dealer, self.n - self.t)  # 从dealer随机选择n-t个不重复的元素
            create_acs_task = asyncio.create_task(self.agreement(key_proposal))

            acs, key_task, work_tasks = await create_acs_task
            await acs
            subset = await key_task
            await asyncio.gather(*work_tasks)
            fluid_mvba_time = time.time() - fluid_mvba_time
            print(f"fluid_mvba_time: {fluid_mvba_time} layer ID: {self.layer_ID} my id: {self.my_id} common_subset: {subset}")
            
            new_shares = []
            for i in range(len(dealer)): 
                for j in range(len(shares[i]['msg'])): 
                    new_shares.append(shares[i]['msg'][j])
            recv_input_time = time.time() - recv_input_time
            print(f"layer ID: {self.layer_ID} recv_input_time: {recv_input_time}")

            
            # 这是 step 2 接收上一层的随机数
            rand_foll_time = time.time()
            randtag = ADMPCMsgType.GENRAND + str(self.layer_ID)
            randsend, randrecv = self.get_send(randtag), self.subscribe_recv(randtag)
            rand_foll = Rand_Fluid_Foll(self.public_keys, self.private_key, 
                                self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                                randsend, randrecv, self.pc, self.curve_params, self.matrix, mpc_instance=self)
            # 这里我们假设当前层的 servers 知道需要生成多少个随机数，在这里就直接设置，这里也是手动改得
            # w = int(len(new_shares)/2)
            # 这里接收的是 Fluid MPC 的 MAC keys 
            mac_keys = w + 2
            if mac_keys > self.n - self.t: 
                rounds = math.ceil(mac_keys / (self.n - self.t))
            else: 
                rounds = 1
            # w, rounds = 2, 1           
            rand_shares = await rand_foll.run_rand(mac_keys, rounds)
            rand_foll_time = time.time() - rand_foll_time
            print(f"layer ID: {self.layer_ID} rand_foll_time: {rand_foll_time} len rand_shares: {len(rand_shares)} len new_shares: {len(new_shares)}")
            
            
            # 这里的 execution stage 需要将输入乘以一个随机数 r
            input_shares = [None] * input_num
            masked_shares = [None] * input_num
            for i in range(input_num):
                masked_shares[i] = new_shares[0] * rand_shares[0]
                input_shares[i] = new_shares[0]
            print(f"here?")

            if self.layer_ID + 1 < len(self.admpc_control_instance.pks_all):
            # if self.admpc_control_instance.pks_all[self.layer_ID + 1] is not None: 
                # 这里我们需要把 原始输入、乘以随机数的输入以及所有随机数传递给下一层
                print(f"enter if")
                trans_values = input_shares + masked_shares + rand_shares
                acss_pre_time = time.time()
                pks_next_layer = self.admpc_control_instance.pks_all[self.layer_ID + 1]       # 下一层的公钥组

                # 这里 ADKGMsgType.ACSS 都是 acss 有可能会和接下来的 trans 协议冲突
                acsstag = ADMPCMsgType.ACSS + str(self.layer_ID+1) + str(self.my_id)
                acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

                self.acss = ACSS_Fluid_Pre(pks_next_layer, 
                                    self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                                    acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                                    mpc_instance=self
                                )
                self.acss_tasks = [None] * self.n
                # 在上一层中只需要创建一次avss即可     
                # test_value = [trans_values[0]]
                print(f"len trans_values: {len(trans_values)}")
                
                self.acss_tasks[self.my_id] = asyncio.create_task(self.acss.avss(0, values=trans_values))

                await self.acss_tasks[self.my_id]
                
                acss_pre_time = time.time() - acss_pre_time
                print(f"layer ID: {self.layer_ID} acss_pre_time: {acss_pre_time}")
                
                print("end")
                # await asyncio.sleep(30)
            else: 
                print("over")
        elif self.layer_ID == 2: 
            print(f"ok")
            recv_input_time = time.time()
            self.acss_tasks = [None] * self.n
            for dealer_id in range(self.n): 
                # 这里 ADKGMsgType.ACSS 都是 acss 有可能会和接下来的 trans 协议冲突
                acsstag = ADMPCMsgType.ACSS + str(self.layer_ID) + str(dealer_id)
                acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

                # 此时传递的是本层的公私钥
                self.acss = ACSS_Fluid_Foll(self.public_keys, self.private_key, 
                                    self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                                    acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                                    mpc_instance=self
                                )
                # 这里的 rounds 也是手动更改的
                # 在这一层，layer = 2，接收到的 shares 的数目组成分为以下几块，原始输入 + 乘以r的masked_values + 随机数(w+2)
                rounds = input_num * 2 + w + 2
                self.acss_tasks[dealer_id] = asyncio.create_task(self.acss.avss(0, dealer_id, rounds))


                # 对于每一个dealer ID，下一层都要创一个来接受这个dealer ID分发的ACSS实例
            done, pending = await asyncio.wait(self.acss_tasks, return_when=asyncio.ALL_COMPLETED)
    
                                                   
    
            # # 从完成的任务中收集结果
            results = [task.result() for task in done]
            dealer, _, shares, commitments = zip(*results)
            print(f"layer ID: {self.layer_ID} my id: {self.my_id} dealers: {dealer}")


            # 这里增加的代码是改进的 Fluid MPC 的代码，增加了MVBA 的过程，来共识一个公共子集
            # 这一步是 MVBA 的过程
            fluid_mvba_time = time.time()
            key_proposal = []
            # for i in range(self.n - self.t): key_proposal.append(dealer[i])
            key_proposal = random.sample(dealer, self.n - self.t)  # 从dealer随机选择n-t个不重复的元素
            create_acs_task = asyncio.create_task(self.agreement(key_proposal))

            acs, key_task, work_tasks = await create_acs_task
            await acs
            subset = await key_task
            await asyncio.gather(*work_tasks)
            fluid_mvba_time = time.time() - fluid_mvba_time
            print(f"fluid_mvba_time: {fluid_mvba_time} layer ID: {self.layer_ID} my id: {self.my_id} common_subset: {subset}")
            
            new_shares = []
            for i in range(len(dealer)): 
                for j in range(len(shares[i]['msg'])): 
                    new_shares.append(shares[i]['msg'][j])
            recv_input_time = time.time() - recv_input_time
            print(f"layer ID: {self.layer_ID} recv_input_time: {recv_input_time}")

            # 这一步骤模拟的是 下一层委员会在接收到 shares 在执行 插值
            inter_shares = [[None for i in range(self.n)] for j in range(rounds)]
            for i in range(rounds):
                for j in range(self.n):
                    inter_shares[i][j] = new_shares[i*self.n+j]

            sc_shares = [] 
            for i in range(len(inter_shares)): 
                sc_shares.append([])
                for j in range(len(inter_shares[0])): 
                    sc_shares[i].append([j+1, inter_shares[i][j]])            
            
            rec_shares = [None] * len(inter_shares)
            fluid_interpolate_time = time.time()
            for i in range(len(inter_shares)): 
                rec_shares[i] = self.poly.interpolate_at(sc_shares[i], 0)
            fluid_interpolate_time = time.time() - fluid_interpolate_time
            print(f"layer ID: {self.layer_ID} fluid_interpolate_time: {fluid_interpolate_time}")
            # print(f"rec_shares: {rec_shares}")

            # 这里的 execution stage 需要执行当前层的计算
            # 需要执行的计算有：a*b, ra*b, \alpha*\beta, \alpha*c, \alpha*rc
            input_shares = rec_shares[:input_num]
            masked_shares = rec_shares[input_num:2*input_num]
            rand_shares = rec_shares[2*input_num:]
            output_shares = [None] * w
            output_masked_shares = [None] * w
            current_rand_shares = [None] * w
            rand_last_layer_outputs = [None] * w
            rand_last_layer_masked_outputs = [None] * w
            for i in range(w):
                output_shares[i] = input_shares[0] * input_shares[1]    # a*b
                output_masked_shares[i] = input_shares[0] * masked_shares[0]    # ra*b
                current_rand_shares[i] = rand_shares[1] * rand_shares[2]    # \alpha*\beta
                rand_last_layer_outputs[i] = rand_shares[2] * input_shares[0]   # \alpha*c
                rand_last_layer_masked_outputs[i] = rand_shares[2] * masked_shares[0]   # \alpha*rc

            # 这里我们需要把 原始输入、乘以随机数的输入以及所有随机数传递给下一层 6 * w + 2
            # trans_values = output_shares + output_shares + output_masked_shares + output_masked_shares + current_rand_shares + rand_last_layer_outputs + rand_last_layer_outputs + rand_last_layer_masked_outputs + rand_last_layer_masked_outputs + rand_shares
            
            trans_values = output_shares + output_masked_shares + current_rand_shares + rand_last_layer_outputs + rand_last_layer_masked_outputs + rand_shares
            
            acss_pre_time = time.time()
            pks_next_layer = self.admpc_control_instance.pks_all[self.layer_ID + 1]       # 下一层的公钥组

            # 这里 ADKGMsgType.ACSS 都是 acss 有可能会和接下来的 trans 协议冲突
            acsstag = ADMPCMsgType.ACSS + str(self.layer_ID+1) + str(self.my_id)
            acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

            self.acss = ACSS_Fluid_Pre(pks_next_layer, 
                                self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                                acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                                mpc_instance=self
                            )
            self.acss_tasks = [None] * self.n
            # 在上一层中只需要创建一次avss即可     
            test_value = [trans_values[0]]
            print(f"len trans_values: {len(trans_values)}")
            self.acss_tasks[self.my_id] = asyncio.create_task(self.acss.avss(0, values=trans_values))
            await self.acss_tasks[self.my_id]
            acss_pre_time = time.time() - acss_pre_time
            print(f"layer ID: {self.layer_ID} acss_pre_time: {acss_pre_time}")
                
            print("end")

        
        else:
        # elif self.layer_ID == 3: 
            # servers 在执行当前层的计算之前需要：1. 接收来自上一层的输入（这里注意区分layer=1的情况）2.接收上一层的随机数，3.接收上一层的三元组
            # await self.admpc_control_instance.control_signal.wait()
            # self.admpc_control_instance.control_signal.clear()
            # 这是 step 1 接收上一层的输出（这里注意区分layer=1的情况）
            # 这个 if 表示的是client 接收shares 并重构最后的输出
            if self.layer_ID + 1 == len(self.admpc_control_instance.pks_all):
                recv_input_time = time.time()
                self.acss_tasks = [None] * self.n
                for dealer_id in range(self.n): 
                    # 这里 ADKGMsgType.ACSS 都是 acss 有可能会和接下来的 trans 协议冲突
                    acsstag = ADMPCMsgType.ACSS + str(self.layer_ID) + str(dealer_id)
                    acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

                    # 此时传递的是本层的公私钥
                    self.acss = ACSS_Fluid_Foll(self.public_keys, self.private_key, 
                                        self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                                        acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                                        mpc_instance=self
                                    )
                    # 这里的 rounds 也是手动更改的
                    rounds = w + 3
                    # rounds = 6 * w + 2
                    self.acss_tasks[dealer_id] = asyncio.create_task(self.acss.avss(0, dealer_id, rounds))


                    # 对于每一个dealer ID，下一层都要创一个来接受这个dealer ID分发的ACSS实例
                done, pending = await asyncio.wait(self.acss_tasks, return_when=asyncio.ALL_COMPLETED)
    
                # 从完成的任务中收集结果
                results = [task.result() for task in done]
                dealer, _, shares, commitments = zip(*results)
                print(f"layer ID: {self.layer_ID} my id: {self.my_id} dealers: {dealer}")

                 # 这里增加的代码是改进的 Fluid MPC 的代码，增加了MVBA 的过程，来共识一个公共子集
                # 这一步是 MVBA 的过程
                fluid_mvba_time = time.time()
                key_proposal = []
                # for i in range(self.n - self.t): key_proposal.append(dealer[i])
                key_proposal = random.sample(dealer, self.n - self.t)  # 从dealer随机选择n-t个不重复的元素
                create_acs_task = asyncio.create_task(self.agreement(key_proposal))

                acs, key_task, work_tasks = await create_acs_task
                await acs
                subset = await key_task
                await asyncio.gather(*work_tasks)
                fluid_mvba_time = time.time() - fluid_mvba_time
                print(f"fluid_mvba_time: {fluid_mvba_time} layer ID: {self.layer_ID} my id: {self.my_id} common_subset: {subset}") 
                
                new_shares = []
                for i in range(len(dealer)): 
                    for j in range(len(shares[i]['msg'])): 
                        new_shares.append(shares[i]['msg'][j])
                recv_input_time = time.time() - recv_input_time
                print(f"layer ID: {self.layer_ID} recv_input_time: {recv_input_time}")

                inter_shares = [[None for i in range(self.n)] for j in range(rounds)]
                for i in range(rounds):
                    for j in range(self.n):
                        inter_shares[i][j] = new_shares[i*self.n+j]

                sc_shares = [] 
                for i in range(len(inter_shares)): 
                    sc_shares.append([])
                    for j in range(len(inter_shares[0])): 
                        sc_shares[i].append([j+1, inter_shares[i][j]])            
                
                rec_shares = [None] * len(inter_shares)
                fluid_interpolate_time = time.time()
                for i in range(len(inter_shares)): 
                    rec_shares[i] = self.poly.interpolate_at(sc_shares[i], 0)
                fluid_interpolate_time = time.time() - fluid_interpolate_time
                print(f"layer ID: {self.layer_ID} fluid_interpolate_time: {fluid_interpolate_time}")

                # 首先 clients 调用 trans 协议接收 shares
                # trans_foll_time = time.time()
                # transtag = ADMPCMsgType.TRANS + str(self.layer_ID)
                # transsend, transrecv = self.get_send(transtag), self.subscribe_recv(transtag)

                # trans_foll = Trans_Fluid_Foll(self.public_keys, self.private_key, 
                #                 self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                #                 transsend, transrecv, self.pc, self.curve_params, mpc_instance=self)
                # # 这里也是假设当前 servers 知道上一层电路门输出的数量
                # # 这里也需要手动改
                # len_values = cm + 3
                # print(f"len_values: {len_values}")
                # new_shares = await trans_foll.run_trans(len_values)
                # trans_foll_time = time.time() - trans_foll_time
                # print(f"layer ID: {self.layer_ID} trans_foll_time: {trans_foll_time}")
                # # print(f"new_shares: {new_shares}")

                # rec_shares = [None] * len_values
                # fluid_interpolate_time = time.time()
                # for i in range(len_values): 
                #     rec_shares[i] = self.poly.interpolate_at(sc_shares[i], 0)
                # fluid_interpolate_time = time.time() - fluid_interpolate_time
                # print(f"layer ID: {self.layer_ID} fluid_interpolate_time: {fluid_interpolate_time}")
                # print(f"rec_shares: {rec_shares}")

                print(f"over")

            # 这里表示的是正在进行的电路计算
            else: 
                print(f"ok")
                recv_input_time = time.time()
                self.acss_tasks = [None] * self.n
                for dealer_id in range(self.n): 
                    # 这里 ADKGMsgType.ACSS 都是 acss 有可能会和接下来的 trans 协议冲突
                    acsstag = ADMPCMsgType.ACSS + str(self.layer_ID) + str(dealer_id)
                    acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

                    # 此时传递的是本层的公私钥
                    self.acss = ACSS_Fluid_Foll(self.public_keys, self.private_key, 
                                        self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                                        acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                                        mpc_instance=self
                                    )
                    # 这里的 rounds 也是手动更改的
                    if self.layer_ID == 3:
                        rounds = 6 * w + 2
                    # elif self.layer_ID == 3: 
                    #     rounds = input_num * 2 + (w - 2) * 5 + w
                    else: 
                        # 这里 + 4 除了是因为rand_values 的长度是 w+2 以外，还加上了 u 和 v
                        rounds = 6 * w + 4
                    self.acss_tasks[dealer_id] = asyncio.create_task(self.acss.avss(0, dealer_id, rounds))


                    # 对于每一个dealer ID，下一层都要创一个来接受这个dealer ID分发的ACSS实例
                done, pending = await asyncio.wait(self.acss_tasks, return_when=asyncio.ALL_COMPLETED)
    
                # 从完成的任务中收集结果
                results = [task.result() for task in done]
                dealer, _, shares, commitments = zip(*results)
                print(f"layer ID: {self.layer_ID} my id: {self.my_id} dealers: {dealer}")
                    
                 # 这里增加的代码是改进的 Fluid MPC 的代码，增加了MVBA 的过程，来共识一个公共子集
                # 这一步是 MVBA 的过程
                fluid_mvba_time = time.time()
                key_proposal = []
                # for i in range(self.n - self.t): key_proposal.append(dealer[i])
                key_proposal = random.sample(dealer, self.n - self.t)  # 从dealer随机选择n-t个不重复的元素
                create_acs_task = asyncio.create_task(self.agreement(key_proposal))

                acs, key_task, work_tasks = await create_acs_task
                await acs
                subset = await key_task
                await asyncio.gather(*work_tasks)
                fluid_mvba_time = time.time() - fluid_mvba_time
                print(f"fluid_mvba_time: {fluid_mvba_time} layer ID: {self.layer_ID} my id: {self.my_id} common_subset: {subset}")

                new_shares = []
                for i in range(len(dealer)): 
                    for j in range(len(shares[i]['msg'])): 
                        new_shares.append(shares[i]['msg'][j])
                recv_input_time = time.time() - recv_input_time
                print(f"layer ID: {self.layer_ID} recv_input_time: {recv_input_time}")

                inter_shares = [[None for i in range(self.n)] for j in range(rounds)]
                for i in range(rounds):
                    for j in range(self.n):
                        inter_shares[i][j] = new_shares[i*self.n+j]

                sc_shares = [] 
                for i in range(len(inter_shares)): 
                    sc_shares.append([])
                    for j in range(len(inter_shares[0])): 
                        sc_shares[i].append([j+1, inter_shares[i][j]])            
                
                rec_shares = [None] * len(inter_shares)
                fluid_interpolate_time = time.time()
                for i in range(len(inter_shares)): 
                    rec_shares[i] = self.poly.interpolate_at(sc_shares[i], 0)
                fluid_interpolate_time = time.time() - fluid_interpolate_time
                print(f"layer ID: {self.layer_ID} fluid_interpolate_time: {fluid_interpolate_time}")
                # print(f"rec_shares: {rec_shares}")

                if self.layer_ID < len(self.admpc_control_instance.pks_all) - 1:
                    len_rec_shares = len(rec_shares)
                    # 这里这个 if 表示的是 下一层是客户端
                    if self.layer_ID + 1 == len(self.admpc_control_instance.pks_all) - 1: 
                        # 这里 servers 需要做的是将 u 和 v 累加，然后传递 u,v,r,z 到 clients
                        z = rec_shares[:w]
                        # if self.layer_ID == 3: 
                        #     rand_shares = rec_shares[2*input_num+5*(w-2):]
                        #     u = rand_shares[1]
                        #     v = rand_shares[2]
                        # else: 
                        #     rand_shares = rec_shares[2*input_num+5*(w-2):len_rec_shares-2]
                        #     u = rec_shares[len_rec_shares-2]
                        #     v = rec_shares[len_rec_shares-1]

                        # 这里进行了简化，直接让 rec_shares 里面的值当 u, r, v
                        trans_shares = z + [rec_shares[0]] + [rec_shares[0]] + [rec_shares[0]]
                        # trans_shares = z + [rand_shares[0]] + [u] + [v]
                        print(f"len trans shares: {len(trans_shares)}")

                        print(f"before trans")
                        acss_pre_time = time.time()
                        pks_next_layer = self.admpc_control_instance.pks_all[self.layer_ID + 1]       # 下一层的公钥组

                        # 这里 ADKGMsgType.ACSS 都是 acss 有可能会和接下来的 trans 协议冲突
                        acsstag = ADMPCMsgType.ACSS + str(self.layer_ID+1) + str(self.my_id)
                        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

                        self.acss = ACSS_Fluid_Pre(pks_next_layer, 
                                            self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                                            acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                                            mpc_instance=self
                                        )
                        self.acss_tasks = [None] * self.n
                        # 在上一层中只需要创建一次avss即可     
                        self.acss_tasks[self.my_id] = asyncio.create_task(self.acss.avss(0, values=trans_shares))
                        await self.acss_tasks[self.my_id]
                        acss_pre_time = time.time() - acss_pre_time
                        print(f"layer ID: {self.layer_ID} acss_pre_time: {acss_pre_time}")
                        # rans_pre_time = time.time()
                        # transtag = ADMPCMsgType.TRANS + str(self.layer_ID+1)
                        # transsend, transrecv = self.get_send(transtag), self.subscribe_recv(transtag)

                        # trans_pre = Trans_Fluid_Pre(self.public_keys, self.private_key, 
                        #                 self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                        #                 transsend, transrecv, self.pc, self.curve_params, mpc_instance=self)
                        # trans_pre_task = asyncio.create_task(trans_pre.run_trans(trans_shares))
                        
                        # trans_pre_time = time.time() - trans_pre_time
                        # print(f"layer ID: {self.layer_ID} trans_pre_time: {trans_pre_time}")
                    
                    else: 

                        # 这里的 execution stage 需要执行当前层的计算
                        # 需要执行的计算有：a*b, ra*b, \alpha*\beta, \alpha*c, \alpha*rc
                        input_shares = rec_shares[:w]
                        masked_shares = rec_shares[w:2*w]
                        # if self.layer_ID == 3: 
                        #     rand_shares = rec_shares[2*input_num+5*(w-2):]
                        #     u = rand_shares[1]
                        #     v = rand_shares[2]
                        # else: 
                        #     rand_shares = rec_shares[2*input_num+5*(w-2):len_rec_shares-2]
                        #     u = rec_shares[len_rec_shares-2]
                        #     v = rec_shares[len_rec_shares-1]
                        # 这里也作了简化，随便让两个值当 u 和 v
                        rand_shares = rec_shares[:w+2]
                        u = rec_shares[0]
                        v = rec_shares[1]

                        output_shares = [None] * w
                        output_masked_shares = [None] * w
                        current_rand_shares = [None] * w
                        rand_last_layer_outputs = [None] * w
                        rand_last_layer_masked_outputs = [None] * w

                        for i in range(w):
                            output_shares[i] = input_shares[0] * input_shares[1]    # a*b
                            output_masked_shares[i] = input_shares[0] * masked_shares[0]    # ra*b
                            current_rand_shares[i] = rand_shares[1] * rand_shares[2]    # \alpha*\beta
                            # current_rand_shares[i] = input_shares[0] * input_shares[1]     # \alpha*\beta
                            rand_last_layer_outputs[i] = rand_shares[2] * input_shares[0]   # \alpha*c
                            # rand_last_layer_outputs[i] = input_shares[0] * input_shares[1]    # \alpha*c
                            rand_last_layer_masked_outputs[i] = rand_shares[2] * masked_shares[0]   # \alpha*rc
                            # rand_last_layer_masked_outputs[i] = input_shares[0] * input_shares[1]   # \alpha*rc
                        
                        # 这里是执行 u 和 v 的累加
                        # if self.layer_ID != 2: 


                        # 这里我们需要把 原始输入、乘以随机数的输入以及所有随机数传递给下一层
                        # 6 * w + 4
                        trans_values = output_shares + output_masked_shares + current_rand_shares + rand_last_layer_outputs + rand_last_layer_masked_outputs + rand_shares + [u] + [v]
                        acss_pre_time = time.time()
                        pks_next_layer = self.admpc_control_instance.pks_all[self.layer_ID + 1]       # 下一层的公钥组

                        # 这里 ADKGMsgType.ACSS 都是 acss 有可能会和接下来的 trans 协议冲突
                        acsstag = ADMPCMsgType.ACSS + str(self.layer_ID+1) + str(self.my_id)
                        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

                        self.acss = ACSS_Fluid_Pre(pks_next_layer, 
                                            self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                                            acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                                            mpc_instance=self
                                        )
                        self.acss_tasks = [None] * self.n
                        # 在上一层中只需要创建一次avss即可     
                        print(f"len trans_values: {len(trans_values)}")
                        self.acss_tasks[self.my_id] = asyncio.create_task(self.acss.avss(0, values=trans_values))
                        await self.acss_tasks[self.my_id]
                        acss_pre_time = time.time() - acss_pre_time
                        print(f"layer ID: {self.layer_ID} acss_pre_time: {acss_pre_time}")
                        
                        print("end")

        layer_time = time.time() - layer_time
        print(f"layer ID: {self.layer_ID} layer_time: {layer_time}")
    
        