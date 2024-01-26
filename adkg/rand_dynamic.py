from adkg.polynomial import polynomials_over
from adkg.utils.poly_misc import interpolate_g1_at_x
from adkg.utils.misc import wrap_send, subscribe_recv
import asyncio
import hashlib, time
from math import ceil
import logging
from adkg.utils.bitmap import Bitmap
from adkg.acss_dynamic import ACSS, ACSS_Pre, ACSS_Foll

from adkg.broadcast.tylerba import tylerba
from adkg.broadcast.optqrbc import optqrbc, optqrbc_dynamic

from adkg.preprocessing import PreProcessedElements

from adkg.mpc import TaskProgramRunner
from adkg.utils.serilization import Serial

import math

import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.NOTSET)

class RANDMsgType:
    ACSS = "GR.A"
    RBC = "GR.R"
    ABA = "GR.B"
    PREKEY = "GR.P"
    KEY = "GR.K"
    MASK = "GR.M"
    GENRAND = "GR.GR"
    ROBUSTREC = "GR.RR"
    TRANS = "GR.TR"
    APREP = "GR.AP"

    
class Rand:
    def __init__(self, public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, matrix):
        self.public_keys, self.private_key, self.g, self.h = (public_keys, private_key, g, h)
        self.n, self.t, self.deg, self.my_id = (n, t, deg, my_id)
        self.sc = ceil((deg+1)/(t+1)) + 1
        self.send, self.recv, self.pc = (send, recv, pc)
        self.ZR, self.G1, self.multiexp, self.dotprod = curve_params
        self.poly = polynomials_over(self.ZR)
        self.poly.clear_cache() #FIXME: Not sure why we need this.
        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)
        self.matrix = matrix

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)
        self.get_send = _send
        self.output_queue = asyncio.Queue()


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

    async def acss_step(self, outputs, values, acss_signal):
        # 这里 RANDMsgType.ACSS 都是 acss 有可能会和接下来的 trans 协议冲突
        acsstag = RANDMsgType.ACSS
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)
        self.acss = ACSS(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, acsssend, acssrecv, self.pc, self.ZR, self.G1
                         )
        self.acss_tasks = [None] * self.n
        # 这里的话应该是 n-parallel ACSS，看一下怎么做到的
        for i in range(self.n):
            if i == self.my_id:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss(0, values=values))
            else:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss(0, dealer_id=i))

        while True:
            (dealer, _, shares, commitments) = await self.acss.output_queue.get()
            outputs[dealer] = {'shares':shares, 'commits':commitments}
            # print("outputs: ", outputs[dealer])
            if len(outputs) >= self.n - self.t:
                # print("Player " + str(self.my_id) + " Got shares from: " + str([output for output in outputs]))
                acss_signal.set()

            if len(outputs) == self.n:
                return    

    async def commonsubset(self, rbc_out, acss_outputs, acss_signal, rbc_signal, rbc_values, coin_keys, aba_in, aba_out):
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
            while True:
                acss_signal.clear()
                for k in rbc_values[j]:
                    if k not in acss_outputs.keys():
                        subset = False
                if subset:
                    coin_keys[j]((acss_outputs, rbc_values[j]))
                    return
                await acss_signal.wait()

        r_threads = [asyncio.create_task(_recv_rbc(j)) for j in range(self.n)]
        # await asyncio.gather(*[asyncio.create_task(_recv_rbc(j)) for j in range(self.n)])

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
    
    async def agreement(self, key_proposal, acss_outputs, acss_signal):
        aba_inputs = [asyncio.Queue() for _ in range(self.n)]
        aba_outputs = [asyncio.Queue() for _ in range(self.n)]
        rbc_outputs = [asyncio.Queue() for _ in range(self.n)]
        
        coin_keys = [asyncio.Queue() for _ in range(self.n)]

        async def predicate(_key_proposal):
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
            rbctag =RANDMsgType.RBC + str(j) # (R, msg)
            rbcsend, rbcrecv = self.get_send(rbctag), self.subscribe_recv(rbctag)

            rbc_input = None
            if j == self.my_id: 
                # print(f"key_proposal: {key_proposal}")
                riv = Bitmap(self.n)
                for k in key_proposal: 
                    riv.set_bit(k)
                rbc_input = bytes(riv.array)
                # print(f"riv.array: {riv.array}")
                # print(f"rbc_input: {rbc_input}")

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

            abatag = RANDMsgType.ABA + str(j) # (B, msg)
            # abatag = j # (B, msg)
            abasend, abarecv =  self.get_send(abatag), self.subscribe_recv(abatag)

            def bcast(o):
                for i in range(self.n):
                    abasend(i, o)
                
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
                acss_outputs,
                acss_signal,
                rbc_signal,
                rbc_values,
                [_.put_nowait for _ in coin_keys],
                [_.put_nowait for _ in aba_inputs],
                [_.get for _ in aba_outputs],
            ),
            self.generate_rand(
                acss_outputs,
                acss_signal,
                rbc_values,
                rbc_signal,
            ),
            work_tasks,
        )

    async def generate_rand(self, acss_outputs, acss_signal, rbc_values, rbc_signal):
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
        
        # Waiting for all ACSS to terminate
        for k in self.mks:
            if k not in acss_outputs:
                await acss_signal.wait()
                acss_signal.clear()

        # print("mks: ", self.mks)

        # 为什么我们的 shares 会有两个呢，rand 对应的是 phi_hat, 那么 shares 就对应的是 phi ，那为什么会有两个呢
        # print("acss_outputs[0]['shares']['msg'][idx+1]: ", acss_outputs[0]['shares']['msg'])

        # 这几步就是每个节点把 shares 随机数，还有承诺提取到这几个二维列表里
        secrets = [[self.ZR(0)]*self.n for _ in range(self.rand_num)]
        randomness = [[self.ZR(0)]*self.n for _ in range(self.rand_num)]
        commits = [[self.G1.identity()]*self.n for _ in range(self.rand_num)]
        for idx in range(self.rand_num):
            for node in range(self.n):
                if node in self.mks:
                    # 重点！！这里 secrets 存的是 idx+1 ，也就是有 phi_hat 对应的 那个 phi 多项式，而不是 Feldman 承诺的 k=0 那个多项式
                    secrets[idx][node] = acss_outputs[node]['shares']['msg'][idx]
                    # print(f"secret[{idx}][{node}] = {secrets[idx][node]}")
                    randomness[idx][node] = acss_outputs[node]['shares']['rand'][idx]
                    # print(f"randomness[{idx}][{node}] = {randomness[idx][node]}")
                    commits[idx][node] = acss_outputs[node]['commits'][idx][0]
                    # print(f"commits[{idx}][{node}] = {commits[idx][node]}")
        
    
        z_shares = [[self.ZR(0) for _ in range(self.n-self.t)] for _ in range(self.rand_num)]
        # r_shares = [[self.ZR(0) for _ in range(self.n-self.t)] for _ in range(self.rand_num)]
        # 这里 z_shares 和 r_shares 我们应该设置成二维数组，每个矩阵对应一个 z_shares 不知道这里为什么都给加起来了 —— 这里加起来是为了模拟 论文中的 a 和 b 共同构成一个高门限的多项式
        # 这里矩阵的话也应该是有几个 rounds 就有几个矩阵，那么rounds应该作为 参数传递进来
        for i in range(self.rand_num): 
            for j in range(self.n-self.t): 
                z_shares[i][j] = self.dotprod(self.matrix[j], secrets[i])
                # r_shares[i][j] = self.dotprod(self.matrix[j], randomness[i])
        return (self.mks, z_shares)
    
    async def run_rand(self, w, rounds):

        # 这里 acss_outputs 需要针对每一 round 对应不同的 acss_outputs
        # acss_outputs = []
        acss_outputs = {}
        acss_signal = asyncio.Event()
   
        # 改变一下策略，让每个参与方一次性 acss rounds 个随机数
        self.rand_num = rounds
        values = [self.ZR.rand() for _ in range(rounds)]
        # 这里是测试代码，假设所有values = 2
        # values = [self.ZR(2) for _ in range(rounds)]
        self.acss_task = asyncio.create_task(self.acss_step(acss_outputs, values, acss_signal))
        await acss_signal.wait()
        acss_signal.clear()
        
        key_proposal = list(acss_outputs.keys())

        # 这一步是 MVBA 的过程
        create_acs_task = asyncio.create_task(self.agreement(key_proposal, acss_outputs, acss_signal))
        acs, key_task, work_tasks = await create_acs_task
        await acs
        output = await key_task
        await asyncio.gather(*work_tasks)
        # mks, sk, pk = output
        # mks, new_shares = output
        # self.output_queue.put_nowait((values[1], mks, sk, pk))
        mks, new_shares = output
        rand_shares = []
        for i in range(self.rand_num): 
            if i == self.rand_num - 1: 
                w = w - i * (self.n - self.t)
                rand_shares = rand_shares + new_shares[i][:w]
            else: 
                rand_shares = rand_shares + new_shares[i]


        # self.output_queue.put_nowait(rand_shares)
        return rand_shares

# Rand_Pre：用来做广播之前的事情（包括广播）
class Rand_Pre(Rand):
    def __init__(self, public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, matrix, mpc_instance):
        # 增加了一个属性：self.mpc_instance，使得Rand实例可以引用mpc_instance
        self.mpc_instance = mpc_instance

        super().__init__(public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, matrix)
        

    async def run_rand(self, w, rounds):
        # 改变一下策略，让每个参与方一次性 acss rounds 个随机数
        self.rand_num = rounds
        values = [self.ZR.rand() for _ in range(rounds)]
        self.acss_task = asyncio.create_task(self.acss_step(values))
        
    async def acss_step(self, values):

        # 此处传递的公钥应该是下一层的公钥
        admpc_control_instance = self.mpc_instance.admpc_control_instance
        layerID = self.mpc_instance.layer_ID
        admpc_lists_next_layer = admpc_control_instance.admpc_lists[layerID + 1]
        pks_next_layer = admpc_control_instance.pks_all[layerID + 1]       # 下一层的公钥组

        # 这里 ADKGMsgType.ACSS 都是 acss 有可能会和接下来的 trans 协议冲突
        acsstag = RANDMsgType.ACSS + str(layerID) + str(self.my_id)
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

        self.acss = ACSS_Pre(pks_next_layer, 
                             self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                             acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                             rand_instance=self
                         )
        self.acss_tasks = [None] * self.n
        # 在上一层中只需要创建一次avss即可        
        self.acss_tasks[self.my_id] = asyncio.create_task(self.acss.avss(0, values=values))
         
# Rand_Foll：做所有收到广播之后要做的事情，包括MVBA等等
class Rand_Foll(Rand):
    def __init__(self, public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, matrix, mpc_instance):
        # 增加了一个属性：self.mpc_instance，使得Rand实例可以引用mpc_instance
        self.mpc_instance = mpc_instance
        
        super().__init__(public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, matrix)  

    
    async def agreement_dynamic(self, key_proposal, acss_outputs, acss_signal):
        aba_inputs = [asyncio.Queue() for _ in range(self.n)]
        aba_outputs = [asyncio.Queue() for _ in range(self.n)]
        rbc_outputs = [asyncio.Queue() for _ in range(self.n)]
        
        coin_keys = [asyncio.Queue() for _ in range(self.n)]

        async def predicate(_key_proposal):
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
            rbctag =RANDMsgType.RBC + str(j) # (R, msg)
            rbcsend, rbcrecv = self.get_send(rbctag), self.subscribe_recv(rbctag)

            rbc_input = None
            if j == self.my_id: 
                # print(f"key_proposal: {key_proposal}")
                riv = Bitmap(self.n)
                for k in key_proposal: 
                    riv.set_bit(k)
                rbc_input = bytes(riv.array)
                # print(f"riv.array: {riv.array}")
                # print(f"rbc_input: {rbc_input}")

            # rbc_outputs[j] = 
            asyncio.create_task(
                optqrbc_dynamic(
                    rbctag,
                    self.my_id,
                    self.n,
                    self.t,
                    self.member_list[j],
                    predicate,
                    rbc_input,
                    rbc_outputs[j].put_nowait,
                    rbcsend,
                    rbcrecv,
                    self.member_list
                )
            )

            abatag = RANDMsgType.ABA + str(j) # (B, msg)
            # abatag = j # (B, msg)
            abasend, abarecv =  self.get_send(abatag), self.subscribe_recv(abatag)

            def bcast(o):
                for i in range(len(self.member_list)):
                    abasend(self.member_list[i], o)
                
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
            self.commonsubset_dynamic(
                rbc_outputs,
                acss_outputs,
                acss_signal,
                rbc_signal,
                rbc_values,
                [_.put_nowait for _ in coin_keys],
                [_.put_nowait for _ in aba_inputs],
                [_.get for _ in aba_outputs],
            ),
            self.generate_rand_dynamic(
                acss_outputs,
                acss_signal,
                rbc_values,
                rbc_signal,
            ),
            work_tasks,
        )

    
    async def run_rand(self, w, rounds):
        self.rand_num = rounds
        self.member_list = []
        for i in range(self.n): 
            self.member_list.append(self.n * (self.mpc_instance.layer_ID) + i)

        # 这里我们直接让 acss return 了，并没有用到他们设计的 异步队列 的 get，后续可能要修改
        acss_signal = asyncio.Event()
        self.acss_task = asyncio.create_task(self.acss_step(rounds))
        acss_outputs = await self.acss_task

        key_proposal = list(acss_outputs.keys())

        # 这一步是 MVBA 的过程
        create_acs_task = asyncio.create_task(self.agreement_dynamic(key_proposal, acss_outputs, acss_signal))
        acs, key_task, work_tasks = await create_acs_task
        await acs
        output = await key_task
        await asyncio.gather(*work_tasks)

        mks, new_shares = output
        rand_shares = []
        for i in range(self.rand_num): 
            if i == self.rand_num - 1: 
                w = w - i * (self.n - self.t)
                rand_shares = rand_shares + new_shares[i][:w]
            else: 
                rand_shares = rand_shares + new_shares[i]

        # self.output_queue.put_nowait(rand_shares)
        return rand_shares

    async def commonsubset_dynamic(self, rbc_out, acss_outputs, acss_signal, rbc_signal, rbc_values, coin_keys, aba_in, aba_out):
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
            while True:
                acss_signal.clear()
                for k in rbc_values[j]:
                    if k not in acss_outputs.keys():
                        subset = False
                if subset:
                    coin_keys[j]((acss_outputs, rbc_values[j]))
                    return
                await acss_signal.wait()

        r_threads = [asyncio.create_task(_recv_rbc(j)) for j in range(self.n)]
        # await asyncio.gather(*[asyncio.create_task(_recv_rbc(j)) for j in range(self.n)])

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
    
    async def generate_rand_dynamic(self, acss_outputs, acss_signal, rbc_values, rbc_signal):
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
        
        # Waiting for all ACSS to terminate
        for k in self.mks:
            if k not in acss_outputs:
                await acss_signal.wait()
                acss_signal.clear()

        # print("mks: ", self.mks)

        # 为什么我们的 shares 会有两个呢，rand 对应的是 phi_hat, 那么 shares 就对应的是 phi ，那为什么会有两个呢
        # print("acss_outputs[0]['shares']['msg'][idx+1]: ", acss_outputs[0]['shares']['msg'])

        # 这几步就是每个节点把 shares 随机数，还有承诺提取到这几个二维列表里
        secrets = [[self.ZR(0)]*self.n for _ in range(self.rand_num)]
        randomness = [[self.ZR(0)]*self.n for _ in range(self.rand_num)]
        commits = [[self.G1.identity()]*self.n for _ in range(self.rand_num)]
        for idx in range(self.rand_num):
            for node in range(self.n):
                if node in self.mks:
                    # 重点！！这里 secrets 存的是 idx+1 ，也就是有 phi_hat 对应的 那个 phi 多项式，而不是 Feldman 承诺的 k=0 那个多项式
                    secrets[idx][node] = acss_outputs[node]['shares']['msg'][idx]
                    # print(f"secret[{idx}][{node}] = {secrets[idx][node]}")
                    randomness[idx][node] = acss_outputs[node]['shares']['rand'][idx]
                    # print(f"randomness[{idx}][{node}] = {randomness[idx][node]}")
                    commits[idx][node] = acss_outputs[node]['commits'][idx][0]
                    # print(f"commits[{idx}][{node}] = {commits[idx][node]}")
        
    
        z_shares = [[self.ZR(0) for _ in range(self.n-self.t)] for _ in range(self.rand_num)]
        # r_shares = [[self.ZR(0) for _ in range(self.n-self.t)] for _ in range(self.rand_num)]
        # 这里 z_shares 和 r_shares 我们应该设置成二维数组，每个矩阵对应一个 z_shares 不知道这里为什么都给加起来了 —— 这里加起来是为了模拟 论文中的 a 和 b 共同构成一个高门限的多项式
        # 这里矩阵的话也应该是有几个 rounds 就有几个矩阵，那么rounds应该作为 参数传递进来
        for i in range(self.rand_num): 
            for j in range(self.n-self.t): 
                z_shares[i][j] = self.dotprod(self.matrix[j], secrets[i])
                # r_shares[i][j] = self.dotprod(self.matrix[j], randomness[i])
        return (self.mks, z_shares)
    

    async def acss_step(self, rounds):
        self.acss_tasks = [None] * self.n
        for dealer_id in range(self.n): 
            # 这里 ADKGMsgType.ACSS 都是 acss 有可能会和接下来的 trans 协议冲突
            acsstag = RANDMsgType.ACSS + str(self.mpc_instance.layer_ID - 1) + str(dealer_id)
            # acsstag = RANDMsgType.ACSS + str(self.mpc_instance.layer_ID-1) + str(dealer_id)
            acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

            # 此时传递的是本层的公私钥
            self.acss = ACSS_Foll(self.public_keys, self.private_key, 
                                self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                                acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                                rand_instance=self
                            )
            

            self.acss_tasks[dealer_id] = asyncio.create_task(self.acss.avss(0, dealer_id, rounds))


            # 对于每一个dealer ID，下一层都要创一个来接受这个dealer ID分发的ACSS实例

        results = await asyncio.gather(*self.acss_tasks)
        dealer, _, shares, commitments = zip(*results)
        
        outputs = {}
        for i in range(len(dealer)): 
            outputs[i] = {'shares':shares[i], 'commits':commitments[i]}
        return outputs

                