from adkg.polynomial import polynomials_over, EvalPoint
from adkg.utils.poly_misc import interpolate_g1_at_x
from adkg.utils.misc import wrap_send, subscribe_recv
import asyncio
import hashlib, time
from math import ceil
import logging
from adkg.utils.bitmap import Bitmap
from adkg.acss import ACSS, ACSS_Pre, ACSS_Foll

from adkg.broadcast.tylerba import tylerba
from adkg.broadcast.optqrbc import optqrbc, optqrbc_dynamic

from adkg.preprocessing import PreProcessedElements

from adkg.mpc import TaskProgramRunner
from adkg.utils.serilization import Serial
from adkg.rand import Rand, Rand_Pre, Rand_Foll
from adkg.robust_rec import Robust_Rec
import math

from adkg.field import GF, GFElement
from adkg.ntl import vandermonde_batch_evaluate
from adkg.elliptic_curve import Subgroup
from adkg.progs.mixins.dataflow import Share
from adkg.robust_reconstruction import robust_reconstruct_admpc, robust_rec_admpc

import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.NOTSET)

class APREPMsgType:
    ACSS = "AP.A"
    RBC = "AP.R"
    ABA = "AP.B"
    PREKEY = "AP.P"
    KEY = "AP.K"
    MASK = "AP.M"
    GENRAND = "AP.GR"
    ROBUSTREC = "AP.RR"
    APREP = "AP.AP"
    
class APREP:
    def __init__(self, public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, matrix):
        self.public_keys, self.private_key, self.g, self.h = (public_keys, private_key, g, h)
        self.n, self.t, self.deg, self.my_id = (n, t, deg, my_id)
        self.sc = ceil((deg+1)/(t+1)) + 1
        self.send, self.recv, self.pc = (send, recv, pc)
        self.ZR, self.G1, self.multiexp, self.dotprod = curve_params
        self.matrix = matrix
        # print(f"type(self.ZR): {type(self.ZR)}")
        self.poly = polynomials_over(self.ZR)
        self.poly.clear_cache() #FIXME: Not sure why we need this.
        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)
        self.get_send = _send
        self.output_queue = asyncio.Queue()

        rectag = APREPMsgType.ROBUSTREC
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

    async def acss_step(self, outputs, aprep_values, acss_signal):
        # 这里 APREPMsgType.ACSS 都是 acss 有可能会和接下来的 trans 协议冲突
        acsstag = APREPMsgType.ACSS
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)
        self.acss = ACSS(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, acsssend, acssrecv, self.pc, self.ZR, self.G1
                         )
        self.acss_tasks = [None] * self.n
        # 这里的话应该是 n-parallel ACSS，看一下怎么做到的
        for i in range(self.n):
            if i == self.my_id:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss_aprep(0, values=aprep_values))
            else:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss_aprep(0, dealer_id=i))

        while True:
            (dealer, _, shares, commitments) = await self.acss.output_queue.get()
            outputs[dealer] = {'shares':shares, 'commits':commitments}
            # print("outputs: ", outputs[dealer])
            # if len(outputs) == 15: 
            if len(outputs) >= self.n - self.t:
                # print("Player " + str(self.my_id) + " Got shares from: " + str([output for output in outputs]))
                acss_signal.set()

            if len(outputs) == self.n:
                return    

    async def commonsubset(self, rbc_out, mult_triples_shares, rec_tau, cm, rbc_signal, rbc_values, coin_keys, aba_in, aba_out):
        assert len(rbc_out) == self.n
        assert len(aba_in) == self.n
        assert len(aba_out) == self.n

        aba_inputted = [False]*self.n
        aba_values = [0]*self.n

        async def _recv_rbc(j):
            rbcl = await rbc_out[j].get()
            rbcb = Bitmap(self.n, rbcl)
            rbc_values[j] = []
          
            for i in range(self.n):
                if rbcb.get_bit(i):
                    rbc_values[j].append(i)
            # print(f"rbc_values[{j}]: {rbc_values[j]}")        
            
            if not aba_inputted[j]:
                aba_inputted[j] = True
                aba_in[j](1)
            
            subset = True
            while True:
                
                if subset:
                    coin_keys[j]((mult_triples_shares, rbc_values[j]))
                    return

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
    
    async def agreement(self, key_proposal, mult_triples_shares, rec_tau, cm):
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
            print(f"kpl: {kpl}")
            while True:
                subset = True
                # 这里是检查收到的来自其他节点的 key_proposal 跟自己的是否一致
                for kk in kpl:
                    for i in range(cm): 
                        if rec_tau[kk][i] != self.ZR(0): 
                            print(f"false")
                            subset = False
                    
                if subset:
                    return True
                

        async def _setup(j):
            
            # starting RBC
            rbctag =APREPMsgType.RBC + str(j) # (R, msg)
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

            abatag = APREPMsgType.ABA + str(j) # (B, msg)
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
                mult_triples_shares,
                rec_tau,
                cm,
                rbc_signal,
                rbc_values,
                [_.put_nowait for _ in coin_keys],
                [_.put_nowait for _ in aba_inputs],
                [_.get for _ in aba_outputs],
            ),
            self.new_triples(
                mult_triples_shares,
                cm,
                rbc_values,
                rbc_signal,
            ),
            work_tasks,
        )

    async def new_triples(self, mult_triples_shares, cm, rbc_values, rbc_signal):
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
        T_list = sorted(self.mks)
        print(f"T_list: {T_list}")
        # 这里就是协议的第三步，从每个参与方提供的 三元组 中提取随机化后的三元组
        # 这里跟需要根据我们共识的集合 T_list 来插值出新的三元组 (u,v,w)
        # 这里对应协议的 step 13
        u = [[self.ZR(0) for _ in range(2*self.t+1)] for _ in range(cm)]
        v = [[self.ZR(0) for _ in range(2*self.t+1)] for _ in range(cm)]
        w = [[self.ZR(0) for _ in range(2*self.t+1)] for _ in range(cm)]
        # 这里 u v w 的行代表 cm ,列代表不同节点的三元组中的元素
        for i in range(cm): 
            for j in range(self.t+1): 
                index = T_list[j]
                u[i][j] = mult_triples_shares[index][i][0]
                v[i][j] = mult_triples_shares[index][i][1]
                w[i][j] = mult_triples_shares[index][i][2]
        
        u_poly, v_poly, w_poly = [], [], []
        for i in range(cm):
            u_poly.append([])
            v_poly.append([])
            # w_poly.append([])
            for j in range(self.t+1): 
                u_poly[i].append([T_list[j]+1, u[i][j]])
                v_poly[i].append([T_list[j]+1, v[i][j]])
                # w_poly[i].append([T_list[j]+1, w[i][j]])
            
        # 这里对应协议的 step 14
        for i in range(cm):
            for j in range(self.t+1, 2*self.t+1): 
                index = T_list[j] + 1
                u[i][j] = self.poly.interpolate_at(u_poly[i], index)
                v[i][j] = self.poly.interpolate_at(v_poly[i], index)

        # 这里对应协议的 step 15
        print(f"step 15")
        d = [[self.ZR(0) for _ in range(self.t)] for _ in range(cm)]
        e = [[self.ZR(0) for _ in range(self.t)] for _ in range(cm)]  
        for i in range(cm):
            for j in range(self.t): 
                index1 = j + self.t + 1
                index2 = T_list[index1]
                d[i][j] = u[i][index1] - mult_triples_shares[index2][i][0]
                e[i][j] = v[i][index1] - mult_triples_shares[index2][i][1]
            

        # 这里对应协议的 step 16
        print(f"step 16")
        d_list, e_list = [], []
        for i in range(cm): 
            d_list += d[i]
            e_list += e[i]
        rec_list = d_list + e_list
        # robust_rec = await self.robust_rec_step(rec_list, 3)
        rec_task3 = asyncio.create_task(self.rec_step(rec_list, 3))
        (mks, robust_rec) = await rec_task3
        # robust_rec_d = await self.robust_rec_step(d_list, robust_rec_sig)
  
        # robust_rec_e = await self.robust_rec_step(e_list, robust_rec_sig)
        robust_rec_d = robust_rec[:int(len(robust_rec)/2)]
        robust_rec_e = robust_rec[int(len(robust_rec)/2):]
        
        rec_d = [[self.ZR(0) for _ in range(self.t)] for _ in range(cm)]
        rec_e = [[self.ZR(0) for _ in range(self.t)] for _ in range(cm)]
        for i in range(cm):
            for j in range(self.t): 
                rec_d[i][j] = robust_rec_d[i*self.t+j]
                rec_e[i][j] = robust_rec_e[i*self.t+j]

        # 这里对应协议的 step 17    
        for i in range(cm):
            for j in range(self.t): 
                index1 = j + self.t + 1
                index2 = T_list[index1]
                w[i][index1] = rec_d[i][j] * rec_e[i][j] + rec_d[i][j] * mult_triples_shares[index2][i][1] + rec_e[i][j] * mult_triples_shares[index2][i][0] + mult_triples_shares[index2][i][2]

        # 这里对应协议的 step 18
        for i in range(cm):
            w_poly.append([])
            for j in range(2*self.t+1): 
                w_poly[i].append([T_list[j]+1, w[i][j]])
        u_point, v_point, w_point = [None] * cm, [None] * cm, [None] * cm
        for i in range(cm):
            point = 3 * self.t + 2
            u_point[i] = self.poly.interpolate_at(u_poly[i], point)
            v_point[i] = self.poly.interpolate_at(v_poly[i], point)
            w_point[i] = self.poly.interpolate_at(w_poly[i], point)

        aprep_triples = []
        for i in range(cm): 
            aprep_triples.append([])
            aprep_triples[i].append(u_point[i])
            aprep_triples[i].append(v_point[i])
            aprep_triples[i].append(w_point[i])
            
        # 测试代码，测试 w == u * v
        # u_point_list, v_point_list, w_point_list = [], [], []
        # for i in range(1): 
        #     u_point_list.append(u_point[i])
        #     v_point_list.append(v_point[i])
        #     w_point_list.append(w_point[i])
        
        # robust_rec_u = await self.robust_rec_step(u_point_list, robust_rec_sig)
        # await robust_rec_sig.wait()
        # robust_rec_sig.clear()
        # robust_rec_v = await self.robust_rec_step(v_point_list, robust_rec_sig)
        # await robust_rec_sig.wait()
        # robust_rec_sig.clear()
        # robust_rec_w = await self.robust_rec_step(w_point_list, robust_rec_sig)
        # await robust_rec_sig.wait()
        # robust_rec_sig.clear()
        # if robust_rec_w[0] == robust_rec_u[0] * robust_rec_v[0]:
        #     print(f"pass")
        # else: 
        #     print(f"false")

        
        return aprep_triples
    
    
    async def gen_rand_step(self, rand_num, rand_outputs, rand_signal):
        # 这里 APREPMsgType.ACSS 都是 acss 有可能会和接下来的 trans 协议冲突
        if rand_num > self.n - self.t: 
            rounds = math.ceil(rand_num / (self. n - self.t))
        else: 
            rounds = 1
        randtag = APREPMsgType.GENRAND
        randsend, randrecv = self.get_send(randtag), self.subscribe_recv(randtag)
        curve_params = (self.ZR, self.G1, self.multiexp, self.dotprod)
        self.rand = Rand(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.my_id, randsend, randrecv, self.pc, curve_params, self.matrix)
        self.rand_task = asyncio.create_task(self.rand.run_rand(rand_num, rounds))

        while True: 
            # rand_outputs = await self.rand.output_queue.get()
            rand_outputs = await self.rand_task

            if len(rand_outputs) == rand_num: 
                # print(f"my id: {self.my_id} rand_outputs: {rand_outputs}")
                rand_signal.set()
                return rand_outputs
            
    async def robust_rec_step(self, rec_shares, index):                
        
        # self.rectasks = [None] * len(rec_shares)
        # for i in range(len(rec_shares)): 
        #     self.rectasks[i] = asyncio.create_task(self.rec.run_robust_rec(i, rec_shares[i]))
        # rec_values = await asyncio.gather(*self.rectasks)
        # print(f"my id: {self.my_id} rec_values: {rec_values}")

        # rec_signal.set()

        rec_values = await self.rec.batch_robust_rec(index, rec_shares)

        return rec_values
    
    async def rec_step(self, rec_shares, index):                
        
        # self.rectasks = [None] * len(rec_shares)
        # for i in range(len(rec_shares)): 
        #     self.rectasks[i] = asyncio.create_task(self.rec.run_robust_rec(i, rec_shares[i]))
        # rec_values = await asyncio.gather(*self.rectasks)
        # print(f"my id: {self.my_id} rec_values: {rec_values}")

        # rec_signal.set()
        # 这里 APREPMsgType.ACSS 都是 acss 有可能会和接下来的 trans 协议冲突

        self.rec_tasks = [None] * self.n
        # 这里的话应该是 n-parallel ACSS，看一下怎么做到的
        for i in range(self.n):
            if i == self.my_id:
                self.rec_tasks[i] = asyncio.create_task(self.rec.run_robust_rec(index, values=rec_shares))
            else:
                self.rec_tasks[i] = asyncio.create_task(self.rec.run_robust_rec(index, dealer_id=i))

        # await asyncio.gather(*self.rec_tasks)
        outputs = []
        rbc_number = []
        while True:
            (dealer_id, rbc_msg) = await self.rec.output_queue.get()
            outputs.append(rbc_msg)
            rbc_number.append(dealer_id)
            # print("outputs: ", outputs[dealer])
            # if len(outputs) == 15: 
            # 这里设计的其实也有问题，
            if len(outputs) == 15:
            # if len(outputs) >= self.n - self.t:
                # print("Player " + str(self.my_id) + " Got shares from: " + str([output for output in outputs]))
                print(f"rbc_number: {rbc_number}")
                print(f"len > n - t")
                sr = Serial(self.G1)
                rec_de_time = time.time()
                rec_de_fs_time = time.time()

                # 首先，对整个 rbc_list 进行一次反序列化
                deserialized_rbc_list = [sr.deserialize_fs(item) for item in outputs]
                print(f"len deserialized_rbc_list: {len(deserialized_rbc_list)}")
                print(f"len deserialized_rbc_list[0]: {len(deserialized_rbc_list[0])}")

                # 初始化 rbc_shares 二维列表
                rbc_shares = [[None for _ in range(len(outputs))] for _ in range(len(deserialized_rbc_list[0]))]

                # 填充 rbc_shares 二维列表
                for i in range(len(deserialized_rbc_list[0])):
                    for node in range(len(deserialized_rbc_list)):
                        rbc_shares[i][node] = int(deserialized_rbc_list[node][i])
                rec_de_fs_time = time.time() - rec_de_fs_time
                print(f"rec_de_fs_time: {rec_de_fs_time}")
                print(f"len rbc_shares: {len(rbc_shares)}")
                print(f"len rbc_shares[0]: {len(rbc_shares[0])}")


                # 这里看一下能否把定义在 ZR 和 G1 上的元素转化到 hoheybadgerMPC 定义的 GFE 类上，再执行 鲁棒性插值的工作
                GFEG1 = GF(Subgroup.BLS12_381)
                # gfe_rbc_msg = [GFEG1(int(rbc_shares[i])) for i in range(len(rbc_shares))] 
                # share = Share(gfe_rbc_msg[self.my_id], self.t)
                # x = await share.open()
                point = EvalPoint(GFEG1, self.n, use_omega_powers=False)
                # 这个 key_proposal 表示的就是我们收到的shares是来自哪些dealer的
                key_proposal = rbc_number
                poly, err = [None] * len(rbc_shares), [None] * len(rbc_shares)
                rec_robust_interpolate_time = time.time()
<<<<<<< HEAD
                rec_values = []
                for i in range(len(rbc_shares)): 
                    poly[i], err[i] = await robust_rec_admpc(rbc_shares[i], key_proposal, GFEG1, self.t, point, self.t)
                    constant = int(poly[i].coeffs[0])
                    rec_values.append(self.ZR(constant))
=======
                for i in range(len(rbc_shares)): 
                    poly[i], err[i] = await robust_rec_admpc(rbc_shares[i], key_proposal, GFEG1, self.t, point, self.t)
>>>>>>> 628abe2187076ba4c91a6a60f30249128b984ff8
                rec_robust_interpolate_time = time.time() - rec_robust_interpolate_time
                print(f"rec_robust_interpolate_time: {rec_robust_interpolate_time}")
                te = int(poly[0].coeffs[0])
                tes = self.ZR(te)
                err_list = [list(err[i]) for i in range(len(err))]

                # 这个就是通过鲁棒性插值找到的 2t+1 的集合
                for i in range(len(err_list)): 
                    if len(err_list[i]) == 0: 
                        continue
                    else: 
                        for j in range(len(err_list[i])): 
                            key_proposal.pop(err_list[i][j])
                print(f"my id: {self.my_id} key_proposal: {key_proposal}")
                rec_de_time = time.time() - rec_de_time
                print(f"rec_de_time: {rec_de_time}")
<<<<<<< HEAD
                return (key_proposal, rec_values)
=======
>>>>>>> 628abe2187076ba4c91a6a60f30249128b984ff8

                # 这一步是 MVBA 的过程
                rec_mvba_time = time.time()
                create_acs_task = asyncio.create_task(self.rec.agreement_honeybadgermpc(key_proposal, rbc_shares, index))
                acs, key_task, work_tasks = await create_acs_task
                await acs
                output = await key_task
                await asyncio.gather(*work_tasks)
                rec_mvba_time = time.time() - rec_mvba_time
                print(f"rec_mvba_time: {rec_mvba_time}")
                mks, rec_values = output
                print(f"mks: {mks}")


                return (mks, rec_values)
                # rec_signal.set()

            if len(outputs) == self.n:
                return 
        
        
        # await asyncio.gather(*self.rec_tasks)
        # print(f"here?")
        
        # rec_shares = await asyncio.gather(*self.rec_tcasks)
        # return rec_shares
        
        
        
        # while True:
        #     (dealer, _, shares, commitments) = await self.acss.output_queue.get()
        #     outputs[dealer] = {'shares':shares, 'commits':commitments}
        #     # print("outputs: ", outputs[dealer])
        #     # if len(outputs) == 15: 
        #     if len(outputs) >= self.n - self.t:
        #         # print("Player " + str(self.my_id) + " Got shares from: " + str([output for output in outputs]))
        #         acss_signal.set()

        #     if len(outputs) == self.n:
        #         return    

        # rec_values = await self.rec.batch_robust_rec(index, rec_shares)

        # return rec_values
        
   
    async def run_aprep(self, cm):
        gen_rand_outputs = []
        gen_rand_signal = asyncio.Event()

        # 这里是调用 Protocol Rand 来生成随机数
        gen_rand_step_time = time.time()
        gen_rand_outputs = await self.gen_rand_step(self.n*cm, gen_rand_outputs, gen_rand_signal)
        gen_rand_step_time = time.time() - gen_rand_step_time
        print(f"gen_rand_step_time: {gen_rand_step_time}") 
        # print(f"gen_rand_outputs: {gen_rand_outputs}")

        acss_outputs = {}
        acss_signal = asyncio.Event()

        # 这里是测试代码，假设 (a,b,c)=(1,2,2) (x,y,z)=(2,3,6) cm=1
        # mult_triples = [[self.ZR.rand() for _ in range(3)] for _ in range(cm)]
        # chec_triples = [[self.ZR.rand() for _ in range(3)] for _ in range(cm)]
        # mult_triples[0][0] = self.ZR(1)
        # mult_triples[0][1] = self.ZR(2)
        # chec_triples[0][0] = self.ZR(2)
        # chec_triples[0][1] = self.ZR(3)
        # for i in range(cm): 
        #     mult_triples[i][2] = mult_triples[i][0] * mult_triples[i][1]
        #     chec_triples[i][2] = chec_triples[i][0] * chec_triples[i][1]

        # 每个参与方生成下一个 epoch 需要的乘法三元组
        mult_triples = [[self.ZR.rand() for _ in range(3)] for _ in range(cm)]
        chec_triples = [[self.ZR.rand() for _ in range(3)] for _ in range(cm)]
        # rand_values = [None] * cm
        for i in range(cm): 
            mult_triples[i][2] = mult_triples[i][0] * mult_triples[i][1]
            chec_triples[i][2] = chec_triples[i][0] * chec_triples[i][1]

        aprep_values = (mult_triples, chec_triples, cm)      

        # 这一步是 acss 的过程
        aprep_acss_start_time = time.time()
        self.acss_task = asyncio.create_task(self.acss_step(acss_outputs, aprep_values, acss_signal))
        await acss_signal.wait()
        acss_signal.clear()
        print(f"aprep_acss_time: {time.time()-aprep_acss_start_time}")
        # print("acss_outputs: ", acss_outputs)

        # 这两步可以放到调用 robust-rec 之前
        await gen_rand_signal.wait()
        gen_rand_signal.clear()
        # print(f"id: {self.my_id} gen_rand_outputs: {gen_rand_outputs}")

        # 这里调用 Protocol Robust-Rec 来重构出刚才生成的随机数的原始值
        # robust_rec_outputs = []
        tes_time = time.time()
        rec_task = asyncio.create_task(self.rec_step(gen_rand_outputs, 0))
        (mks, robust_rec_outputs) = await rec_task
        print(f"len outputs: {len(robust_rec_outputs)}")
        mks_list = sorted(mks)
        print(f"mks_list: {mks_list}")
        # print(f"len outputs[0]: {len(outputs[0])}")
        # await rec_signal
        # rec_signal.clear()
        # robust_rec_outputs = await self.robust_rec_step(gen_rand_outputs, 0)
        print(f"tes_time: {time.time()-tes_time}")

        
        
        # print(f"robust_rec_outputs: {robust_rec_outputs}")

        # 这一步我们需要用 chec_triples 来验证 mult_triples 中的三元组是否 c = a * b
        # 这里 'msg' 表示的是 phis 集合，'rand' 表示的是 phis_hat 集合，phis[0] 里面的元素是 mult_triples，phis[1] 里面的元素是 chec_triples
        # 这里 acss_outputs[n] 中的 n 代表的是不同节点提供的三元组
        # print(f"acss_outputs[0]['shares']['msg'][0][0]: {acss_outputs[0]['shares']['msg'][0][0]}")
        print(f"len acss_outputs: {len(acss_outputs)}")
        # 假设 acss_outputs 是一个字典，键是节点编号，值是该节点的输出数据

        mult_triples_shares = {}
        chec_triples_shares = {}
        rands = {}

        # 假设 robust_rec_outputs 是一个列表，按照某种顺序排列
        # 这里需要确保 robust_rec_outputs 的长度足够
        for node in mks_list:
            print(f"my id: {self.my_id} node in mks: {node}")
            if node in acss_outputs:
                output = acss_outputs[node]
                # 初始化每个节点的三元组列表
                mult_triples_shares[node] = [0] * cm
                chec_triples_shares[node] = [0] * cm
                rands[node] = [0] * cm

                # 从节点数据中提取三元组信息
                for i in range(cm):
                    mult_triples_shares[node][i] = output['shares']['msg'][0][i]
                    chec_triples_shares[node][i] = output['shares']['msg'][1][i]
                    rands[node][i] = robust_rec_outputs[node * cm + i]  # 使用 mks.index(node) 来找到正确的索引
            else:
                # 如果 mks 中的某个节点在 acss_outputs 中不存在，你可以选择跳过或者初始化为空
                print(f"Warning: Node {node} is not present in acss_outputs")

        # 打印结果以验证
        print(f"len mult_triples_shares[1]: {len(mult_triples_shares[1]) if 1 in mult_triples_shares else 'Node not available'}")


        # mult_triples_shares = {}
        # chec_triples_shares = {}
        # rands = {}
        # # 这是一个临时计数器，用来给 robust_rec_outputs 里面的随机数分配给各个三元组
        # # number = 0

        # # 假设 robust_rec_outputs 仍然是一个列表，按照某种顺序排列
        # for node, output in acss_outputs.items():
        #     # 初始化每个节点的三元组列表
        #     mult_triples_shares[node] = [0] * cm
        #     chec_triples_shares[node] = [0] * cm
        #     rands[node] = [0] * cm

        #     # 从节点数据中提取三元组信息
        #     for i in range(cm):
        #         mult_triples_shares[node][i] = output['shares']['msg'][0][i]
        #         chec_triples_shares[node][i] = output['shares']['msg'][1][i]
        #         rands[node][i] = robust_rec_outputs[node*cm+i]  # 这里假设 robust_rec_outputs 的索引依然有效，可能需要根据实际情况调整
        #     # number += 1

        # # 打印结果以验证
        # print(f"len mult_triples_shares[0]: {len(mult_triples_shares[0])}")
        # print(f"rands: {rands}")

        
        # mult_triples_shares = [[0 for _ in range(cm)] for _ in range(len(acss_outputs))]
        # chec_triples_shares = [[0 for _ in range(cm)] for _ in range(len(acss_outputs))]
        # rands = [[0 for _ in range(cm)] for _ in range(len(acss_outputs))]
        # for node in range(len(acss_outputs)): 
        #     for i in range(cm): 
        #         mult_triples_shares[node][i] = acss_outputs[node]['shares']['msg'][0][i]
        #         chec_triples_shares[node][i] = acss_outputs[node]['shares']['msg'][1][i]
        #         rands[node][i] = robust_rec_outputs[node*cm+i]
        # print(f"split triples")

        # 这一步开始用 chec 三元组来计算 乘法三元组
        # print(f"my id: {self.my_id} mult_triples_shares[0][0]: {mult_triples_shares[0][0]}")

        # 初始化 rho 和 sigma 为字典结构
        rho = {node: [0] * cm for node in mult_triples_shares}
        sigma = {node: [0] * cm for node in mult_triples_shares}

        # 计算 rho 和 sigma 的值
        for node, outputs in mult_triples_shares.items():
            for i in range(cm):
                rho[node][i] = rands[node][i] * mult_triples_shares[node][i][0] - chec_triples_shares[node][i][0]
                sigma[node][i] = mult_triples_shares[node][i][1] - chec_triples_shares[node][i][1]

        print("before the second rec")

        # 转换 rho 和 sigma 到列表形式以进行后续处理，
        # 注意，因为不同节点收到的 node 集合的顺序是不一致的，这里我们需要先给这些字典的顺序调整成一致，然后再执行后续步骤
        rho_list = []
        sigma_list = []
        for node in mult_triples_shares:
            print(f"my id: {self.my_id} node: {node}")
            rho_list += rho[node]
            sigma_list += sigma[node]

        # 这里调用 Robust-Rec 协议重构 rho 和 sigma
        aprep_rec_start_time = time.time()
        rec_list = rho_list + sigma_list

        # 异步执行 Robust-Rec 协议
        rec_task1 = asyncio.create_task(self.rec_step(rec_list, 1))
        (mks, robust_rec) = await rec_task1
        mks_list = sorted(mks)


        # rho = [[0 for _ in range(cm)] for _ in range(len(acss_outputs))]
        # sigma = [[0 for _ in range(cm)] for _ in range(len(acss_outputs))]
        # for node in range(len(acss_outputs)): 
        #     for i in range(cm): 
        #         rho[node][i] = rands[node][i] * mult_triples_shares[node][i][0] - chec_triples_shares[node][i][0]
        #         sigma[node][i] = mult_triples_shares[node][i][1] - chec_triples_shares[node][i][1]
        #         # sigma[node][i] = chec_triples_shares[node][i][1] - mult_triples_shares[node][i][1]
        # print(f"before the second rec")
        # rho_list = []
        # sigma_list = []
        # for i in range(len(acss_outputs)): 
        #     rho_list += rho[i]
        #     sigma_list += sigma[i]
        # # 这里调用 Robust-Rec 协议重构 rho 和 sigma
        # aprep_rec_start_time = time.time()
        # rec_list = rho_list + sigma_list

        # rec_task1 = asyncio.create_task(self.rec_step(rec_list, 1))
        # robust_rec = await rec_task1


        # robust_rec = await self.robust_rec_step(rec_list, 1)
        # robust_rec_rho = await self.robust_rec_step(rho_list, robust_rec_signal)
        
        # robust_rec_sigma = await self.robust_rec_step(sigma_list, robust_rec_signal)
        
        print(f"aprep_rec_time: {time.time()-aprep_rec_start_time}")
        # print(f"robust_rec_rho: {robust_rec_rho}")

        # 假设 robust_rec 是一个列表，已按顺序包含所有必需数据
        robust_rec_rho = robust_rec[:int(len(robust_rec)/2)]
        robust_rec_sigma = robust_rec[int(len(robust_rec)/2):]

        # 使用字典初始化 rec_rho 和 rec_sigma
        rec_rho = {node: [0] * cm for node in mult_triples_shares}
        rec_sigma = {node: [0] * cm for node in mult_triples_shares}

        # 分配 robust_rec_rho 和 robust_rec_sigma 到 rec_rho 和 rec_sigma
        for node, outputs in mult_triples_shares.items():
            if node in mks_list: 
                for i in range(cm):
                    index = mks_list.index(node)
                    rec_rho[node][i] = robust_rec_rho[index * cm + i]
                    rec_sigma[node][i] = robust_rec_sigma[index * cm + i]

        # 初始化并计算 tau
        tau = {node: [0] * cm for node in mult_triples_shares}
        for node, outputs in mult_triples_shares.items():
            for i in range(cm):
                tau[node][i] = (rands[node][i] * mult_triples_shares[node][i][2] - chec_triples_shares[node][i][2] -
                                rec_sigma[node][i] * chec_triples_shares[node][i][0] - rec_rho[node][i] * chec_triples_shares[node][i][1] -
                                rec_rho[node][i] * rec_sigma[node][i])

        # 转换 tau 到列表形式
        tau_list = []
        for node in mult_triples_shares:
            tau_list += tau[node]

        # 异步执行 robust_rec_step
        print(f"len tau_list: {len(tau_list)}")
        rec_task2 = asyncio.create_task(self.rec_step(tau_list, 2))
        (mks, robust_rec_tau) = await rec_task2
        mks_list = sorted(mks)

        # 初始化 rec_tau 并赋值
        rec_tau = {node: [0] * cm for node in mult_triples_shares}
        for node, outputs in mult_triples_shares.items():
            if node in mks_list: 
                for i in range(cm):
                    index = mks_list.index(node)
                    rec_tau[node][i] = robust_rec_tau[index * cm + i]

        # print(f"rec_tau[0]: {rec_tau[0]}")



        # robust_rec_rho = robust_rec[:int(len(robust_rec)/2)]
        # robust_rec_sigma = robust_rec[int(len(robust_rec)/2):]
        # rec_rho = [[0 for _ in range(cm)] for _ in range(len(acss_outputs))]
        # rec_sigma = [[0 for _ in range(cm)] for _ in range(len(acss_outputs))]
        # for node in range(len(acss_outputs)): 
        #     for i in range(cm): 
        #         rec_rho[node][i] = robust_rec_rho[node*cm+i]
        #         rec_sigma[node][i] = robust_rec_sigma[node*cm+i]
        
        # # 下面是计算 \tau 并调用 protocol Robust-Rec 来重构 \tau 检测是否等于 0
        # tau = [[0 for _ in range(cm)] for _ in range(len(acss_outputs))]
        # for node in range(len(acss_outputs)): 
        #     for i in range(cm): 
        #         tau[node][i] = rands[node][i] * mult_triples_shares[node][i][2] - chec_triples_shares[node][i][2] - rec_sigma[node][i] * chec_triples_shares[node][i][0] - rec_rho[node][i] * chec_triples_shares[node][i][1] - rec_rho[node][i] * rec_sigma[node][i]
        # # print(f"tau[0][0]: {tau[0][0]}")
        # tau_list = []
        # for i in range(len(acss_outputs)): 
        #     tau_list += tau[i]
        
        # rec_task2 = asyncio.create_task(self.rec_step(tau_list, 2))
        # robust_rec_tau = await rec_task2
        # # robust_rec_tau = await self.robust_rec_step(tau_list, 2)
        
        # # print(f"robust_rec_tau: {robust_rec_tau}")
        # rec_tau = [[0 for _ in range(cm)] for _ in range(len(acss_outputs))]
        # for node in range(len(acss_outputs)): 
        #     for i in range(cm): 
        #         rec_tau[node][i] = robust_rec_tau[node*cm+i]
        # print(f"rec_tau: {rec_tau}")

        # 这里检查 \tau 是否等于0，如果等于0，就放到 key_proposal 中
                    
        # 假设 rec_tau 是一个字典，键为节点编号，值为与该节点相关的数据列表
        key_proposal = []
        for node, values in rec_tau.items():
            add_node = True  # 假设需要将节点添加到 key_proposal
            for value in values:
                if value != self.ZR(0):
                    add_node = False  # 如果任何一个值不等于零，不添加该节点
                    break
            if add_node:
                key_proposal.append(node)

        # key_proposal = []
        # for node in range(len(acss_outputs)): 
        #     for i in range(cm): 
        #         if rec_tau[node][i] != self.ZR(0):
        #             break
        #     key_proposal.append(node)
        print(f"rec_tau key_proposal: {key_proposal}")
        

        # 这一步是 MVBA 的过程
        mvba_time = time.time()
        create_acs_task = asyncio.create_task(self.agreement(key_proposal, mult_triples_shares, rec_tau, cm))
        acs, key_task, work_tasks = await create_acs_task
        await acs
        output = await key_task
        await asyncio.gather(*work_tasks)
        # mks, sk, pk = output
        new_mult_triples = output
        mvba_time = time.time() - mvba_time
        print(f"aprep_mvba_time: {mvba_time}")
        # self.output_queue.put_nowait((values[1], mks, sk, pk))
        # self.output_queue.put_nowait(new_mult_triples)
        return new_mult_triples
        
class APREP_Pre(APREP):
    def __init__(self, public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, matrix, mpc_instance):
        # 增加了一个属性：self.mpc_instance，使得Rand实例可以引用mpc_instance
        self.mpc_instance = mpc_instance

        super().__init__(public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, matrix)
            
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

    async def acss_step(self, aprep_values):

        # 此处传递的公钥应该是下一层的公钥
        admpc_control_instance = self.mpc_instance.admpc_control_instance
        layerID = self.mpc_instance.layer_ID
        pks_next_layer = admpc_control_instance.pks_all[layerID + 1]       # 下一层的公钥组

        # 这里 APREPMsgType.ACSS 都是 acss 有可能会和接下来的 trans 协议冲突
        acsstag = APREPMsgType.ACSS + str(layerID) + str(self.my_id)
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)
        self.acss = ACSS_Pre(pks_next_layer,
                             self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                             acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                             mpc_instance=self.mpc_instance
                         )
        self.acss_tasks = [None] * self.n
        self.acss_tasks[self.my_id] = asyncio.create_task(self.acss.avss_aprep(0, values=aprep_values))

    
    async def gen_rand_step(self, rand_num):
        # 这里 APREPMsgType.ACSS 都是 acss 有可能会和接下来的 trans 协议冲突
        if rand_num > self.n - self.t: 
            rounds = math.ceil(rand_num / (self. n - self.t))
        else: 
            rounds = 1
        randtag = APREPMsgType.GENRAND
        randsend, randrecv = self.get_send(randtag), self.subscribe_recv(randtag)
        curve_params = (self.ZR, self.G1, self.multiexp, self.dotprod)
        self.rand = Rand_Pre(self.public_keys, self.private_key, 
                             self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                             randsend, randrecv, self.pc, curve_params, self.matrix, 
                             mpc_instance=self.mpc_instance)
        self.rand_task = asyncio.create_task(self.rand.run_rand(rand_num, rounds))
   
    async def run_aprep(self, cm):

        # 这里是调用 Protocol Rand 来生成随机数
        gen_rand_task = asyncio.create_task(self.gen_rand_step(self.n*cm))
        
        # 每个参与方生成下一个 epoch 需要的乘法三元组
        mult_triples = [[self.ZR.rand() for _ in range(3)] for _ in range(cm)]
        chec_triples = [[self.ZR.rand() for _ in range(3)] for _ in range(cm)]
        # rand_values = [None] * cm
        for i in range(cm): 
            mult_triples[i][2] = mult_triples[i][0] * mult_triples[i][1]
            chec_triples[i][2] = chec_triples[i][0] * chec_triples[i][1]

        aprep_values = (mult_triples, chec_triples, cm)      
        # 这一步是 acss 的过程
        self.acss_task = asyncio.create_task(self.acss_step(aprep_values))
        await self.acss_task

        
    
class APREP_Foll(APREP):
    def __init__(self, public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, matrix, mpc_instance):
        # 增加了一个属性：self.mpc_instance，使得Rand实例可以引用mpc_instance
        self.mpc_instance = mpc_instance

        super().__init__(public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, matrix)

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

    async def acss_step(self, cm):
        self.acss_tasks = [None] * self.n
        for dealer_id in range(self.n): 
            # 这里 ADKGMsgType.ACSS 都是 acss 有可能会和接下来的 trans 协议冲突
            acsstag = APREPMsgType.ACSS + str(self.mpc_instance.layer_ID - 1) + str(dealer_id)
            acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

            # 此时传递的是本层的公私钥
            self.acss = ACSS_Foll(self.public_keys, self.private_key, 
                                self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                                acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                                mpc_instance=self.mpc_instance
                            )
            self.acss_tasks[dealer_id] = asyncio.create_task(self.acss.avss_aprep(0, dealer_id, cm))
        
        results = await asyncio.gather(*self.acss_tasks)
        dealer, _, shares, commitments = zip(*results)
        
        outputs = {}
        for i in range(len(dealer)): 
            outputs[i] = {'shares':shares[i], 'commits':commitments[i]}
        return outputs
          

    async def commonsubset(self, rbc_out, mult_triples_shares, rec_tau, cm, rbc_signal, rbc_values, coin_keys, aba_in, aba_out):
        assert len(rbc_out) == self.n
        assert len(aba_in) == self.n
        assert len(aba_out) == self.n

        aba_inputted = [False]*self.n
        aba_values = [0]*self.n

        async def _recv_rbc(j):
            rbcl = await rbc_out[j].get()
            rbcb = Bitmap(self.n, rbcl)
            rbc_values[j] = []
          
            for i in range(self.n):
                if rbcb.get_bit(i):
                    rbc_values[j].append(i)
            # print(f"rbc_values[{j}]: {rbc_values[j]}")        
            
            if not aba_inputted[j]:
                aba_inputted[j] = True
                aba_in[j](1)
            
            subset = True
            while True:
                
                if subset:
                    coin_keys[j]((mult_triples_shares, rbc_values[j]))
                    return

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
    
    async def agreement(self, key_proposal, mult_triples_shares, rec_tau, cm):
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
                # 这里是检查收到的来自其他节点的 key_proposal 跟自己的是否一致
                for kk in kpl:
                    for i in range(cm): 
                        if rec_tau[kk][i] != self.ZR(0): 
                            subset = False
                    
                if subset:
                    return True
                

        async def _setup(j):
            
            # starting RBC
            rbctag =APREPMsgType.RBC + str(j) # (R, msg)
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
                    j,
                    predicate,
                    rbc_input,
                    rbc_outputs[j].put_nowait,
                    rbcsend,
                    rbcrecv,
                    self.member_list
                )
            )

            abatag = APREPMsgType.ABA + str(j) # (B, msg)
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
            self.commonsubset(
                rbc_outputs,
                mult_triples_shares,
                rec_tau,
                cm,
                rbc_signal,
                rbc_values,
                [_.put_nowait for _ in coin_keys],
                [_.put_nowait for _ in aba_inputs],
                [_.get for _ in aba_outputs],
            ),
            self.new_triples(
                mult_triples_shares,
                cm,
                rbc_values,
                rbc_signal,
            ),
            work_tasks,
        )

    async def new_triples(self, mult_triples_shares, cm, rbc_values, rbc_signal):
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
        T_list = list(self.mks)
        # 这里就是协议的第三步，从每个参与方提供的 三元组 中提取随机化后的三元组
        # 这里跟需要根据我们共识的集合 T_list 来插值出新的三元组 (u,v,w)
        # 这里对应协议的 step 13
        u = [[self.ZR(0) for _ in range(2*self.t+1)] for _ in range(cm)]
        v = [[self.ZR(0) for _ in range(2*self.t+1)] for _ in range(cm)]
        w = [[self.ZR(0) for _ in range(2*self.t+1)] for _ in range(cm)]
        # 这里 u v w 的行代表 cm ,列代表不同节点的三元组中的元素
        for i in range(cm): 
            for j in range(self.t+1): 
                index = T_list[j]
                u[i][j] = mult_triples_shares[index][i][0]
                v[i][j] = mult_triples_shares[index][i][1]
                w[i][j] = mult_triples_shares[index][i][2]
        
        u_poly, v_poly, w_poly = [], [], []
        for i in range(cm):
            u_poly.append([])
            v_poly.append([])
            # w_poly.append([])
            for j in range(self.t+1): 
                u_poly[i].append([T_list[j]+1, u[i][j]])
                v_poly[i].append([T_list[j]+1, v[i][j]])
                # w_poly[i].append([T_list[j]+1, w[i][j]])
            
        # 这里对应协议的 step 14
        for i in range(cm):
            for j in range(self.t+1, 2*self.t+1): 
                index = T_list[j] + 1
                u[i][j] = self.poly.interpolate_at(u_poly[i], index)
                v[i][j] = self.poly.interpolate_at(v_poly[i], index)

        # 这里对应协议的 step 15
        d = [[self.ZR(0) for _ in range(self.t)] for _ in range(cm)]
        e = [[self.ZR(0) for _ in range(self.t)] for _ in range(cm)]  
        for i in range(cm):
            for j in range(self.t): 
                index1 = j + self.t + 1
                index2 = T_list[index1]
                d[i][j] = u[i][index1] - mult_triples_shares[index2][i][0]
                e[i][j] = v[i][index1] - mult_triples_shares[index2][i][1]
            

        # 这里对应协议的 step 16
        d_list, e_list = [], []
        for i in range(cm): 
            d_list += d[i]
            e_list += e[i]
        rec_list = d_list + e_list
        robust_rec = await self.robust_rec_step(rec_list, 3)
        # robust_rec_d = await self.robust_rec_step(d_list, robust_rec_sig)
  
        # robust_rec_e = await self.robust_rec_step(e_list, robust_rec_sig)
        robust_rec_d = robust_rec[:int(len(robust_rec)/2)]
        robust_rec_e = robust_rec[int(len(robust_rec)/2):]
        
        rec_d = [[self.ZR(0) for _ in range(self.t)] for _ in range(cm)]
        rec_e = [[self.ZR(0) for _ in range(self.t)] for _ in range(cm)]
        for i in range(cm):
            for j in range(self.t): 
                rec_d[i][j] = robust_rec_d[i*self.t+j]
                rec_e[i][j] = robust_rec_e[i*self.t+j]

        # 这里对应协议的 step 17    
        for i in range(cm):
            for j in range(self.t): 
                index1 = j + self.t + 1
                index2 = T_list[index1]
                w[i][index1] = rec_d[i][j] * rec_e[i][j] + rec_d[i][j] * mult_triples_shares[index2][i][1] + rec_e[i][j] * mult_triples_shares[index2][i][0] + mult_triples_shares[index2][i][2]

        # 这里对应协议的 step 18
        for i in range(cm):
            w_poly.append([])
            for j in range(2*self.t+1): 
                w_poly[i].append([T_list[j]+1, w[i][j]])
        u_point, v_point, w_point = [None] * cm, [None] * cm, [None] * cm
        for i in range(cm):
            point = 3 * self.t + 2
            u_point[i] = self.poly.interpolate_at(u_poly[i], point)
            v_point[i] = self.poly.interpolate_at(v_poly[i], point)
            w_point[i] = self.poly.interpolate_at(w_poly[i], point)

        aprep_triples = []
        for i in range(cm): 
            aprep_triples.append([])
            aprep_triples[i].append(u_point[i])
            aprep_triples[i].append(v_point[i])
            aprep_triples[i].append(w_point[i])
            
        # 测试代码，测试 w == u * v
        # u_point_list, v_point_list, w_point_list = [], [], []
        # for i in range(1): 
        #     u_point_list.append(u_point[i])
        #     v_point_list.append(v_point[i])
        #     w_point_list.append(w_point[i])
        
        # robust_rec_u = await self.robust_rec_step(u_point_list, robust_rec_sig)
        # await robust_rec_sig.wait()
        # robust_rec_sig.clear()
        # robust_rec_v = await self.robust_rec_step(v_point_list, robust_rec_sig)
        # await robust_rec_sig.wait()
        # robust_rec_sig.clear()
        # robust_rec_w = await self.robust_rec_step(w_point_list, robust_rec_sig)
        # await robust_rec_sig.wait()
        # robust_rec_sig.clear()
        # if robust_rec_w[0] == robust_rec_u[0] * robust_rec_v[0]:
        #     print(f"pass")
        # else: 
        #     print(f"false")

        
        return aprep_triples
    
    
    async def gen_rand_step(self, rand_num, rand_outputs):
        # 这里 APREPMsgType.ACSS 都是 acss 有可能会和接下来的 trans 协议冲突
        if rand_num > self.n - self.t: 
            rounds = math.ceil(rand_num / (self. n - self.t))
        else: 
            rounds = 1

        randtag = APREPMsgType.GENRAND
        randsend, randrecv = self.get_send(randtag), self.subscribe_recv(randtag)
        curve_params = (self.ZR, self.G1, self.multiexp, self.dotprod)
        self.rand_foll = Rand_Foll(self.public_keys, self.private_key, 
                              self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                              randsend, randrecv, self.pc, curve_params, self.matrix, 
                              mpc_instance=self.mpc_instance)
        # print(f"{self.mpc_instance.layer_ID}")
        self.rand_task = asyncio.create_task(self.rand_foll.run_rand(rand_num, rounds))
        rand_outputs = await self.rand_task
        # print(f"len(rand_outputs): {len(rand_outputs)}, rand_outputs: {rand_outputs}")
        return rand_outputs

        while True: 
            # rand_outputs = await self.rand.output_queue.get()
            rand_outputs = await self.rand_task

            if len(rand_outputs) == rand_num: 
                # print(f"my id: {self.my_id} rand_outputs: {rand_outputs}")
                rand_signal.set()
                return rand_outputs
            
    async def robust_rec_step(self, rec_shares, index):                
        
        # self.rectasks = [None] * len(rec_shares)
        # for i in range(len(rec_shares)): 
        #     self.rectasks[i] = asyncio.create_task(self.rec.run_robust_rec(i, rec_shares[i]))
        # rec_values = await asyncio.gather(*self.rectasks)
        # print(f"my id: {self.my_id} rec_values: {rec_values}")

        # rec_signal.set()
        

        rec_values = await self.rec.batch_run_robust_rec(index, rec_shares, self.member_list)

        return rec_values
        
    
    async def run_aprep(self, cm):
        gen_rand_outputs = []

        # 这里是调用 Protocol Rand 来生成随机数
        gen_rand_time = time.time()
        gen_rand_outputs = await self.gen_rand_step(self.n*cm, gen_rand_outputs)
        gen_rand_time = time.time() - gen_rand_time
        print(f"gen_rand_time: {gen_rand_time}")

        # 这一步是 acss 的过程
        acss_time = time.time()
        self.acss_task = asyncio.create_task(self.acss_step(cm))
        acss_outputs = await self.acss_task
        acss_time = time.time() - acss_time
        print(f"acss_time: {acss_time}")
        # print(f"aprep_acss_time: {time.time()-aprep_acss_start_time}")
        # print("acss_outputs: ", acss_outputs)

        # print(f"id: {self.my_id} gen_rand_outputs: {gen_rand_outputs}")

        # 这里调用 Protocol Robust-Rec 来重构出刚才生成的随机数的原始值
        rec_time = time.time()
        self.member_list = []
        for i in range(self.n): 
            self.member_list.append(self.n * (self.mpc_instance.layer_ID) + i)
        robust_rec_outputs = await self.robust_rec_step(gen_rand_outputs, 0)
        rec_time = time.time() - rec_time
        print(f"rec_time: {rec_time}")
        # print(f"tes_time: {time.time()-tes_time}")

        
        
        # print(f"robust_rec_outputs: {robust_rec_outputs}")

        # 这一步我们需要用 chec_triples 来验证 mult_triples 中的三元组是否 c = a * b
        # 这里 'msg' 表示的是 phis 集合，'rand' 表示的是 phis_hat 集合，phis[0] 里面的元素是 mult_triples，phis[1] 里面的元素是 chec_triples
        # 这里 acss_outputs[n] 中的 n 代表的是不同节点提供的三元组
        # print(f"acss_outputs[0]['shares']['msg'][0][0]: {acss_outputs[0]['shares']['msg'][0][0]}")
        rec_time1 = time.time()
        mult_triples_shares = [[0 for _ in range(cm)] for _ in range(len(acss_outputs))]
        chec_triples_shares = [[0 for _ in range(cm)] for _ in range(len(acss_outputs))]
        rands = [[0 for _ in range(cm)] for _ in range(len(acss_outputs))]
        for node in range(len(acss_outputs)): 
            for i in range(cm): 
                mult_triples_shares[node][i] = acss_outputs[node]['shares']['msg'][0][i]
                chec_triples_shares[node][i] = acss_outputs[node]['shares']['msg'][1][i]
                rands[node][i] = robust_rec_outputs[node*cm+i]
        # 这一步开始用 chec 三元组来计算 乘法三元组
        # print(f"my id: {self.my_id} mult_triples_shares[0][0]: {mult_triples_shares[0][0]}")
        rho = [[0 for _ in range(cm)] for _ in range(len(acss_outputs))]
        sigma = [[0 for _ in range(cm)] for _ in range(len(acss_outputs))]
        for node in range(len(acss_outputs)): 
            for i in range(cm): 
                rho[node][i] = rands[node][i] * mult_triples_shares[node][i][0] - chec_triples_shares[node][i][0]
                sigma[node][i] = mult_triples_shares[node][i][1] - chec_triples_shares[node][i][1]
                # sigma[node][i] = chec_triples_shares[node][i][1] - mult_triples_shares[node][i][1]
        rho_list = []
        sigma_list = []
        for i in range(len(acss_outputs)): 
            rho_list += rho[i]
            sigma_list += sigma[i]
        # 这里调用 Robust-Rec 协议重构 rho 和 sigma
        aprep_rec_start_time = time.time()
        rec_list = rho_list + sigma_list
        robust_rec = await self.robust_rec_step(rec_list, 1)
        rec_time1 = time.time() - rec_time1
        print(f"rec_time1: {rec_time1}")
        # robust_rec_rho = await self.robust_rec_step(rho_list, robust_rec_signal)
        
        # robust_rec_sigma = await self.robust_rec_step(sigma_list, robust_rec_signal)
        
        # print(f"aprep_rec_time: {time.time()-aprep_rec_start_time}")
        # print(f"robust_rec_rho: {robust_rec_rho}")

        rec_time2 = time.time()
        robust_rec_rho = robust_rec[:int(len(robust_rec)/2)]
        robust_rec_sigma = robust_rec[int(len(robust_rec)/2):]
        rec_rho = [[0 for _ in range(cm)] for _ in range(len(acss_outputs))]
        rec_sigma = [[0 for _ in range(cm)] for _ in range(len(acss_outputs))]
        for node in range(len(acss_outputs)): 
            for i in range(cm): 
                rec_rho[node][i] = robust_rec_rho[node*cm+i]
                rec_sigma[node][i] = robust_rec_sigma[node*cm+i]
        
        # 下面是计算 \tau 并调用 protocol Robust-Rec 来重构 \tau 检测是否等于 0
        tau = [[0 for _ in range(cm)] for _ in range(len(acss_outputs))]
        for node in range(len(acss_outputs)): 
            for i in range(cm): 
                tau[node][i] = rands[node][i] * mult_triples_shares[node][i][2] - chec_triples_shares[node][i][2] - rec_sigma[node][i] * chec_triples_shares[node][i][0] - rec_rho[node][i] * chec_triples_shares[node][i][1] - rec_rho[node][i] * rec_sigma[node][i]
        # print(f"tau[0][0]: {tau[0][0]}")
        tau_list = []
        for i in range(len(acss_outputs)): 
            tau_list += tau[i]
        robust_rec_tau = await self.robust_rec_step(tau_list, 2)
        
        # print(f"robust_rec_tau: {robust_rec_tau}")
        rec_tau = [[0 for _ in range(cm)] for _ in range(len(acss_outputs))]
        for node in range(len(acss_outputs)): 
            for i in range(cm): 
                rec_tau[node][i] = robust_rec_tau[node*cm+i]
        # print(f"rec_tau: {rec_tau}")

        # 这里检查 \tau 是否等于0，如果等于0，就放到 key_proposal 中
        key_proposal = []
        for node in range(len(acss_outputs)): 
            for i in range(cm): 
                if rec_tau[node][i] != self.ZR(0):
                    break
            key_proposal.append(node)
        # print(f"key_proposal: {key_proposal}")
        rec_time2 = time.time() - rec_time2
        print(f"rec_time2: {rec_time2}")
        

        # 这一步是 MVBA 的过程
        aprep_mvba_time = time.time()
        create_acs_task = asyncio.create_task(self.agreement(key_proposal, mult_triples_shares, rec_tau, cm))
        acs, key_task, work_tasks = await create_acs_task
        await acs
        output = await key_task
        await asyncio.gather(*work_tasks)
        # mks, sk, pk = output
        new_mult_triples = output
        aprep_mvba_time = time.time() - aprep_mvba_time
        print(f"aprep_mvba_time: {aprep_mvba_time}")
        # self.output_queue.put_nowait((values[1], mks, sk, pk))
        # self.output_queue.put_nowait(new_mult_triples)
        return new_mult_triples