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
from adkg.utils.serilization import Serial
from adkg.rand import Rand
from adkg.robust_rec import Robust_Rec
import math

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

        rec_values = await self.rec.batch_run_robust_rec(index, rec_shares)

        return rec_values
        
    
    async def run_aprep(self, cm):
        gen_rand_outputs = []
        gen_rand_signal = asyncio.Event()

        # 这里是调用 Protocol Rand 来生成随机数
        gen_rand_outputs = await self.gen_rand_step(self.n*cm, gen_rand_outputs, gen_rand_signal)
               

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
        # aprep_acss_start_time = time.time()
        self.acss_task = asyncio.create_task(self.acss_step(acss_outputs, aprep_values, acss_signal))
        await acss_signal.wait()
        acss_signal.clear()
        # print(f"aprep_acss_time: {time.time()-aprep_acss_start_time}")
        # print("acss_outputs: ", acss_outputs)

        # 这两步可以放到调用 robust-rec 之前
        await gen_rand_signal.wait()
        gen_rand_signal.clear()

        # print(f"id: {self.my_id} gen_rand_outputs: {gen_rand_outputs}")

        # 这里调用 Protocol Robust-Rec 来重构出刚才生成的随机数的原始值
        # robust_rec_outputs = []
        tes_time = time.time()
        robust_rec_outputs = await self.robust_rec_step(gen_rand_outputs, 0)
        # print(f"tes_time: {time.time()-tes_time}")

        
        
        # print(f"robust_rec_outputs: {robust_rec_outputs}")

        # 这一步我们需要用 chec_triples 来验证 mult_triples 中的三元组是否 c = a * b
        # 这里 'msg' 表示的是 phis 集合，'rand' 表示的是 phis_hat 集合，phis[0] 里面的元素是 mult_triples，phis[1] 里面的元素是 chec_triples
        # 这里 acss_outputs[n] 中的 n 代表的是不同节点提供的三元组
        # print(f"acss_outputs[0]['shares']['msg'][0][0]: {acss_outputs[0]['shares']['msg'][0][0]}")
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
        # robust_rec_rho = await self.robust_rec_step(rho_list, robust_rec_signal)
        
        # robust_rec_sigma = await self.robust_rec_step(sigma_list, robust_rec_signal)
        
        # print(f"aprep_rec_time: {time.time()-aprep_rec_start_time}")
        # print(f"robust_rec_rho: {robust_rec_rho}")

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
        

        # 这一步是 MVBA 的过程
        create_acs_task = asyncio.create_task(self.agreement(key_proposal, mult_triples_shares, rec_tau, cm))
        acs, key_task, work_tasks = await create_acs_task
        await acs
        output = await key_task
        await asyncio.gather(*work_tasks)
        # mks, sk, pk = output
        new_mult_triples = output
        # self.output_queue.put_nowait((values[1], mks, sk, pk))
        # self.output_queue.put_nowait(new_mult_triples)
        return new_mult_triples
        
