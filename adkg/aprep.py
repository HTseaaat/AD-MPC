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

class ADKGMsgType:
    ACSS = "A"
    RBC = "R"
    ABA = "B"
    PREKEY = "P"
    KEY = "K"
    MASK = "M"
    GENRAND = "GR"
    ROBUSTREC = "RR"
    
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

    async def acss_step(self, outputs, aprep_values, acss_signal):
        # 这里 ADKGMsgType.ACSS 都是 acss 有可能会和接下来的 trans 协议冲突
        acsstag = ADKGMsgType.ACSS
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
            rbctag =ADKGMsgType.RBC + str(j) # (R, msg)
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

            abatag = ADKGMsgType.ABA + str(j) # (B, msg)
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
            self.new_share(
                acss_outputs,
                acss_signal,
                rbc_values,
                rbc_signal,
            ),
            work_tasks,
        )

    async def new_share(self, acss_outputs, acss_signal, rbc_values, rbc_signal):
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
        secrets = [[self.ZR(0)]*self.n for _ in range(self.sc-1)]
        randomness = [[self.ZR(0)]*self.n for _ in range(self.sc-1)]
        commits = [[self.G1.identity()]*self.n for _ in range(self.sc-1)]
        for idx in range(self.sc-1):
            for node in range(self.n):
                if node in self.mks:
                    # 重点！！这里 secrets 存的是 idx+1 ，也就是有 phi_hat 对应的 那个 phi 多项式，而不是 Feldman 承诺的 k=0 那个多项式
                    secrets[idx][node] = acss_outputs[node]['shares']['msg'][idx+1]
                    # print(f"secret[{idx}][{node}] = {secrets[idx][node]}")
                    randomness[idx][node] = acss_outputs[node]['shares']['rand'][idx]
                    # print(f"randomness[{idx}][{node}] = {randomness[idx][node]}")
                    commits[idx][node] = acss_outputs[node]['commits'][idx+1][0]
                    # print(f"commits[{idx}][{node}] = {commits[idx][node]}")
        
    
        z_shares = [self.ZR(0)]*self.n
        r_shares = [self.ZR(0)]*self.n

        sc_shares = []
        for i in self.mks:
            sc_shares.append([i+1, secrets[0][i]])

        # print(f"sc_shares: {sc_shares}")

        # 这里测试的就是在得到公共子集之后重构新的 shares 
        res = self.poly.interpolate_at(sc_shares, 0)
        # print(f"{self.my_id} res: {res}")

        # 这里测试的是两个 shares 的加法
        test_add = secrets[0][0] + secrets[0][1]
        # print(f"{self.my_id} test_add: {test_add}")

        # 这里测试的是两个 shares 的乘法
        # pp = PreProcessedElements()
        # pp.generate_triples(10, self.n, self.t)
        # async def _prog(ctx):
        #     for _ in range(10):
        #         a_sh, b_sh, ab_sh = ctx.preproc.get_triples(ctx)
        #         a, b, ab = await a_sh.open(), await b_sh.open(), await ab_sh.open()
        #         assert a * b == ab

        # program_runner = TaskProgramRunner(self.n, self.t)
        # program_runner.add(_prog)
        # await program_runner.join()
    
        # return (self.mks, secret, pk)
        return (self.mks, res)

    # async def masked_values(): 

    
    
    async def gen_rand_step(self, rand_num, rand_outputs, rand_signal):
        # 这里 ADKGMsgType.ACSS 都是 acss 有可能会和接下来的 trans 协议冲突
        if rand_num > self.n - self.t: 
            rounds = math.ceil(rand_num / (self. n - self.t))
        else: 
            rounds = 1
        randtag = ADKGMsgType.GENRAND
        randsend, randrecv = self.get_send(randtag), self.subscribe_recv(randtag)
        curve_params = (self.ZR, self.G1, self.multiexp, self.dotprod)
        self.rand = Rand(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.my_id, randsend, randrecv, self.pc, curve_params, self.matrix)
        self.rand_task = asyncio.create_task(self.rand.run_rand(rand_num, rounds))

        while True: 
            rand_outputs = await self.rand.output_queue.get()

            if len(rand_outputs) == rand_num: 
                print(f"my id: {self.my_id} rand_outputs: {rand_outputs}")
                rand_signal.set()
                return rand_outputs
            
    async def robust_rec_step(self, rec_shares, rec_signal):        
        
        # self.rectask = asyncio.create_task(self.rec.run_robust_rec(0, rec_shares[0]))
        
        
        self.rectasks = [None] * len(rec_shares)
        for i in range(len(rec_shares)): 
            self.rectasks[i] = asyncio.create_task(self.rec.run_robust_rec(i, rec_shares[i]))
        rec_values = await asyncio.gather(*self.rectasks)
        # rec_values = await self.rectasks[1]
        print(f"my id: {self.my_id} rec_values: {rec_values}")

        # for task in self.rectasks: 
        #     task.cancel()
           
        # res = await self.rec.run_robust_rec(0, rec_shares[0])
        # print(res)
        # res1 = await self.rec.run_robust_rec(1, rec_shares[1])
        # print(res1)

        # 这里我给搞成顺序执行的了，后面需要改成并行执行
        # rec_values = [None] * len(rec_shares)
        # for i in range(len(rec_shares)): 
        #     rec_values[i] = await self.rec.run_robust_rec(i, rec_shares[i])
        #     print(f"my id: {self.my_id} here")
            # print(f"rec_values[{i}]: {rec_values[i]}")
        
        # print(f"my id: {self.my_id} rec_values: {rec_values}")
        rec_signal.set()
        return rec_values
        # rec_values = []

        # while True: 
        #     rec_value = await self.rec.output_queue.get()
        #     print(f"my id: {self.my_id} rec_outputs: {rec_value}")
        #     rec_values.append(rec_value)
        #     # rec_signal.set()
        #     # return rec_values
        #     if len(rec_values) == len(rec_shares):
        #         print(f"my id: {self.my_id} rand_outputs: {rec_values}")
        #         rec_signal.set()
        #         return rec_values
        

    
    async def robust_rec_step_test(self, rec_shares, rec_signal):        
        
        # self.rectask = asyncio.create_task(self.rec.run_robust_rec(0, rec_shares[0]))
        
        
        self.rectasks = [None] * len(rec_shares)
        for i in range(len(rec_shares)): 
            self.rectasks[i] = asyncio.create_task(self.rec.run_robust_rec_test(i, rec_shares[i]))
        rec_values = await asyncio.gather(*self.rectasks)
        # rec_values = await self.rectasks[1]
        print(f"my id: {self.my_id} rec_values: {rec_values}")

        # for task in self.rectasks: 
        #     task.cancel()
           
        # res = await self.rec.run_robust_rec(0, rec_shares[0])
        # print(res)
        # res1 = await self.rec.run_robust_rec(1, rec_shares[1])
        # print(res1)

        # 这里我给搞成顺序执行的了，后面需要改成并行执行
        # rec_values = [None] * len(rec_shares)
        # for i in range(len(rec_shares)): 
        #     rec_values[i] = await self.rec.run_robust_rec(i, rec_shares[i])
        #     print(f"my id: {self.my_id} here")
            # print(f"rec_values[{i}]: {rec_values[i]}")
        
        # print(f"my id: {self.my_id} rec_values: {rec_values}")
        rec_signal.set()
        return rec_values
    
    async def run_aprep(self, cm):
        logging.info(f"Starting ADKG for node {self.my_id}")
        
        gen_rand_outputs = []
        gen_rand_signal = asyncio.Event()

        # 这里是调用 Protocol Rand 来生成随机数
        gen_rand_outputs = await self.gen_rand_step(self.n*cm, gen_rand_outputs, gen_rand_signal)
               

        acss_outputs = {}
        acss_signal = asyncio.Event()



        # 每个参与方生成下一个 epoch 需要的乘法三元组
        mult_triples = [[self.ZR.rand() for _ in range(3)] for _ in range(cm)]
        chec_triples = [[self.ZR.rand() for _ in range(3)] for _ in range(cm)]
        # rand_values = [None] * cm
        for i in range(cm): 
            mult_triples[i][2] = mult_triples[i][0] * mult_triples[i][1]
            chec_triples[i][2] = chec_triples[i][0] * chec_triples[i][1]
            # rand_values[i] = self.ZR.rand()

        aprep_values = (mult_triples, chec_triples, cm)      

        # 这一步是 acss 的过程
        self.acss_task = asyncio.create_task(self.acss_step(acss_outputs, aprep_values, acss_signal))
        await acss_signal.wait()
        acss_signal.clear()
        # print("acss_outputs: ", acss_outputs)

        # 这两步可以放到调用 robust-rec 之前
        await gen_rand_signal.wait()
        gen_rand_signal.clear()

        print(f"id: {self.my_id} gen_rand_outputs: {gen_rand_outputs}")

        # 这里调用 Protocol Robust-Rec 来重构出刚才生成的随机数的原始值
        # robust_rec_outputs = []
        robust_rec_signal = asyncio.Event()

        # 这里是调用 Protocol Rand 来生成随机数
        robust_rec_outputs = await self.robust_rec_step(gen_rand_outputs, robust_rec_signal)

        await robust_rec_signal.wait()
        robust_rec_signal.clear()
        print(f"robust_rec_outputs: {robust_rec_outputs}")

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
                rands[node][i] = robust_rec_outputs[node*2+i]
        # 这一步开始用 chec 三元组来计算 乘法三元组
        rho = [[0 for _ in range(cm)] for _ in range(len(acss_outputs))]
        sigma = [[0 for _ in range(cm)] for _ in range(len(acss_outputs))]
        for node in range(len(acss_outputs)): 
            for i in range(cm): 
                rho[node][i] = rands[node][i] * mult_triples_shares[node][i][0] - chec_triples_shares[node][i][0]
                sigma[node][i] = mult_triples_shares[node][i][1] - chec_triples_shares[node][i][1]
        rho_list = []
        sigma_list = []
        for i in range(len(acss_outputs)): 
            rho_list += rho[i]
            sigma_list += sigma[i]
        # 这里调用 Robust-Rec 协议重构 rho 和 sigma
        robust_rho_signal = asyncio.Event()
        robust_rec_rho = await self.robust_rec_step(rho_list, robust_rho_signal)
        await robust_rho_signal.wait()
        robust_rho_signal.clear()
        print(f"robust_rec_rho: {robust_rec_rho}")
        
        key_proposal = list(acss_outputs.keys())

        # 这一步是 MVBA 的过程
        create_acs_task = asyncio.create_task(self.agreement(key_proposal, acss_outputs, acss_signal))
        acs, key_task, work_tasks = await create_acs_task
        await acs
        output = await key_task
        await asyncio.gather(*work_tasks)
        # mks, sk, pk = output
        mks, new_shares = output
        # self.output_queue.put_nowait((values[1], mks, sk, pk))
        self.output_queue.put_nowait((mks, new_shares))
        
        logging.info(f"ADKG finished! Node {self.my_id}")