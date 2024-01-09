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
    
class CP:
    def __init__(self, g, h, ZR):
        self.g  = g
        self.h = h
        self.ZR = ZR

    def dleq_derive_chal(self, x, y, a1, a2):
        commit = str(x)+str(y)+str(a1)+str(a2)
        try:
            commit = commit.encode()
        except AttributeError:
            pass 
        hs =  hashlib.sha256(commit).digest() 
        return self.ZR.hash(hs)

    def dleq_verify(self, x, y, chal, res):
        a1 = self.multiexp([x, self.g],[chal, res])
        a2 = self.multiexp([y, self.h],[chal, res])

        eLocal = self.dleq_derive_chal(x, a1, y, a2)
        return eLocal == chal

    def dleq_prove(self, alpha, x, y):
        w = self.ZR.random()
        a1 = self.g**w
        a2 = self.h**w
        e = self.dleq_derive_chal(x, a1, y, a2)
        return  e, w - e*alpha # return (challenge, response)

# 这个就是他的零知识证明的代码
class PoK:
    def __init__(self, g, ZR, multiexp):
        self.g  = g
        self.ZR = ZR
        self.multiexp = multiexp

    def pok_derive_chal(self, x, a):
        commit = str(x)+str(a)
        try:
            commit = commit.encode()
        except AttributeError:
            pass 
        hs =  hashlib.sha256(commit).digest() 
        return self.ZR.hash(hs)

    def pok_verify(self, x, chal, res):
        a = self.multiexp([x, self.g],[chal, res])
        eLocal = self.pok_derive_chal(x, a)
        return eLocal == chal

    def pok_prove(self, alpha, x):
        w = self.ZR.rand()
        a = self.g**w
        e = self.pok_derive_chal(x, a)
        return  e, w - e*alpha # return (challenge, response)
    
class Trans:
    def __init__(self, public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, matrices):
        self.public_keys, self.private_key, self.g, self.h = (public_keys, private_key, g, h)
        self.n, self.t, self.deg, self.my_id = (n, t, deg, my_id)
        self.sc = ceil((deg+1)/(t+1)) + 1
        self.send, self.recv, self.pc = (send, recv, pc)
        self.ZR, self.G1, self.multiexp, self.dotprod = curve_params
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

    async def acss_step(self, outputs, trans_values, acss_signal):
        acsstag = ADKGMsgType.ACSS
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)
        self.acss = ACSS(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, acsssend, acssrecv, self.pc, self.ZR, self.G1
                         , self.rbcl_list
                         )
        self.acss_tasks = [None] * self.n
        # 这里的话应该是 n-parallel ACSS，看一下怎么做到的
        for i in range(self.n):
            if i == self.my_id:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss(0, values=trans_values))
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

    async def print_rbc_outputs(self, rbc_outputs): 
        for j in range(len(rbc_outputs)): 
            while not rbc_outputs[j].empty(): 
                message = await rbc_outputs[j].get()
                print(f"rbc_outputs[{j}]: {message}")
    
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
                print(f"key_proposal: {key_proposal}")
                riv = Bitmap(self.n)
                for k in key_proposal: 
                    riv.set_bit(k)
                rbc_input = bytes(riv.array)
                print(f"riv.array: {riv.array}")
                print(f"rbc_input: {rbc_input}")

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
        print(f"rbc_values: {rbc_values}")
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

        print("mks: ", self.mks)

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
                    print(f"secret[{idx}][{node}] = {secrets[idx][node]}")
                    randomness[idx][node] = acss_outputs[node]['shares']['rand'][idx]
                    print(f"randomness[{idx}][{node}] = {randomness[idx][node]}")
                    commits[idx][node] = acss_outputs[node]['commits'][idx+1][0]
                    print(f"commits[{idx}][{node}] = {commits[idx][node]}")
        
    
        z_shares = [self.ZR(0)]*self.n
        r_shares = [self.ZR(0)]*self.n

        sc_shares = []
        for i in self.mks:
            sc_shares.append([i+1, secrets[0][i]])

        print(f"sc_shares: {sc_shares}")

        # 这里测试的就是在得到公共子集之后重构新的 shares 
        res = self.poly.interpolate_at(sc_shares, 0)
        print(f"{self.my_id} res: {res}")

        # 这里测试的是两个 shares 的加法
        test_add = secrets[0][0] + secrets[0][1]
        print(f"{self.my_id} test_add: {test_add}")

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

    
    async def rbc_masked_step(self, rbc_masked_input): 
        # print(f"{self.my_id} run the rbc masked step")
        # print(f"{self.my_id} rbc_masked_input: {rbc_masked_input}")

        rbc_outputs = [asyncio.Queue() for _ in range(self.n)]
        
        async def predicate(serialized_masked_input):
            return True


        async def _setup(j):            
            # starting RBC
            rbctag =ADKGMsgType.MASK + str(j) # (M, msg)
            rbcsend, rbcrecv = self.get_send(rbctag), self.subscribe_recv(rbctag)

            rbc_input = None
            if j == self.my_id: 
                riv = Bitmap(self.n)
                riv.set_bit(j)
                rbc_input = rbc_masked_input
                print(f"{self.my_id} rbc_input: {rbc_input}")

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

        await asyncio.gather(*[_setup(j) for j in range(self.n)])

        # 这里存的是序列化的各方广播的 masked values and commitments
        self.rbcl_list = await asyncio.gather(*(rbc_outputs[j].get() for j in range(self.n)))    

    
    async def run_trans(self, start_time):
        logging.info(f"Starting ADKG for node {self.my_id}")
        acss_outputs = {}
        acss_signal = asyncio.Event()

        acss_start_time = time.time()
        # values 的个数取决于 sc，sc 是什么目前还没看到，目前 values 设置的数量是 2 个
        # values =[self.ZR.rand() for _ in range(self.sc)]

        values = [None] * (self.sc)
        values[0] = self.ZR.rand()
        values[1] = self.ZR(2*(self.my_id+1)+3)

        # 这里模拟的是 private input 的 phi_hat 就是 values 对应的随机数，我们这里的设置是在调用 acss 之前就生成好这些随机数，然后再传入 acss 中
        values_hat = [None] * self.sc
        values_hat[0] = self.ZR.rand()
        values_hat[1] = self.ZR.rand()

        # 这里模拟的是用来给 private input 设置 masked values 的随机数 alpha 和 alpha_hat
        alpha = self.ZR(self.my_id+1+7)
        alpha_hat = self.ZR(3*(self.my_id+1)+5)
        # print("values: ", values)

        # 这一步是给 private input vlaues[1] 加一个 masked value 
        masked_values = values[1] + alpha
        masked_values_hat = values_hat[1] + alpha_hat
        # c = self.pc.commit_alpha(alpha, alpha_hat)
        c = self.pc.commit_alpha(alpha, alpha_hat)

        # 我们需要先执行 rbc ，再在 acss 过程中去验证我们的 masked values 的值是否是正确的，这里我们需要一个 signal 来先让acss 协程等待 rbc 结束
        # rbc_masked_signal = asyncio.Event()
        sr = Serial(self.G1)
        serialized_masked_values = sr.serialize_f(masked_values)
        serialized_masked_values_hat = sr.serialize_f(masked_values_hat)
        serialized_c = sr.serialize_g(c)
        rbc_masked_input = serialized_masked_values + serialized_masked_values_hat + serialized_c
        await asyncio.create_task(self.rbc_masked_step(rbc_masked_input))        

        # 这里 我们把要传入的参数放到一个集合中再传入 acss
        trans_values = (values, values_hat)
        # 这一步是 acss 的过程
        self.acss_task = asyncio.create_task(self.acss_step(acss_outputs, trans_values, acss_signal))
        await acss_signal.wait()
        acss_signal.clear()
        print("acss_outputs: ", acss_outputs)
        acss_time = time.time() - acss_start_time
        self.benchmark_logger.info(f"ACSS time: {(acss_time)}")
        
        key_proposal = list(acss_outputs.keys())


        # 这一步是 MVBA 的过程
        create_acs_task = asyncio.create_task(self.agreement(key_proposal, acss_outputs, acss_signal))
        acs, key_task, work_tasks = await create_acs_task
        await acs
        output = await key_task
        adkg_time = time.time()-start_time
        await asyncio.gather(*work_tasks)
        # mks, sk, pk = output
        mks, new_shares = output
        # self.output_queue.put_nowait((values[1], mks, sk, pk))
        self.output_queue.put_nowait((mks, new_shares))
        
        self.benchmark_logger.info("ADKG time: %f", adkg_time)
        logging.info(f"ADKG finished! Node {self.my_id}, time: {adkg_time} (seconds)")