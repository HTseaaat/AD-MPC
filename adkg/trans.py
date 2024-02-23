from adkg.polynomial import polynomials_over, EvalPoint
from adkg.utils.poly_misc import interpolate_g1_at_x
from adkg.utils.misc import wrap_send, subscribe_recv
import asyncio
import hashlib, time
from math import ceil
import logging
from adkg.utils.bitmap import Bitmap
from adkg.acss import ACSS, ACSS_Pre, ACSS_Foll, ACSS_Fluid_Pre, ACSS_Fluid_Foll

from adkg.broadcast.tylerba import tylerba
from adkg.broadcast.optqrbc import optqrbc, optqrbc_dynamic

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

class TRANSMsgType:
    ACSS = "TR.A"
    RBC = "TR.R"
    ABA = "TR.B"
    PREKEY = "TR.P"
    KEY = "TR.K"
    MASK = "TR.M"
    GENRAND = "TR.GR"
    ROBUSTREC = "TR.RR"
    TRANS = "TR.TR"
    APREP = "TR.AP"

class Trans:
    def __init__(self, public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params):
        self.public_keys, self.private_key, self.g, self.h = (public_keys, private_key, g, h)
        self.n, self.t, self.deg, self.my_id = (n, t, deg, my_id)
        self.sc = ceil((deg+1)/(t+1)) + 1
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

        rectag = TRANSMsgType.ROBUSTREC
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

    async def acss_step(self, outputs, trans_values, acss_signal):
        acsstag = TRANSMsgType.ACSS
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)
        self.acss = ACSS(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, acsssend, acssrecv, self.pc, self.ZR, self.G1
                         , self.rbcl_list
                         )
        self.acss_tasks = [None] * self.n
        # 这里的话应该是 n-parallel ACSS，看一下怎么做到的
        len_values = len(trans_values[0])
        for i in range(self.n):
            if i == self.my_id:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss_trans(0, len_values, values=trans_values))
            else:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss_trans(0, len_values, dealer_id=i))

        while True:
            (dealer, _, shares, commitments) = await self.acss.output_queue.get()
            outputs[dealer] = {'shares':shares, 'commits':commitments}
            # print("outputs: ", outputs[dealer])
            if len(outputs) >= self.n - self.t:
                # print("Player " + str(self.my_id) + " Got shares from: " + str([output for output in outputs]))
                acss_signal.set()

            if len(outputs) == self.n:
                return    

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
    
    async def agreement(self, key_proposal, de_masked_value, acss_outputs, acss_signal):
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
            # print(f"kpl: {kpl}")
            # print(f"de_masked_value: {de_masked_value}")
            if len(kpl) <= self.t:
                return False
            
            GFEG1 = GF(Subgroup.BLS12_381)
            point = EvalPoint(GFEG1, self.n, use_omega_powers=False)
            poly, err = [None] * len(de_masked_value), [None] * len(de_masked_value)
            for i in range(len(de_masked_value)): 
                poly[i], err[i] = await robust_reconstruct_admpc(de_masked_value[i], key_proposal, GFEG1, self.t, point, self.t)
            err_list = [list(err[i]) for i in range(len(err))]
            for i in range(len(err_list)): 
                if len(err_list[i]) != 0: 
                    return False         
        
            return True

        async def _setup(j):
            
            # starting RBC
            rbctag = TRANSMsgType.RBC + str(j) # (R, msg)
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

            abatag = TRANSMsgType.ABA + str(j) # (B, msg)
            # abatag = TRANSMsgType.ABA + str(j)
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
                rbc_signal,
                rbc_values,
                [_.put_nowait for _ in coin_keys],
                [_.put_nowait for _ in aba_inputs],
                [_.get for _ in aba_outputs],
            ),
            self.new_share(
                rbc_values,
                rbc_signal,
                acss_outputs,
                acss_signal, 
            ),
            work_tasks,
        )

    async def new_share(self, rbc_values, rbc_signal, acss_outputs, acss_signal):
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
        mks_list = list(self.mks)
        secrets_num = len(acss_outputs[mks_list[0]]['shares']['msg'])
        secrets = [[self.ZR(0) for _ in range(self.n)] for _ in range(secrets_num)]
        # secrets = [self.ZR(0)] * self.n 

        for i in range(secrets_num): 
            for node in range(self.n): 
                if node in self.mks: 
                    secrets[i][node] = acss_outputs[node]['shares']['msg'][i]
        
        # for node in range(self.n):
        #     if node in self.mks:
        #         secrets[node] = acss_outputs[node]['shares']['msg'][index]
        #         print(f"secret[{node}] = {secrets[node]}")
                    

        sc_shares = []
        for i in range(secrets_num): 
            sc_shares.append([])
            for j in self.mks:
                sc_shares[i].append([j+1, secrets[i][j]])

        # print(f"my id: {self.my_id} sc_shares: {sc_shares}")

        # 这里测试的就是在得到公共子集之后重构新的 shares 
        res = []
        for i in range(secrets_num):
            res.append(self.poly.interpolate_at(sc_shares[i], 0))
        # res = self.poly.interpolate_at(sc_shares, 0)
        # print(f"my id: {self.my_id} res: {res}")

        return res

    # async def masked_values(): 

    
    async def rbc_masked_step(self, rbc_masked_input): 
        # print(f"{self.my_id} run the rbc masked step")
        # print(f"{self.my_id} rbc_masked_input: {rbc_masked_input}")

        rbc_outputs = [asyncio.Queue() for _ in range(self.n)]
        
        async def predicate(_m):
            return True


        async def _setup(j):            
            # starting RBC
            rbctag =TRANSMsgType.MASK + str(j) # (M, msg)
            rbcsend, rbcrecv = self.get_send(rbctag), self.subscribe_recv(rbctag)

            rbc_input = None
            if j == self.my_id: 
                rbc_input = rbc_masked_input
                # print(f"{self.my_id} rbc_input: {rbc_input}")

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
    
    async def run_trans(self, values, rand_values):
        self.len_values = len(values)
        # 这里模拟的是 step 1
        rand_values_hat = [None] * len(values)
        values_hat = [None] * len(values)
        for i in range(len(values)): 
            values_hat[i] = self.ZR.rand()
            rand_values_hat[i] = self.ZR.rand()

        # 这里是协议 step 2 和 3
        masked_values, masked_values_hat = [None] * len(values), [None] * len(values)
        c = [None] * len(values)
        for i in range(len(values)): 
            masked_values[i] = values[i] + rand_values[i]
            masked_values_hat[i] = values_hat[i] + rand_values_hat[i]
            c[i] = self.pc.commit_trans(rand_values[i], rand_values_hat[i])
        
        # 这里是协议 step 4
        # 我们需要先执行 rbc ，再在 acss 过程中去验证我们的 masked values 的值是否是正确的，这里我们需要一个 signal 来先让acss 协程等待 rbc 结束
        # rbc_masked_signal = asyncio.Event()
        sr = Serial(self.G1)
        serialized_masked_values = sr.serialize_fs(masked_values)
        serialized_masked_values_hat = sr.serialize_fs(masked_values_hat)
        serialized_c = sr.serialize_gs(c)
        rbc_masked_input = serialized_masked_values + serialized_masked_values_hat + serialized_c
        await asyncio.create_task(self.rbc_masked_step(bytes(rbc_masked_input)))

        # 这里是协议 step 5
        acss_outputs = {}
        acss_signal = asyncio.Event()
        # 这里 我们把要传入的参数放到一个集合中再传入 acss
        trans_values = (values, values_hat)
        test = asyncio.create_task(self.acss_step(acss_outputs, trans_values, acss_signal))
        await test
        # await self.acss_step(acss_outputs, trans_values, acss_signal)
        # self.acss_task = asyncio.create_task(self.acss_step(acss_outputs, trans_values, acss_signal))
        await acss_signal.wait()
        acss_signal.clear()
        # print("acss_outputs: ", acss_outputs)
        
        # 这里对应协议的 step 6，这里的 LT 就对应论文中的 LT
        LT = list(acss_outputs.keys())

        # 这里对应协议的 step 7， GT 对应论文中的 GT
        # de_masked_values = [[self.ZR(0) for _ in range(len(values))] for _ in range(self.n)]
        de_masked_values = [[self.ZR(0) for _ in range(self.n)] for _ in range(len(values))]
        for i in range(len(values)): 
            for j in range(self.n): 
                if j in LT: 
                    de_masked_values[i][j] = int(sr.deserialize_f(self.rbcl_list[j][32*i:32*(i+1)]))

        GFEG1 = GF(Subgroup.BLS12_381)
        point = EvalPoint(GFEG1, self.n, use_omega_powers=False)
        poly, err = [None] * len(values), [None] * len(values)
        for i in range(len(values)): 
            poly[i], err[i] = await robust_reconstruct_admpc(de_masked_values[i], LT, GFEG1, self.t, point, self.t)
            # err_list[i] = list(err[i])
            # GT[i] = [j for j in range(self.n) if j not in err_list[i]]

        err_list = [list(err[i]) for i in range(len(err))]

        # 这个就是通过鲁棒性插值找到的 2t+1 的集合
        for i in range(len(err_list)): 
            if len(err_list[i]) == 0: 
                continue
            else: 
                for j in range(len(err_list[i])): 
                    LT.pop(err_list[i][j])
        GT = LT


        # 这一步是 MVBA 的过程
        # 这里是协议的 step 7 和 8
        # 这里的话我们先只允许一个trans 一个值
        # create_acs_task = asyncio.create_task(self.agreement(GT[0], de_masked_values[0], 0, acss_outputs, acss_signal))
        # create_acs_task = asyncio.create_task(self.agreement(GT[0], de_masked_values, i, acss_outputs, acss_signal))
        # create_acs_tasks = [None] * len(values)
        # for i in range(len(values)): 
        #     create_acs_tasks[i] = asyncio.create_task(self.agreement(GT[i], de_masked_values[i], i, acss_outputs, acss_signal))
        
        create_acs_task = asyncio.create_task(self.agreement(GT, de_masked_values, acss_outputs, acss_signal))

        acs, key_task, work_tasks = await create_acs_task
        await acs
        output = await key_task
        await asyncio.gather(*work_tasks)

        # agreement_results = await asyncio.gather(*create_acs_tasks)
        # acs = [result[0] for result in agreement_results]
        # key_task = [result[1] for result in agreement_results]
        # work_tasks = [result[2] for result in agreement_results]
        
        # # acs, key_task, work_tasks = await asyncio.gather(*create_acs_tasks)
        # await asyncio.gather(*acs)
        # output = await asyncio.gather(*key_task)
        # await asyncio.gather(*work_tasks)
        new_shares = output
        
        # acs, key_task, work_tasks = await create_acs_task
        # await acs[0]
        # output = await key_task[0]
        # await asyncio.gather(*work_tasks[0])
        # new_shares = output

        # self.output_queue.put_nowait(new_shares)
        return new_shares
        
class Trans_Pre(Trans):
    def __init__(self, public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, mpc_instance):
        # 增加了一个属性：self.mpc_instance，使得Rand实例可以引用mpc_instance
        self.mpc_instance = mpc_instance

        super().__init__(public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params)
    
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

    async def acss_step(self, trans_values):
        # 此处传递的公钥应该是下一层的公钥
        admpc_control_instance = self.mpc_instance.admpc_control_instance
        layerID = self.mpc_instance.layer_ID
        pks_next_layer = admpc_control_instance.pks_all[layerID + 1]       # 下一层的公钥组

        # 这里 ADKGMsgType.ACSS 都是 acss 有可能会和接下来的 trans 协议冲突
        acsstag = TRANSMsgType.ACSS + str(layerID) + str(self.my_id)
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

        self.acss = ACSS_Pre(pks_next_layer, 
                             self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                             acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                             mpc_instance=self.mpc_instance
                         )
        self.acss_tasks = [None] * self.n
        # 在上一层中只需要创建一次avss即可        
        # self.acss_tasks[self.my_id] = asyncio.create_task(self.acss.avss(0, values=trans_values))
        self.acss_tasks[self.my_id] = asyncio.create_task(self.acss.avss_trans(0, values=trans_values))

        # # 此处传递的公钥应该是下一层的公钥
        # admpc_control_instance = self.mpc_instance.admpc_control_instance
        # layerID = self.mpc_instance.layer_ID
        # admpc_lists_next_layer = admpc_control_instance.admpc_lists[layerID + 1]
        # pks_next_layer = admpc_control_instance.pks_all[layerID + 1]       # 下一层的公钥组

        # # 这里 ADKGMsgType.ACSS 都是 acss 有可能会和接下来的 trans 协议冲突
        # acsstag = TRANSMsgType.ACSS + str(layerID) + str(self.my_id)
        # acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

        # self.acss = ACSS_Pre(pks_next_layer, 
        #                      self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
        #                      acsssend, acssrecv, self.pc, self.ZR, self.G1, 
        #                      mpc_instance=self.mpc_instance
        #                  )
        # self.acss_tasks = [None] * self.n
        # # 在上一层中只需要创建一次avss即可    
        # if self.my_id == 0: 
        #     self.acss_tasks[self.my_id] = asyncio.create_task(self.acss.avss_trans(0, values=trans_values))
        #     # self.acss_tasks[self.my_id] = asyncio.create_task(self.acss.avss(0, values=trans_values[0]))

    async def rbc_masked_step_pre(self, rbc_masked_input): 
        rbc_outputs = asyncio.Queue()

        member_list = [(self.mpc_instance.layer_ID) * self.n + self.my_id]
        for i in range(self.n): 
            member_list.append(self.n * (self.mpc_instance.layer_ID + 1) + i)
        
        async def predicate(_m):
            return True

        rbctag =TRANSMsgType.MASK + str(self.my_id) # (M, msg)
        rbcsend, rbcrecv = self.get_send(rbctag), self.subscribe_recv(rbctag)

        rbc_input = rbc_masked_input
        asyncio.create_task(
            optqrbc_dynamic(
                rbctag,
                self.my_id,
                self.n+1,
                self.t,
                self.my_id,
                predicate,
                rbc_input,
                rbc_outputs.put_nowait,
                rbcsend,
                rbcrecv,
                member_list
            )
        )
    
    async def run_trans(self, values, rand_values):     
        # 改变一下策略，让每个参与方一次性 acss rounds 个随机数
        # rounds = 1
        # self.rand_num = rounds
        # values = [self.ZR.rand() for _ in range(rounds)]
        # self.acss_task = asyncio.create_task(self.acss_step(values))

        # 这里模拟的是 step 1
        rand_values_hat = [None] * len(values)
        values_hat = [None] * len(values)
        for i in range(len(values)): 
            values_hat[i] = self.ZR.rand()
            rand_values_hat[i] = self.ZR.rand()

        # 这里是协议 step 2 和 3
        masked_values, masked_values_hat = [None] * len(values), [None] * len(values)
        c = [None] * len(values)
        for i in range(len(values)): 
            masked_values[i] = values[i] + rand_values[i]
            masked_values_hat[i] = values_hat[i] + rand_values_hat[i]
            c[i] = self.pc.commit_trans(rand_values[i], rand_values_hat[i])
        
        # 这里是协议 step 4
        # 我们需要先执行 rbc ，再在 acss 过程中去验证我们的 masked values 的值是否是正确的，这里我们需要一个 signal 来先让acss 协程等待 rbc 结束
        # rbc_masked_signal = asyncio.Event()
        sr = Serial(self.G1)
        serialized_masked_values = sr.serialize_fs(masked_values)
        serialized_masked_values_hat = sr.serialize_fs(masked_values_hat)
        serialized_c = sr.serialize_gs(c)
        rbc_masked_input = serialized_masked_values + serialized_masked_values_hat + serialized_c
        rbc_masked_task = asyncio.create_task(self.rbc_masked_step_pre(bytes(rbc_masked_input)))

        # 这里是协议 step 5
        # 这里 我们把要传入的参数放到一个集合中再传入 acss
        trans_values = (values, values_hat)
        self.acss_task = asyncio.create_task(self.acss_step(trans_values))


class Trans_Foll(Trans):        
    def __init__(self, public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, mpc_instance):
        # 增加了一个属性：self.mpc_instance，使得Rand实例可以引用mpc_instance
        self.mpc_instance = mpc_instance

        super().__init__(public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params)
    
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

    async def acss_step(self, len_values):
        rounds = 1
        self.acss_tasks = [None] * self.n
        for dealer_id in range(self.n): 
            # 这里 ADKGMsgType.ACSS 都是 acss 有可能会和接下来的 trans 协议冲突
            acsstag = TRANSMsgType.ACSS + str(self.mpc_instance.layer_ID - 1) + str(dealer_id)
            acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

            # 此时传递的是本层的公私钥
            self.acss = ACSS_Foll(self.public_keys, self.private_key, 
                                self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                                acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                                mpc_instance=self.mpc_instance, rbc_values=self.rbcl_list
                            )
            # self.acss_tasks[dealer_id] = asyncio.create_task(self.acss.avss(0, dealer_id, rounds))
            self.acss_tasks[dealer_id] = asyncio.create_task(self.acss.avss_trans(0, dealer_id, len_values))


            # 对于每一个dealer ID，下一层都要创一个来接受这个dealer ID分发的ACSS实例

        results = await asyncio.gather(*self.acss_tasks)
        dealer, _, shares, commitments = zip(*results)
        
        outputs = {}
        for i in range(len(dealer)): 
            outputs[i] = {'shares':shares[i], 'commits':commitments[i]}
        return outputs
    
        # self.acss_tasks = [None] * self.n
        # for dealer_id in range(1): 
        #     # 这里 ADKGMsgType.ACSS 都是 acss 有可能会和接下来的 trans 协议冲突
        #     acsstag = TRANSMsgType.ACSS + str(self.mpc_instance.layer_ID - 1) + str(dealer_id)
        #     acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

        #     # 此时传递的是本层的公私钥
        #     self.acss = ACSS_Foll(self.public_keys, self.private_key, 
        #                         self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
        #                         acsssend, acssrecv, self.pc, self.ZR, self.G1, 
        #                         mpc_instance=self.mpc_instance
        #                         # rbc_values=self.rbcl_list
        #                     )
        #     self.acss_tasks[dealer_id] = asyncio.create_task(self.acss.avss_trans(0, dealer_id, len_values))
        #     # acss_tasks[dealer_id] = asyncio.create_task(self.acss.avss(0, dealer_id, len_values))


        #     # 对于每一个dealer ID，下一层都要创一个来接受这个dealer ID分发的ACSS实例

        # results = await asyncio.gather(*self.acss_tasks)
        # dealer, _, shares, commitments = zip(*results)
        
        # outputs = {}
        # for i in range(len(dealer)): 
        #     outputs[i] = {'shares':shares[i], 'commits':commitments[i]}
        # return outputs

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
    
    async def agreement(self, key_proposal, de_masked_value, acss_outputs, acss_signal):
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
            # print(f"kpl: {kpl}")
            # print(f"de_masked_value: {de_masked_value}")
            if len(kpl) <= self.t:
                return False
            
            GFEG1 = GF(Subgroup.BLS12_381)
            point = EvalPoint(GFEG1, self.n, use_omega_powers=False)
            poly, err = [None] * len(de_masked_value), [None] * len(de_masked_value)
            for i in range(len(de_masked_value)): 
                poly[i], err[i] = await robust_reconstruct_admpc(de_masked_value[i], key_proposal, GFEG1, self.t, point, self.t)
            err_list = [list(err[i]) for i in range(len(err))]
            for i in range(len(err_list)): 
                if len(err_list[i]) != 0: 
                    return False         
        
            return True

        async def _setup(j):
            
            # starting RBC
            rbctag = TRANSMsgType.RBC + str(j) # (R, msg)
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
                    self.member_list
                )
            )

            abatag = TRANSMsgType.ABA + str(j) # (B, msg)
            # abatag = TRANSMsgType.ABA + str(j)
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
                rbc_signal,
                rbc_values,
                [_.put_nowait for _ in coin_keys],
                [_.put_nowait for _ in aba_inputs],
                [_.get for _ in aba_outputs],
            ),
            self.new_share(
                rbc_values,
                rbc_signal,
                acss_outputs,
                acss_signal, 
            ),
            work_tasks,
        )

    async def new_share(self, rbc_values, rbc_signal, acss_outputs, acss_signal):
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
        mks_list = list(self.mks)
        secrets_num = len(acss_outputs[mks_list[0]]['shares']['msg'])
        secrets = [[self.ZR(0) for _ in range(self.n)] for _ in range(secrets_num)]
        # secrets = [self.ZR(0)] * self.n 

        for i in range(secrets_num): 
            for node in range(self.n): 
                if node in self.mks: 
                    secrets[i][node] = acss_outputs[node]['shares']['msg'][i]
        
        # for node in range(self.n):
        #     if node in self.mks:
        #         secrets[node] = acss_outputs[node]['shares']['msg'][index]
        #         print(f"secret[{node}] = {secrets[node]}")
                    

        sc_shares = []
        for i in range(secrets_num): 
            sc_shares.append([])
            for j in self.mks:
                sc_shares[i].append([j+1, secrets[i][j]])

        # print(f"my id: {self.my_id} sc_shares: {sc_shares}")

        # 这里测试的就是在得到公共子集之后重构新的 shares 
        res = []
        for i in range(secrets_num):
            res.append(self.poly.interpolate_at(sc_shares[i], 0))
        # res = self.poly.interpolate_at(sc_shares, 0)
        # print(f"my id: {self.my_id} res: {res}")

        return res

    # async def masked_values(): 

    
    async def rbc_masked_step_foll(self): 
        rbc_tasks = [None] * self.n
        rbc_outputs = [asyncio.Queue() for _ in range(self.n)]

        async def predicate(_m):
            return True

        for dealer_id in range(self.n): 
            # 注意！dealer_id 这里要改一下
            # dealer_id = (self.mpc_instance.layer_ID - 1) * self.n + i

            rbctag =TRANSMsgType.MASK + str(dealer_id) # (M, msg)
            rbcsend, rbcrecv = self.get_send(rbctag), self.subscribe_recv(rbctag)
            rbc_input = None

            member_list = [(self.mpc_instance.layer_ID - 1) * self.n + dealer_id]
            for j in range(self.n): 
                member_list.append(self.n * (self.mpc_instance.layer_ID) + j)

            if self.my_id < dealer_id: 
                rbc_tasks[dealer_id] = asyncio.create_task(
                optqrbc_dynamic(
                    rbctag,
                    self.my_id,
                    self.n+1,
                    self.t,
                    dealer_id,
                    predicate,
                    rbc_input,
                    rbc_outputs[dealer_id].put_nowait,
                    rbcsend,
                    rbcrecv,
                    member_list
                ))
            else: 
                rbc_tasks[dealer_id] = asyncio.create_task(
                optqrbc_dynamic(
                    rbctag,
                    self.my_id+1,
                    self.n+1,
                    self.t,
                    dealer_id,
                    predicate,
                    rbc_input,
                    rbc_outputs[dealer_id].put_nowait,
                    rbcsend,
                    rbcrecv,
                    member_list
                ))

        # await asyncio.gather(*[rbc_tasks(j) for j in range(self.n)])
        await asyncio.gather(*rbc_tasks)

        # 这里存的是序列化的各方广播的 masked values and commitments
        trans_await_rbcl_list = time.time()
        self.rbcl_list = await asyncio.gather(*(rbc_outputs[j].get() for j in range(self.n)))
        trans_await_rbcl_list = time.time() - trans_await_rbcl_list
        print(f"trans_await_rbcl_list: {trans_await_rbcl_list}")
    
    async def run_trans(self, len_values):
        self.member_list = []
        for i in range(self.n): 
            self.member_list.append(self.n * (self.mpc_instance.layer_ID) + i)

        # 这里是协议 step 4
        # 我们需要先执行 rbc ，再在 acss 过程中去验证我们的 masked values 的值是否是正确的，这里我们需要一个 signal 来先让acss 协程等待 rbc 结束
        trans_rbc_time = time.time()
        rbc_tasks = [None] * self.n
        rbc_outputs = [asyncio.Queue() for _ in range(self.n)]

        async def predicate(_m):
            return True

        async def _setup(dealer_id):
            # 注意！dealer_id 这里要改一下
            # dealer_id = (self.mpc_instance.layer_ID - 1) * self.n + i

            rbctag =TRANSMsgType.MASK + str(dealer_id) # (M, msg)
            rbcsend, rbcrecv = self.get_send(rbctag), self.subscribe_recv(rbctag)
            rbc_input = None

            member_list = [(self.mpc_instance.layer_ID - 1) * self.n + dealer_id]
            for j in range(self.n): 
                member_list.append(self.n * (self.mpc_instance.layer_ID) + j)

            if self.my_id < dealer_id: 
                rbc_tasks[dealer_id] = asyncio.create_task(
                optqrbc_dynamic(
                    rbctag,
                    self.my_id,
                    self.n+1,
                    self.t,
                    dealer_id,
                    predicate,
                    rbc_input,
                    rbc_outputs[dealer_id].put_nowait,
                    rbcsend,
                    rbcrecv,
                    member_list
                ))
            else: 
                rbc_tasks[dealer_id] = asyncio.create_task(
                optqrbc_dynamic(
                    rbctag,
                    self.my_id+1,
                    self.n+1,
                    self.t,
                    dealer_id,
                    predicate,
                    rbc_input,
                    rbc_outputs[dealer_id].put_nowait,
                    rbcsend,
                    rbcrecv,
                    member_list
                ))

        # await asyncio.gather(*[rbc_tasks(j) for j in range(self.n)])
        trans_await_gather_rbc_time = time.time()
        await asyncio.gather(*[_setup(dealer_id) for dealer_id in range(self.n)])
        # await asyncio.gather(*rbc_tasks)
        trans_await_gather_rbc_time = time.time() - trans_await_gather_rbc_time
        print(f"trans_await_gather_rbc_time: {trans_await_gather_rbc_time}")

        # 这里存的是序列化的各方广播的 masked values and commitments
        trans_await_rbcl_list = time.time()
        self.rbcl_list = await asyncio.gather(*(rbc_outputs[j].get() for j in range(self.n)))
        trans_await_rbcl_list = time.time() - trans_await_rbcl_list
        print(f"trans_await_rbcl_list: {trans_await_rbcl_list}")
        trans_rbc_time = time.time() - trans_rbc_time
        print(f"trans_rbc_time: {trans_rbc_time}")
        
        # # 这里是协议 step 4
        # # 我们需要先执行 rbc ，再在 acss 过程中去验证我们的 masked values 的值是否是正确的，这里我们需要一个 signal 来先让acss 协程等待 rbc 结束
        # trans_rbc_time = time.time()
        # await asyncio.create_task(self.rbc_masked_step_foll())
        # trans_rbc_time = time.time() - trans_rbc_time
        # print(f"trans_rbc_time: {trans_rbc_time}")

        # 这里是协议 step 5
        # 这里我们直接让 acss return 了，并没有用到他们设计的 异步队列 的 get，后续可能要修改
        trans_acss_time = time.time()
        acss_signal = asyncio.Event()
        self.acss_task = asyncio.create_task(self.acss_step(len_values))
        acss_outputs = await self.acss_task
        trans_acss_time = time.time() - trans_acss_time
        print(f"trans_acss_time: {trans_acss_time}")
        
        # # 这里对应协议的 step 6，这里的 LT 就对应论文中的 LT
        LT = list(acss_outputs.keys())

        # 这里对应协议的 step 7， GT 对应论文中的 GT
        # de_masked_values = [[self.ZR(0) for _ in range(len(values))] for _ in range(self.n)]
        sr = Serial(self.G1)
        de_masked_values = [[self.ZR(0) for _ in range(self.n)] for _ in range(len_values)]
        for i in range(len_values): 
            for j in range(self.n): 
                if j in LT: 
                    de_masked_values[i][j] = int(sr.deserialize_f(self.rbcl_list[j][32*i:32*(i+1)]))

        GFEG1 = GF(Subgroup.BLS12_381)
        point = EvalPoint(GFEG1, self.n, use_omega_powers=False)
        poly, err = [None] * len_values, [None] * len_values
        for i in range(len_values): 
            poly[i], err[i] = await robust_reconstruct_admpc(de_masked_values[i], LT, GFEG1, self.t, point, self.t)
            # err_list[i] = list(err[i])
            # GT[i] = [j for j in range(self.n) if j not in err_list[i]]

        err_list = [list(err[i]) for i in range(len(err))]

        # 这个就是通过鲁棒性插值找到的 2t+1 的集合
        for i in range(len(err_list)): 
            if len(err_list[i]) == 0: 
                continue
            else: 
                for j in range(len(err_list[i])): 
                    LT.pop(err_list[i][j])
        GT = LT


        # 这一步是 MVBA 的过程
        # 这里是协议的 step 7 和 8
        trans_mvba_time = time.time()
        create_acs_task = asyncio.create_task(self.agreement(GT, de_masked_values, acss_outputs, acss_signal))

        acs, key_task, work_tasks = await create_acs_task
        await acs
        output = await key_task
        await asyncio.gather(*work_tasks)
        new_shares = output
        trans_mvba_time = time.time() - trans_mvba_time
        print(f"trans_mvba_time: {trans_mvba_time}")

        return new_shares



class Trans_Fluid_Pre(Trans):
    def __init__(self, public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, mpc_instance):
        # 增加了一个属性：self.mpc_instance，使得Rand实例可以引用mpc_instance
        self.mpc_instance = mpc_instance

        super().__init__(public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params)
    
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

    async def acss_step(self, trans_values):
        # 此处传递的公钥应该是下一层的公钥
        admpc_control_instance = self.mpc_instance.admpc_control_instance
        layerID = self.mpc_instance.layer_ID
        pks_next_layer = admpc_control_instance.pks_all[layerID + 1]       # 下一层的公钥组

        # 这里 ADKGMsgType.ACSS 都是 acss 有可能会和接下来的 trans 协议冲突
        acsstag = TRANSMsgType.ACSS + str(layerID) + str(self.my_id)
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

        self.acss = ACSS_Fluid_Pre(pks_next_layer, 
                             self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                             acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                             mpc_instance=self.mpc_instance
                         )
        self.acss_tasks = [None] * self.n
        # 在上一层中只需要创建一次avss即可        
        # self.acss_tasks[self.my_id] = asyncio.create_task(self.acss.avss(0, values=trans_values))
        self.acss_tasks[self.my_id] = asyncio.create_task(self.acss.avss_trans(0, values=trans_values))

        # # 此处传递的公钥应该是下一层的公钥
        # admpc_control_instance = self.mpc_instance.admpc_control_instance
        # layerID = self.mpc_instance.layer_ID
        # admpc_lists_next_layer = admpc_control_instance.admpc_lists[layerID + 1]
        # pks_next_layer = admpc_control_instance.pks_all[layerID + 1]       # 下一层的公钥组

        # # 这里 ADKGMsgType.ACSS 都是 acss 有可能会和接下来的 trans 协议冲突
        # acsstag = TRANSMsgType.ACSS + str(layerID) + str(self.my_id)
        # acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

        # self.acss = ACSS_Pre(pks_next_layer, 
        #                      self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
        #                      acsssend, acssrecv, self.pc, self.ZR, self.G1, 
        #                      mpc_instance=self.mpc_instance
        #                  )
        # self.acss_tasks = [None] * self.n
        # # 在上一层中只需要创建一次avss即可    
        # if self.my_id == 0: 
        #     self.acss_tasks[self.my_id] = asyncio.create_task(self.acss.avss_trans(0, values=trans_values))
        #     # self.acss_tasks[self.my_id] = asyncio.create_task(self.acss.avss(0, values=trans_values[0]))

    async def rbc_masked_step_pre(self, rbc_masked_input): 
        rbc_outputs = asyncio.Queue()

        member_list = [(self.mpc_instance.layer_ID) * self.n + self.my_id]
        for i in range(self.n): 
            member_list.append(self.n * (self.mpc_instance.layer_ID + 1) + i)
        
        print(f"before predicate")
        async def predicate(_m):
            return True

        rbctag =TRANSMsgType.MASK + str(self.my_id) # (M, msg)
        rbcsend, rbcrecv = self.get_send(rbctag), self.subscribe_recv(rbctag)

        rbc_input = rbc_masked_input
        print(f"before rbc_dynamic")
        asyncio.create_task(
            optqrbc_dynamic(
                rbctag,
                self.my_id,
                self.n+1,
                self.t,
                self.my_id,
                predicate,
                rbc_input,
                rbc_outputs.put_nowait,
                rbcsend,
                rbcrecv,
                member_list
            )
        )
    
    async def run_trans(self, values):     

        
        # 这里是协议 step 4
        # 我们需要先执行 rbc ，再在 acss 过程中去验证我们的 masked values 的值是否是正确的，这里我们需要一个 signal 来先让acss 协程等待 rbc 结束
        # rbc_masked_signal = asyncio.Event()
        sr = Serial(self.G1)
        serialized_values = sr.serialize_fs(values)
        print(f"befor rbc pre")
        rbc_masked_task = asyncio.create_task(self.rbc_masked_step_pre(bytes(serialized_values)))

        

class Trans_Fluid_Foll(Trans):        
    def __init__(self, public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, mpc_instance):
        # 增加了一个属性：self.mpc_instance，使得Rand实例可以引用mpc_instance
        self.mpc_instance = mpc_instance

        super().__init__(public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params)
    
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

    async def acss_step(self, len_values):
        rounds = 1
        self.acss_tasks = [None] * self.n
        for dealer_id in range(self.n): 
            # 这里 ADKGMsgType.ACSS 都是 acss 有可能会和接下来的 trans 协议冲突
            acsstag = TRANSMsgType.ACSS + str(self.mpc_instance.layer_ID - 1) + str(dealer_id)
            acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

            # 此时传递的是本层的公私钥
            self.acss = ACSS_Foll(self.public_keys, self.private_key, 
                                self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                                acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                                mpc_instance=self.mpc_instance, rbc_values=self.rbcl_list
                            )
            # self.acss_tasks[dealer_id] = asyncio.create_task(self.acss.avss(0, dealer_id, rounds))
            self.acss_tasks[dealer_id] = asyncio.create_task(self.acss.avss_trans(0, dealer_id, len_values))


            # 对于每一个dealer ID，下一层都要创一个来接受这个dealer ID分发的ACSS实例

        results = await asyncio.gather(*self.acss_tasks)
        dealer, _, shares, commitments = zip(*results)
        
        outputs = {}
        for i in range(len(dealer)): 
            outputs[i] = {'shares':shares[i], 'commits':commitments[i]}
        return outputs
    
        # self.acss_tasks = [None] * self.n
        # for dealer_id in range(1): 
        #     # 这里 ADKGMsgType.ACSS 都是 acss 有可能会和接下来的 trans 协议冲突
        #     acsstag = TRANSMsgType.ACSS + str(self.mpc_instance.layer_ID - 1) + str(dealer_id)
        #     acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

        #     # 此时传递的是本层的公私钥
        #     self.acss = ACSS_Foll(self.public_keys, self.private_key, 
        #                         self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
        #                         acsssend, acssrecv, self.pc, self.ZR, self.G1, 
        #                         mpc_instance=self.mpc_instance
        #                         # rbc_values=self.rbcl_list
        #                     )
        #     self.acss_tasks[dealer_id] = asyncio.create_task(self.acss.avss_trans(0, dealer_id, len_values))
        #     # acss_tasks[dealer_id] = asyncio.create_task(self.acss.avss(0, dealer_id, len_values))


        #     # 对于每一个dealer ID，下一层都要创一个来接受这个dealer ID分发的ACSS实例

        # results = await asyncio.gather(*self.acss_tasks)
        # dealer, _, shares, commitments = zip(*results)
        
        # outputs = {}
        # for i in range(len(dealer)): 
        #     outputs[i] = {'shares':shares[i], 'commits':commitments[i]}
        # return outputs

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
    
    async def agreement(self, key_proposal, de_masked_value, acss_outputs, acss_signal):
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
            # print(f"kpl: {kpl}")
            # print(f"de_masked_value: {de_masked_value}")
            if len(kpl) <= self.t:
                return False
            
            GFEG1 = GF(Subgroup.BLS12_381)
            point = EvalPoint(GFEG1, self.n, use_omega_powers=False)
            poly, err = [None] * len(de_masked_value), [None] * len(de_masked_value)
            for i in range(len(de_masked_value)): 
                poly[i], err[i] = await robust_reconstruct_admpc(de_masked_value[i], key_proposal, GFEG1, self.t, point, self.t)
            err_list = [list(err[i]) for i in range(len(err))]
            for i in range(len(err_list)): 
                if len(err_list[i]) != 0: 
                    return False         
        
            return True

        async def _setup(j):
            
            # starting RBC
            rbctag = TRANSMsgType.RBC + str(j) # (R, msg)
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
                    self.member_list
                )
            )

            abatag = TRANSMsgType.ABA + str(j) # (B, msg)
            # abatag = TRANSMsgType.ABA + str(j)
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
                rbc_signal,
                rbc_values,
                [_.put_nowait for _ in coin_keys],
                [_.put_nowait for _ in aba_inputs],
                [_.get for _ in aba_outputs],
            ),
            self.new_share(
                rbc_values,
                rbc_signal,
                acss_outputs,
                acss_signal, 
            ),
            work_tasks,
        )

    async def new_share(self, rbc_values, rbc_signal, acss_outputs, acss_signal):
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
        mks_list = list(self.mks)
        secrets_num = len(acss_outputs[mks_list[0]]['shares']['msg'])
        secrets = [[self.ZR(0) for _ in range(self.n)] for _ in range(secrets_num)]
        # secrets = [self.ZR(0)] * self.n 

        for i in range(secrets_num): 
            for node in range(self.n): 
                if node in self.mks: 
                    secrets[i][node] = acss_outputs[node]['shares']['msg'][i]
        
        # for node in range(self.n):
        #     if node in self.mks:
        #         secrets[node] = acss_outputs[node]['shares']['msg'][index]
        #         print(f"secret[{node}] = {secrets[node]}")
                    

        sc_shares = []
        for i in range(secrets_num): 
            sc_shares.append([])
            for j in self.mks:
                sc_shares[i].append([j+1, secrets[i][j]])

        # print(f"my id: {self.my_id} sc_shares: {sc_shares}")

        # 这里测试的就是在得到公共子集之后重构新的 shares 
        res = []
        for i in range(secrets_num):
            res.append(self.poly.interpolate_at(sc_shares[i], 0))
        # res = self.poly.interpolate_at(sc_shares, 0)
        # print(f"my id: {self.my_id} res: {res}")

        return res

    # async def masked_values(): 

    
    async def rbc_masked_step_foll(self): 
        rbc_tasks = [None] * self.n
        rbc_outputs = [asyncio.Queue() for _ in range(self.n)]

        async def predicate(_m):
            return True

        for dealer_id in range(self.n): 
            # 注意！dealer_id 这里要改一下
            # dealer_id = (self.mpc_instance.layer_ID - 1) * self.n + i

            rbctag =TRANSMsgType.MASK + str(dealer_id) # (M, msg)
            rbcsend, rbcrecv = self.get_send(rbctag), self.subscribe_recv(rbctag)
            rbc_input = None

            member_list = [(self.mpc_instance.layer_ID - 1) * self.n + dealer_id]
            for j in range(self.n): 
                member_list.append(self.n * (self.mpc_instance.layer_ID) + j)

            if self.my_id < dealer_id: 
                rbc_tasks[dealer_id] = asyncio.create_task(
                optqrbc_dynamic(
                    rbctag,
                    self.my_id,
                    self.n+1,
                    self.t,
                    dealer_id,
                    predicate,
                    rbc_input,
                    rbc_outputs[dealer_id].put_nowait,
                    rbcsend,
                    rbcrecv,
                    member_list
                ))
            else: 
                rbc_tasks[dealer_id] = asyncio.create_task(
                optqrbc_dynamic(
                    rbctag,
                    self.my_id+1,
                    self.n+1,
                    self.t,
                    dealer_id,
                    predicate,
                    rbc_input,
                    rbc_outputs[dealer_id].put_nowait,
                    rbcsend,
                    rbcrecv,
                    member_list
                ))

        # await asyncio.gather(*[rbc_tasks(j) for j in range(self.n)])
        await asyncio.gather(*rbc_tasks)

        # 这里存的是序列化的各方广播的 masked values and commitments
        trans_await_rbcl_list = time.time()
        self.rbcl_list = await asyncio.gather(*(rbc_outputs[j].get() for j in range(self.n)))
        trans_await_rbcl_list = time.time() - trans_await_rbcl_list
        print(f"trans_await_rbcl_list: {trans_await_rbcl_list}")
    
    async def run_trans(self, len_values):
        self.member_list = []
        for i in range(self.n): 
            self.member_list.append(self.n * (self.mpc_instance.layer_ID) + i)

        # 这里是协议 step 4
        # 我们需要先执行 rbc ，再在 acss 过程中去验证我们的 masked values 的值是否是正确的，这里我们需要一个 signal 来先让acss 协程等待 rbc 结束
        trans_rbc_time = time.time()
        rbc_tasks = [None] * self.n
        rbc_outputs = [asyncio.Queue() for _ in range(self.n)]

        async def predicate(_m):
            return True

        print(f"before setup")
        async def _setup(dealer_id):
            # 注意！dealer_id 这里要改一下
            # dealer_id = (self.mpc_instance.layer_ID - 1) * self.n + i

            rbctag =TRANSMsgType.MASK + str(dealer_id) # (M, msg)
            rbcsend, rbcrecv = self.get_send(rbctag), self.subscribe_recv(rbctag)
            rbc_input = None

            member_list = [(self.mpc_instance.layer_ID - 1) * self.n + dealer_id]
            for j in range(self.n): 
                member_list.append(self.n * (self.mpc_instance.layer_ID) + j)

            if self.my_id < dealer_id: 
                rbc_tasks[dealer_id] = asyncio.create_task(
                optqrbc_dynamic(
                    rbctag,
                    self.my_id,
                    self.n+1,
                    self.t,
                    dealer_id,
                    predicate,
                    rbc_input,
                    rbc_outputs[dealer_id].put_nowait,
                    rbcsend,
                    rbcrecv,
                    member_list
                ))
            else: 
                rbc_tasks[dealer_id] = asyncio.create_task(
                optqrbc_dynamic(
                    rbctag,
                    self.my_id+1,
                    self.n+1,
                    self.t,
                    dealer_id,
                    predicate,
                    rbc_input,
                    rbc_outputs[dealer_id].put_nowait,
                    rbcsend,
                    rbcrecv,
                    member_list
                ))

        # await asyncio.gather(*[rbc_tasks(j) for j in range(self.n)])
        trans_await_gather_rbc_time = time.time()
        await asyncio.gather(*[_setup(dealer_id) for dealer_id in range(self.n)])
        # await asyncio.gather(*rbc_tasks)
        trans_await_gather_rbc_time = time.time() - trans_await_gather_rbc_time
        print(f"trans_await_gather_rbc_time: {trans_await_gather_rbc_time}")

        # 这里存的是序列化的各方广播的 masked values and commitments
        trans_await_rbcl_list = time.time()
        self.rbcl_list = await asyncio.gather(*(rbc_outputs[j].get() for j in range(self.n)))
        trans_await_rbcl_list = time.time() - trans_await_rbcl_list
        print(f"trans_await_rbcl_list: {trans_await_rbcl_list}")
        trans_rbc_time = time.time() - trans_rbc_time
        print(f"trans_rbc_time: {trans_rbc_time}")
        

        # 这里对应协议的 step 7， GT 对应论文中的 GT
        # de_masked_values = [[self.ZR(0) for _ in range(len(values))] for _ in range(self.n)]
        sr = Serial(self.G1)
        de_masked_values = [[self.ZR(0) for _ in range(self.n)] for _ in range(len_values)]
        for i in range(len_values): 
            for j in range(self.n): 
                de_masked_values[i][j] = int(sr.deserialize_f(self.rbcl_list[j][32*i:32*(i+1)]))

        

        return de_masked_values

  