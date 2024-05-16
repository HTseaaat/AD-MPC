from adkg.polynomial import polynomials_over, EvalPoint
from adkg.utils.poly_misc import interpolate_g1_at_x
from adkg.utils.misc import wrap_send, subscribe_recv
import asyncio
import hashlib, time
from math import ceil
import logging
from adkg.utils.bitmap import Bitmap
from adkg.acss import ACSS, ACSS_Foll, ACSS_Pre
from adkg.router import SimpleRouter

from adkg.broadcast.tylerba import tylerba
from adkg.broadcast.optqrbc import optqrbc

from adkg.preprocessing import PreProcessedElements

from adkg.mpc import TaskProgramRunner
from adkg.robust_rec import robust_reconstruct_admpc, Robust_Rec
from adkg.trans import Trans, Trans_Pre, Trans_Foll
from adkg.rand import Rand, Rand_Pre, Rand_Foll
from adkg.aprep import APREP, APREP_Pre, APREP_Foll
import math

from adkg.utils.serilization import Serial
from adkg.field import GF, GFElement
from adkg.ntl import vandermonde_batch_evaluate
from adkg.elliptic_curve import Subgroup
from adkg.progs.mixins.dataflow import Share
from adkg.robust_reconstruction import robust_reconstruct_admpc, robust_rec_admpc

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
    def __init__(self, public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, matrices, total_cm, layers):
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
        self.total_cm = total_cm
        self.layers = layers

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
        rec_values = await self.rec.batch_robust_rec(index, rec_shares)

        # # rec_signal.set()
        return rec_values
    
    async def rec_step(self, rec_shares, index):                
        
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
        
   
    
    async def mult(self, mult_values, mult_triples, layer): 
        print(f"enter mult")
        gamma_list, epsilon_list = [None] * len(mult_values), [None] * len(mult_values)

        # # 这里模拟的是敌手在每一层都注入错误对开销的影响
        # print(f"ok")
        # batch_rec_list = []
        # # 这里我们假设节点 0,1,2,3,4 是拜占庭节点，然后他们给的输入都是 0 
        # # 在这里我们测试拜占庭节点数目的多少对性能开销的影响
        # byzantine_nodes = [0]
        # for i in range(len(mult_values)): 
        #     if self.my_id in byzantine_nodes: 
        #         gamma_list[i] = self.ZR(0)
        #         epsilon_list[i] = self.ZR(0)
        #         batch_rec_list.append(gamma_list[i])
        #         batch_rec_list.append(epsilon_list[i])
        #     else: 
        #         gamma_list[i] = mult_values[i][0] - mult_triples[layer*self.cm+i][0]
        #         epsilon_list[i] = mult_values[i][1] - mult_triples[layer*self.cm+i][1]
        #         batch_rec_list.append(gamma_list[i])
        #         batch_rec_list.append(epsilon_list[i])
        # # gamma = mult_values[0] - mult_triples[0]
        # # epsilon = mult_values[1] - mult_triples[1]

        # # batch_rec_list = []
        # # batch_rec_list.append(gamma_list)
        # # batch_rec_list.append(epsilon_list)

        # # robust_rec_signal = asyncio.Event()
        # sttime = time.time()
        # # rec_gamma = await self.robust_rec_step(gamma, 0)
        
        # # await robust_rec_signal.wait()
        # # robust_rec_signal.clear()
        # # rec_epsilon = await self.robust_rec_step(epsilon, 1)
        # # await robust_rec_signal.wait()
        # # robust_rec_signal.clear()

        # # rec_values = await self.robust_rec_step(batch_rec_list, 0)
        # rec_task = asyncio.create_task(self.rec_step(batch_rec_list, layer))
        # (mks, rec_values) = await rec_task
        # print(f"mult rec_values: {len(rec_values)}")
        # num = 0
        # rec_gamma_list, rec_epsilon_list = [], []
        # for i in range(len(mult_values)):
        #     rec_gamma_list.append(rec_values[num])
        #     rec_epsilon_list.append(rec_values[num+1])
        #     num += 2
        # mult_outputs = [None] * len(mult_values)
        # for i in range(len(mult_values)):
        #     mult_outputs[i] = mult_triples[i][2] + rec_gamma_list[i] * mult_triples[i][1] + rec_epsilon_list[i] * mult_triples[i][0] + rec_gamma_list[i] * rec_epsilon_list[i]

        # # rec_gamma, rec_epsilon = await asyncio.gather(self.robust_rec_step(gamma, 0), self.robust_rec_step(epsilon, 1))  
        # print(f"sttime: {time.time()-sttime}")
        
<<<<<<< HEAD
        # 这里我模拟的是 layer = 3 时敌手注入攻击的情况
=======
        # 这里我模拟的是 layer = 1 时敌手注入攻击的情况
>>>>>>> 628abe2187076ba4c91a6a60f30249128b984ff8
        if layer == 3: 
            print(f"ok")
            batch_rec_list = []
            # 这里我们假设节点 0,1,2,3,4 是拜占庭节点，然后他们给的输入都是 0 
            # 在这里我们测试拜占庭节点数目的多少对性能开销的影响
            byzantine_nodes = []
            for i in range(len(mult_values)): 
                if self.my_id in byzantine_nodes: 
                    gamma_list[i] = self.ZR(0)
                    epsilon_list[i] = self.ZR(0)
                    batch_rec_list.append(gamma_list[i])
                    batch_rec_list.append(epsilon_list[i])
                else: 
                    gamma_list[i] = mult_values[i][0] - mult_triples[layer*self.cm+i][0]
                    epsilon_list[i] = mult_values[i][1] - mult_triples[layer*self.cm+i][1]
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

            # rec_values = await self.robust_rec_step(batch_rec_list, 0)
            rec_task = asyncio.create_task(self.rec_step(batch_rec_list, layer))
            (mks, rec_values) = await rec_task
            print(f"mult rec_values: {len(rec_values)}")
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
        else: 
            batch_rec_list = []
            for i in range(len(mult_values)): 
                gamma_list[i] = mult_values[i][0] - mult_triples[layer*self.cm+i][0]
                epsilon_list[i] = mult_values[i][1] - mult_triples[layer*self.cm+i][1]
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

            # rec_values = await self.robust_rec_step(batch_rec_list, 0)
            rec_task = asyncio.create_task(self.rec_step(batch_rec_list, layer))
            (mks, rec_values) = await rec_task
            print(f"mult rec_values: {len(rec_values)}")
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

    
    async def run_computation(self, inputs, gate_tape, mult_triples, layer):
        print(f"len inputs: {len(inputs)} len gate_tape: {len(gate_tape)} len mult: {len(mult_triples)}")

        # before_mult_time = time.time()
        
        self.gates_num = len(gate_tape)
        # 这里根据当前层门的数量对输入进行划分
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
        # before_mult_time = time.time() - before_mult_time
        # print(f"before_mult_time: {before_mult_time}")
        batch_mult_outputs = await self.mult(batch_mult_gates, mult_triples, layer)
        for i in range(len(mult_pos)): 
            gate_output_values[mult_pos[i]] = batch_mult_outputs[i]

        # self.output_queue.put_nowait(gate_output_values)
        return gate_output_values
    
   
    async def run_admpc(self, start_time):

         # honeybadgermpc 第一步需要调用 aprep 协议生成电路需要的三元组
        layers = self.layers - 2
<<<<<<< HEAD
        # 这里电路有多少层需要手动改
        layers = 10
=======
        layers = 6
>>>>>>> 628abe2187076ba4c91a6a60f30249128b984ff8
        # layers = 9
        self.cm = int(self.total_cm / layers)
        cm = self.cm
        # 这里的话 电路宽度要等于 2 * cm
        w = 2 * cm
        print(f"cm: {cm} layers: {layers}")


        # 这里测试的是当有节点下线后的测试
        if self.my_id != 9:
            step3_start_time = time.time()
            apreptag = ADMPCMsgType.APREP
            aprepsend, apreprecv = self.get_send(apreptag), self.subscribe_recv(apreptag)
            aprep = APREP(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.my_id, aprepsend, apreprecv, self.pc, self.curve_params, self.matrix)
            new_mult_triples = await aprep.run_aprep(self.total_cm)
            step3_time = time.time() - step3_start_time
            # print(f"step 3 output: {new_mult_triples}")
            # print(f"len new_mult_triples: {len(new_mult_triples)}")
            print(f"step3_time: {step3_time}")

            # honeybadgermpc 第二步需要调用 acss 协议广播自己的输入
            # 这里的话 输入的数据要是 2 * w
            intput_num = 2 * w

            if intput_num > self.n - self.t: 
                rounds = math.ceil(intput_num / (self.n - self.t))
            else: 
                rounds = 1

            step2_start_time = time.time()
            randtag = ADMPCMsgType.GENRAND
            randsend, randrecv = self.get_send(randtag), self.subscribe_recv(randtag)
            rand = Rand(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.my_id, randsend, randrecv, self.pc, self.curve_params, self.matrix)
            new_shares = await rand.run_rand(intput_num, rounds)
            step2_time = time.time() - step2_start_time
            print(f"len new_shares: {len(new_shares)}")
            print(f"step2_time: {step2_time}")

            # 这里是 execution stage 的 step 1，执行当前层的计算
            gate_tape = []
            for i in range(cm): 
                gate_tape.append(1)
            for i in range(w - cm): 
                gate_tape.append(0)
            
            # 这里根据电路层数，执行每层的计算
            for i in range(layers): 
                layer_time = time.time()
                gate_outputs = await self.run_computation(new_shares, gate_tape, new_mult_triples, i)
                layer_time = time.time() - layer_time
                print(f"layer ID: {i} layer_time: {layer_time}")

            # 这里是调用 robust_rec 来重构输出
            rec_time = time.time()
            print(f"len gate_outputs: {len(gate_outputs)}")
            # 这里的话我先设置了一个很大的数字 20，这个要是重复的话会引起冲突，导致协议运行不下去
            rec_task = asyncio.create_task(self.rec_step(gate_outputs, 20))
            (mks, output_values) = await rec_task
            # (mks, output_values) = await self.rec_step(gate_outputs, 0)
            rec_time = time.time() - rec_time
            print(f"final rec rec_time: {rec_time}")

            admpc_time = time.time() - start_time
            print(f"honeybadgermpc_time: {admpc_time}")
        # else: 
        #     await asyncio.sleep(180)
        # else: 
        #     await asyncio.sleep(240)
        # # honeybadgermpc 第一步需要调用 aprep 协议生成电路需要的三元组
        # layers = self.layers - 2
        # layers = 1
        # # layers = 9
        # cm = int(self.total_cm / layers)
        # # 这里的话 电路宽度要等于 2 * cm
        # w = 2 * cm
        # print(f"cm: {cm} layers: {layers}")

        # step3_start_time = time.time()
        # apreptag = ADMPCMsgType.APREP
        # aprepsend, apreprecv = self.get_send(apreptag), self.subscribe_recv(apreptag)
        # aprep = APREP(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.my_id, aprepsend, apreprecv, self.pc, self.curve_params, self.matrix)
        # new_mult_triples = await aprep.run_aprep(self.total_cm)
        # step3_time = time.time() - step3_start_time
        # # print(f"step 3 output: {new_mult_triples}")
        # print(f"step3_time: {step3_time}")

        # # honeybadgermpc 第二步需要调用 acss 协议广播自己的输入
        # # 这里的话 输入的数据要是 2 * w
        # intput_num = 2 * w

        # if intput_num > self.n - self.t: 
        #     rounds = math.ceil(intput_num / (self.n - self.t))
        # else: 
        #     rounds = 1

        # step2_start_time = time.time()
        # randtag = ADMPCMsgType.GENRAND
        # randsend, randrecv = self.get_send(randtag), self.subscribe_recv(randtag)
        # rand = Rand(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.my_id, randsend, randrecv, self.pc, self.curve_params, self.matrix)
        # new_shares = await rand.run_rand(intput_num, rounds)
        # step2_time = time.time() - step2_start_time
        # print(f"len new_shares: {len(new_shares)}")
        # print(f"step2_time: {step2_time}")
       
        # # 这里是 execution stage 的 step 1，执行当前层的计算
        # gate_tape = []
        # for i in range(cm): 
        #     gate_tape.append(1)
        # for i in range(w - cm): 
        #     gate_tape.append(0)
        
        # # 这里根据电路层数，执行每层的计算
        # for i in range(layers): 
        #     layer_time = time.time()
        #     gate_outputs = await self.run_computation(new_shares, gate_tape, new_mult_triples)
        #     layer_time = time.time() - layer_time
        #     print(f"layer ID: {i} layer_time: {layer_time}")

        # # 这里是调用 robust_rec 来重构输出
        # rec_time = time.time()
        # output_values = await self.robust_rec_step(gate_outputs, 0)
        # rec_time = time.time() - rec_time
        # print(f"rec_time: {rec_time}")

        # admpc_time = time.time() - start_time
        # print(f"honeybadgermpc_time: {admpc_time}")
        # logging.info(f"admpc finished! n: {self.n} Node {self.my_id}, tape_num: {tape_num} step1_time: {step1_time}, w: {w} step2_time: {step2_time}, cm: {cm} step3_time: {step3_time}, step4_time: {step4_time} time: {admpc_time}")
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
        self.gates_num = len(gate_tape)
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
    
    
    async def run_admpc(self, start_time):
        acss_start_time = time.time()
        self.public_keys = self.public_keys[self.n*self.layer_ID:self.n*self.layer_ID+self.n]
        cm = int(self.admpc_control_instance.total_cm/(self.admpc_control_instance.layer_num-1))
        w = cm
        len_values = cm
        print(f"cm: {cm} total_cm: {self.admpc_control_instance.total_cm}")

        # 计算每层的时间
        layer_time = time.time()

        


        # 我们假设 layer_ID = 0 时是 clients 提供输入给 servers
        if self.layer_ID == 0:

            clients_inputs = [self.ZR.rand()]

            # 此处传递的公钥应该是下一层的公钥
            acss_pre_time = time.time()
            pks_next_layer = self.admpc_control_instance.pks_all[self.layer_ID + 1]       # 下一层的公钥组

            # 这里 ADKGMsgType.ACSS 都是 acss 有可能会和接下来的 trans 协议冲突
            acsstag = ADMPCMsgType.ACSS + str(self.layer_ID+1) + str(self.my_id)
            acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

            self.acss = ACSS_Pre(pks_next_layer, 
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
            # 这里 w 和 cm 根据 n 和 t 的不同需要手动改
            # w = int(self.n / 2) 
            rand_pre_time = time.time()
            if w > self.n - self.t: 
                rounds = math.ceil(w / (self.n - self.t))
            else: 
                rounds = 1

            randtag = ADMPCMsgType.GENRAND + str(self.layer_ID+1)
            randsend, randrecv = self.get_send(randtag), self.subscribe_recv(randtag)

            rand_pre = Rand_Pre(self.public_keys, self.private_key, 
                                self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                                randsend, randrecv, self.pc, self.curve_params, self.matrix, mpc_instance=self)
            rand_pre_task = asyncio.create_task(rand_pre.run_rand(w, rounds))
            await rand_pre_task
            rand_pre_time = time.time() - rand_pre_time
            print(f"layer ID: {self.layer_ID} rand_pre_time: {rand_pre_time}")

            # clients step 3 调用 Aprep 协议传递三元组给下一层
            # cm = int(self.n / 2)
            # cm = 100
            aprep_pre_time = time.time()
            apreptag = ADMPCMsgType.APREP + str(self.layer_ID+1)
            aprepsend, apreprecv = self.get_send(apreptag), self.subscribe_recv(apreptag)

            aprep_pre = APREP_Pre(self.public_keys, self.private_key, 
                          self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                          aprepsend, apreprecv, self.pc, self.curve_params, self.matrix, mpc_instance=self)
            aprep_pre_task = asyncio.create_task(aprep_pre.run_aprep(cm))
            await aprep_pre_task
            aprep_pre_time = time.time() - aprep_pre_time
            print(f"layer ID: {self.layer_ID} aprep_pre_time: {aprep_pre_time}")

            # 没有办法用 signal 来控制不同层的传输，因此这里先设置一个 sleep 信号，后面得改
            # await asyncio.sleep(30)

        elif self.layer_ID == 1: 
            # servers 在执行当前层的计算之前需要：1. 接收来自上一层的输入（这里注意区分layer=1的情况）2.接收上一层的随机数，3.接收上一层的三元组
            # await self.admpc_control_instance.control_signal.wait()
            # self.admpc_control_instance.control_signal.clear()
            # 这是 step 1 接收上一层的输出（这里注意区分layer=1的情况）
            recv_input_time = time.time()
            self.acss_tasks = [None] * self.n
            for dealer_id in range(self.n): 
                # 这里 ADKGMsgType.ACSS 都是 acss 有可能会和接下来的 trans 协议冲突
                acsstag = ADMPCMsgType.ACSS + str(self.layer_ID) + str(dealer_id)
                acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

                # 此时传递的是本层的公私钥
                self.acss = ACSS_Foll(self.public_keys, self.private_key, 
                                    self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                                    acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                                    mpc_instance=self
                                )
                # 这里的 rounds 也是手动更改的
                rounds = 1
                self.acss_tasks[dealer_id] = asyncio.create_task(self.acss.avss(0, dealer_id, rounds))


                # 对于每一个dealer ID，下一层都要创一个来接受这个dealer ID分发的ACSS实例
            results = await asyncio.gather(*self.acss_tasks)
            dealer, _, shares, commitments = zip(*results)
                
            
            new_shares = []
            for i in range(len(dealer)): 
                for j in range(len(shares[i]['msg'])): 
                    new_shares.append(shares[i]['msg'][j])
            recv_input_time = time.time() - recv_input_time
            print(f"layer ID: {self.layer_ID} recv_input_time: {recv_input_time}")
            # print(f"new_shares: {new_shares}")

            
            # 这是 step 2 接收上一层的随机数
            rand_foll_time = time.time()
            randtag = ADMPCMsgType.GENRAND + str(self.layer_ID)
            randsend, randrecv = self.get_send(randtag), self.subscribe_recv(randtag)
            rand_foll = Rand_Foll(self.public_keys, self.private_key, 
                                  self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                                  randsend, randrecv, self.pc, self.curve_params, self.matrix, mpc_instance=self)
            # 这里我们假设当前层的 servers 知道需要生成多少个随机数，在这里就直接设置，这里也是手动改得
            # w = int(len(new_shares)/2)
            if w > self.n - self.t: 
                rounds = math.ceil(w / (self.n - self.t))
            else: 
                rounds = 1
            # w, rounds = 2, 1           
            rand_shares = await rand_foll.run_rand(w, rounds)
            rand_foll_time = time.time() - rand_foll_time
            print(f"layer ID: {self.layer_ID} rand_foll_time: {rand_foll_time}")
            
            # print(f"rand_shares: {rand_shares}")

            # # 这是 step 3 接收上一层的三元组
            aprep_foll_time = time.time()
            apreptag = ADMPCMsgType.APREP + str(self.layer_ID)
            aprepsend, apreprecv = self.get_send(apreptag), self.subscribe_recv(apreptag)

            aprep_foll = APREP_Foll(self.public_keys, self.private_key, 
                          self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                          aprepsend, apreprecv, self.pc, self.curve_params, self.matrix, mpc_instance=self)

            # 这里同样也是假设当前层的 servers 知道该层需要多少乘法三元组,手动
            # cm = int(len(new_shares)/2)
            # cm = 100
            new_mult_triples = await aprep_foll.run_aprep(cm)
            aprep_foll_time = time.time() - aprep_foll_time
            print(f"layer ID: {self.layer_ID} aprep_foll_time: {aprep_foll_time}")
            # print(f"new triples: {new_mult_triples}")


            # 这里是 execution stage 的 step 1，执行当前层的计算
            exec_time = time.time()
            gate_tape = []
            for i in range(cm): 
                gate_tape.append(1)
            gate_outputs = await self.run_computation(new_shares, gate_tape, new_mult_triples)
            exec_time = time.time() - exec_time
            print(f"layer ID: {self.layer_ID} exec_time: {exec_time}")
            # print(f"my id: {self.my_id} outputs: {gate_outputs}")

            if self.layer_ID + 1 < len(self.admpc_control_instance.pks_all):
            # if self.admpc_control_instance.pks_all[self.layer_ID + 1] is not None: 
                # 这里是 execution stage 的 step 2，调用 rand 协议为下一层生成随机数
                # w 是需要生成的随机数的数量 手动
                # w = int(len(gate_outputs)/2)
                # w = 1
                rand_pre_time = time.time()
                if w > self.n - self.t: 
                    rounds = math.ceil(w / (self.n - self.t))
                else: 
                    rounds = 1

                randtag = ADMPCMsgType.GENRAND + str(self.layer_ID+1)
                randsend, randrecv = self.get_send(randtag), self.subscribe_recv(randtag)

                rand_pre = Rand_Pre(self.public_keys, self.private_key, 
                                    self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                                    randsend, randrecv, self.pc, self.curve_params, self.matrix, mpc_instance=self)
                rand_pre_task = asyncio.create_task(rand_pre.run_rand(w, rounds))
                rand_pre_time = time.time() - rand_pre_time
                print(f"layer ID: {self.layer_ID} rand_pre_time: {rand_pre_time}")

                # 这里是 execution stage 的 step 3，调用 Aprep 协议为下一层生成乘法三元组 手动
                # cm = int(len(gate_outputs)/2)
                # cm = 1
                aprep_pre_time = time.time()
                apreptag = ADMPCMsgType.APREP + str(self.layer_ID+1)
                aprepsend, apreprecv = self.get_send(apreptag), self.subscribe_recv(apreptag)

                aprep_pre = APREP_Pre(self.public_keys, self.private_key, 
                            self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                            aprepsend, apreprecv, self.pc, self.curve_params, self.matrix, mpc_instance=self)
                aprep_pre_task = asyncio.create_task(aprep_pre.run_aprep(cm))
                aprep_pre_time = time.time() - aprep_pre_time
                print(f"layer ID: {self.layer_ID} aprep_pre_time: {aprep_pre_time}")

                # 这里是 execution stage 的 step 4，调用 Trans 协议将当前层的电路输出传输到下一层
                trans_pre_time = time.time()
                transtag = ADMPCMsgType.TRANS + str(self.layer_ID+1)
                transsend, transrecv = self.get_send(transtag), self.subscribe_recv(transtag)

                trans_pre = Trans_Pre(self.public_keys, self.private_key, 
                                self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                                transsend, transrecv, self.pc, self.curve_params, mpc_instance=self)
                trans_pre_task = asyncio.create_task(trans_pre.run_trans(gate_outputs, rand_shares))
                
                self.admpc_control_instance.control_signal.set()
                trans_pre_time = time.time() - trans_pre_time
                print(f"layer ID: {self.layer_ID} trans_pre_time: {trans_pre_time}")
                
                print("end")
                # await asyncio.sleep(30)
            else: 
                print("over")
        else:
        # elif self.layer_ID == 2: 
            # servers 在执行当前层的计算之前需要：1. 接收来自上一层的输入（这里注意区分layer=1的情况）2.接收上一层的随机数，3.接收上一层的三元组
            # await self.admpc_control_instance.control_signal.wait()
            # self.admpc_control_instance.control_signal.clear()
            # 这是 step 1 接收上一层的输出（这里注意区分layer=1的情况）
            print(f"ok")
            trans_foll_time = time.time()
            transtag = ADMPCMsgType.TRANS + str(self.layer_ID)
            transsend, transrecv = self.get_send(transtag), self.subscribe_recv(transtag)

            trans_foll = Trans_Foll(self.public_keys, self.private_key, 
                            self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                            transsend, transrecv, self.pc, self.curve_params, mpc_instance=self)
            # 这里也是假设当前 servers 知道上一层电路门输出的数量
            # 这里也需要手动改
            # len_values = int(self.n / 2)
            new_shares = await trans_foll.run_trans(len_values)
            trans_foll_time = time.time() - trans_foll_time
            print(f"layer ID: {self.layer_ID} trans_foll_time: {trans_foll_time}")
            # print(f"new shares: {new_shares}")
                


            # 这是 step 2 接收上一层的随机数
            rand_foll_time = time.time()
            randtag = ADMPCMsgType.GENRAND + str(self.layer_ID)
            randsend, randrecv = self.get_send(randtag), self.subscribe_recv(randtag)
            rand_foll = Rand_Foll(self.public_keys, self.private_key, 
                                  self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                                  randsend, randrecv, self.pc, self.curve_params, self.matrix, mpc_instance=self)
            # 这里我们假设当前层的 servers 知道需要生成多少个随机数，在这里就直接设置
            # w = int(len(new_shares)/2)
            # w = 1
            if w > self.n - self.t: 
                rounds = math.ceil(w / (self.n - self.t))
            else: 
                rounds = 1
            # w, rounds = 2, 1           
            rand_shares = await rand_foll.run_rand(w, rounds)
            rand_foll_time = time.time() - rand_foll_time
            print(f"layer ID: {self.layer_ID} rand_foll_time: {rand_foll_time}")
            
            # print(f"rand_shares: {rand_shares}")

            # # 这是 step 3 接收上一层的三元组
            aprep_foll_time = time.time()
            apreptag = ADMPCMsgType.APREP + str(self.layer_ID)
            aprepsend, apreprecv = self.get_send(apreptag), self.subscribe_recv(apreptag)

            aprep_foll = APREP_Foll(self.public_keys, self.private_key, 
                          self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                          aprepsend, apreprecv, self.pc, self.curve_params, self.matrix, mpc_instance=self)

            # 这里同样也是假设当前层的 servers 知道该层需要多少乘法三元组
            # cm = int(len(new_shares)/2)
            # cm = 1
            new_mult_triples = await aprep_foll.run_aprep(cm)
            aprep_foll_time = time.time() - aprep_foll_time
            print(f"layer ID: {self.layer_ID} aprep_foll_time: {aprep_foll_time}")
            # print(f"new triples: {new_mult_triples}")


            # 这里是 execution stage 的 step 1，执行当前层的计算
            exec_time = time.time()
            gate_tape = []
            for i in range(cm): 
                gate_tape.append(1)
            gate_outputs = await self.run_computation(new_shares, gate_tape, new_mult_triples)
            exec_time = time.time() - exec_time
            print(f"layer ID: {self.layer_ID} exec_time: {exec_time}")
            # print(f"my id: {self.my_id} outputs: {gate_outputs}")

            if self.layer_ID + 1 < len(self.admpc_control_instance.pks_all):
            # if self.admpc_control_instance.pks_all[self.layer_ID + 1] is not None: 
                # 这里是 execution stage 的 step 2，调用 rand 协议为下一层生成随机数
                # w 是需要生成的随机数的数量 手动
                # w = int(len(gate_outputs)/2)
                # w = 1
                rand_pre_time = time.time()
                if w > self.n - self.t: 
                    rounds = math.ceil(w / (self.n - self.t))
                else: 
                    rounds = 1

                randtag = ADMPCMsgType.GENRAND + str(self.layer_ID+1)
                randsend, randrecv = self.get_send(randtag), self.subscribe_recv(randtag)

                rand_pre = Rand_Pre(self.public_keys, self.private_key, 
                                    self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                                    randsend, randrecv, self.pc, self.curve_params, self.matrix, mpc_instance=self)
                rand_pre_task = asyncio.create_task(rand_pre.run_rand(w, rounds))
                rand_pre_time = time.time() - rand_pre_time
                print(f"layer ID: {self.layer_ID} rand_pre_time: {rand_pre_time}")

                # 这里是 execution stage 的 step 3，调用 Aprep 协议为下一层生成乘法三元组 手动
                # cm = int(len(gate_outputs)/2)
                # cm = 1
                aprep_pre_time = time.time()
                apreptag = ADMPCMsgType.APREP + str(self.layer_ID+1)
                aprepsend, apreprecv = self.get_send(apreptag), self.subscribe_recv(apreptag)

                aprep_pre = APREP_Pre(self.public_keys, self.private_key, 
                            self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                            aprepsend, apreprecv, self.pc, self.curve_params, self.matrix, mpc_instance=self)
                aprep_pre_task = asyncio.create_task(aprep_pre.run_aprep(cm))
                aprep_pre_time = time.time() - aprep_pre_time
                print(f"layer ID: {self.layer_ID} aprep_pre_time: {aprep_pre_time}")

                # 这里是 execution stage 的 step 4，调用 Trans 协议将当前层的电路输出传输到下一层
                trans_pre_time = time.time()
                transtag = ADMPCMsgType.TRANS + str(self.layer_ID+1)
                transsend, transrecv = self.get_send(transtag), self.subscribe_recv(transtag)

                trans_pre = Trans_Pre(self.public_keys, self.private_key, 
                                self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                                transsend, transrecv, self.pc, self.curve_params, mpc_instance=self)
                trans_pre_task = asyncio.create_task(trans_pre.run_trans(gate_outputs, rand_shares))
                
                self.admpc_control_instance.control_signal.set()
                trans_pre_time = time.time() - trans_pre_time
                print(f"layer ID: {self.layer_ID} trans_pre_time: {trans_pre_time}")
                
                print("end")
                # await asyncio.sleep(30)
            else: 
                print("over")
        layer_time = time.time() - layer_time
        print(f"layer ID: {self.layer_ID} layer_time: {layer_time}")
        
        