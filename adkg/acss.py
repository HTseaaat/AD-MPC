import asyncio
from collections import defaultdict
from pickle import dumps, loads
import re, time
from adkg.polynomial import polynomials_over
from adkg.symmetric_crypto import SymmetricCrypto
from adkg.utils.misc import wrap_send, subscribe_recv
from adkg.broadcast.optqrbc import optqrbc, optqrbc_dynamic
from adkg.utils.serilization import Serial

from pypairing import ZR, G1, blsmultiexp as multiexp, dotprod


import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)

# Uncomment this when you want logs from this file.
# logger.setLevel(logging.DEBUG)


class HbAVSSMessageType:
    OK = 1
    IMPLICATE = 2
    RECOVERY = 4
    RECOVERY1 = 5
    RECOVERY2 = 6
    KDIBROADCAST = 7

class ACSS:
    #@profile
    def __init__(
            self, public_keys, private_key, g, h, n, t, deg, sc, my_id, send, recv, pc, field, G1
            , rbc_values=None
    ):  # (# noqa: E501)
        self.public_keys, self.private_key = public_keys, private_key
        self.n, self.t, self.deg, self.my_id = n, t, deg, my_id
        self.g, self.h = g, h 
        self.sr = Serial(G1)
        self.sc = sc 
        self.poly_commit = pc

        # 这里存的是各方广播的 masked values
        if rbc_values is not None: 
            self.rbc_values = rbc_values
        
        self.multiexp = multiexp

        self.benchmark_logger = logging.LoggerAdapter(
            logging.getLogger("benchmark_logger"), {"node_id": self.my_id}
        )

        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)

        self.get_send = _send

        self.acss_status = defaultdict(lambda: True)
        self.field = field
        self.poly = polynomials_over(self.field)
        self.poly.clear_cache()
        self.output_queue = asyncio.Queue()
        self.tagvars = {}
        self.tasks = []
        self.data = {}

    def __enter__(self):
        return self

    #def __exit__(self, typ, value, traceback):
    def kill(self):
        # self.benchmark_logger.info("ACSS kill called")
        self.subscribe_recv_task.cancel()
        # self.benchmark_logger.info("ACSS recv task cancelled")
        for task in self.tasks:
            task.cancel()
        # self.benchmark_logger.info("ACSS self.tasks cancelled")
        for key in self.tagvars:
            for task in self.tagvars[key]['tasks']:
                task.cancel()
        # self.benchmark_logger.info("ACSS self tagvars canceled")

    
    #@profile
    async def _handle_implication(self, tag, j, idx, j_sk):
        """
        Handle the implication of AVSS.
        Return True if the implication is valid, False otherwise.
        """
        commitments =  self.tagvars[tag]['commitments']
        # discard if PKj ! = g^SKj
        if self.public_keys[j] != self.g**j_sk:
            return False
        # decrypt and verify
        implicate_msg = None #FIXME: IMPORTANT!!
        j_shared_key = (self.tagvars[tag]['ephemeral_public_key'])**j_sk

        # Same as the batch size
        secret_count = len(commitments)

        try:
            j_shares, j_witnesses = SymmetricCrypto.decrypt(
                j_shared_key.__getstate__(), implicate_msg
            )
        except Exception as e:  # TODO specific exception
            logger.warn("Implicate confirmed, bad encryption:", e)
            return True
        return not self.poly_commit.batch_verify_eval(
            commitments[idx], j + 1, j_shares, j_witnesses, self.t
        )

    def _init_recovery_vars(self, tag):
        self.kdi_broadcast_sent = False
        self.saved_shares = [None] * self.n
        self.saved_shared_actual_length = 0
        self.interpolated = False

    # this function should eventually multicast OK, set self.tagvars[tag]['all_shares_valid'] to True, and set self.tagvars[tag]['shares']
    #@profile
    async def _handle_share_recovery(self, tag, sender=None, avss_msg=[""]):
        send, recv, multicast = self.tagvars[tag]['io']
        if not self.tagvars[tag]['in_share_recovery']:
            return
        if self.tagvars[tag]['all_shares_valid'] and not self.kdi_broadcast_sent:
            logger.debug("[%d] sent_kdi_broadcast", self.my_id)
            kdi = self.tagvars[tag]['shared_key']
            multicast((HbAVSSMessageType.KDIBROADCAST, kdi))
            self.kdi_broadcast_sent = True
        if self.tagvars[tag]['all_shares_valid']:
            return

        if avss_msg[0] == HbAVSSMessageType.KDIBROADCAST:
            logger.debug("[%d] received_kdi_broadcast from sender %d", self.my_id, sender)
            
            # FIXME: IMPORTANT!! read the message from rbc output
            # retrieved_msg = await avid.retrieve(tag, sender)
            retrieved_msg = None
            try:
                j_shares, j_witnesses = SymmetricCrypto.decrypt(
                    avss_msg[1].__getstate__(), retrieved_msg
                )
            except Exception as e:  # TODO: Add specific exception
                logger.debug("Implicate confirmed, bad encryption:", e)
            commitments = self.tagvars[tag]['commitments']
            if (self.poly_commit.batch_verify_eval(commitments,
                                                   sender + 1, j_shares, j_witnesses, self.t)):
                if not self.saved_shares[sender]:
                    self.saved_shared_actual_length += 1
                    self.saved_shares[sender] = j_shares

        # if t+1 in the saved_set, interpolate and sell all OK
        if self.saved_shared_actual_length >= self.t + 1 and not self.interpolated:
            logger.debug("[%d] interpolating", self.my_id)
            # Batch size
            shares = []
            secret_count = len(self.tagvars[tag]['commitments'])
            for i in range(secret_count):
                phi_coords = [
                    (j + 1, self.saved_shares[j][i]) for j in range(self.n) if self.saved_shares[j] is not None
                ]
                shares.append(self.poly.interpolate_at(phi_coords, self.my_id + 1))
            self.tagvars[tag]['all_shares_valid'] = True
            self.tagvars[tag]['shares'] = shares
            self.tagvars[tag]['in_share_recovery'] = False
            self.interpolated = True
            multicast((HbAVSSMessageType.OK, ""))
    
    def decode_proposal(self, proposal):
        g_size = self.sr.g_size
        c_size = 32

        # deserializing commitments
        com_size = g_size*(self.t+1)*(self.rand_num)
        commits_all = self.sr.deserialize_gs(proposal[0:com_size])
        commits = [commits_all[i*(self.t+1):(i+1)*(self.t+1)] for i in range(self.rand_num)]

        # deserializing ciphertexts
        # IMPORTANT: Here 32 additional bytes are used in the ciphertext for padding
        ctx_size = (c_size*2*self.rand_num+c_size)*self.n
        my_ctx_start = com_size + (c_size*2*self.rand_num+c_size)*self.my_id
        my_ctx_end = my_ctx_start + (c_size*2*self.rand_num+c_size)
        ctx_bytes = proposal[my_ctx_start:my_ctx_end]

        # deserializing the ephemeral public key
        ephkey = self.sr.deserialize_g(proposal[com_size+ctx_size:])
        
        return (ctx_bytes, commits, ephkey)
    
    def decode_proposal_trans(self, proposal):
        g_size = self.sr.g_size
        c_size = 32

        # deserializing commitments
        com_size = g_size*(self.t+1)*(self.len_values)
        commits_all = self.sr.deserialize_gs(proposal[0:com_size])
        commits = [commits_all[i*(self.t+1):(i+1)*(self.t+1)] for i in range(self.len_values)]

        # deserializing ciphertexts
        # IMPORTANT: Here 32 additional bytes are used in the ciphertext for padding
        ctx_size = (c_size*2*self.len_values+c_size)*self.n
        my_ctx_start = com_size + (c_size*2*self.len_values+c_size)*self.my_id
        my_ctx_end = my_ctx_start + (c_size*2*self.len_values+c_size)
        ctx_bytes = proposal[my_ctx_start:my_ctx_end]

        # deserializing the ephemeral public key
        ephkey = self.sr.deserialize_g(proposal[com_size+ctx_size:])
        
        return (ctx_bytes, commits, ephkey)

    def decode_proposal_aprep(self, proposal):
        g_size = self.sr.g_size
        c_size = 32

        # deserializing commitments
        # 这里的 3+3+1 指的是 乘法三元组中对应的三个 commits，验证三元组对应的 三个 commits
        com_size = g_size*(self.t+1)*(self.cm)*(3+3)
        # print(f"id: {self.my_id} proposal: {proposal[0:com_size]}")
        # 这里 commis_all 我们是按照 cm 进行划分的
        commits_all = self.sr.deserialize_gs(proposal[0:com_size])
        # print(f"commits_all: {commits_all}")
        mult_triples_commits = [[] for _ in range(self.cm)]
        chec_triples_commits = [[] for _ in range(self.cm)]
        rand_values_commits = []
        num = 0
        for i in range(self.cm): 
            mult_triples_commits[i] = []
            chec_triples_commits[i] = []
            for j in range(3): 
                mult_triples_commits[i].append(commits_all[num*(self.t+1):(num+1)*(self.t+1)])
                num += 1
            for j in range(3): 
                chec_triples_commits[i].append(commits_all[num*(self.t+1):(num+1)*(self.t+1)])
                num += 1
            # rand_values_commits.append(commits_all[num*(self.t+1):(num+1)*(self.t+1)])
            # num += 1

        commits = (mult_triples_commits, chec_triples_commits)
        # print(f"mult_triples_commits: {mult_triples_commits}")
        # print(f"chec_triples_commits: {chec_triples_commits}")
        # print(f"rand_values_commits: {rand_values_commits}")

        # deserializing ciphertexts
        # IMPORTANT: Here 32 additional bytes are used in the ciphertext for padding
        # 这里解密我们也需要参照 commits 的反序列化方法
        # 这个 2 是从哪里来的，这里的 2 是多项式 phi 和 phi_hat 这两个，但是 ADKG k=0 时没有对应的 phi_hat 那么这里怎么能是 2 呢
        ctx_size = (c_size*2*self.cm*(3+3)+c_size)*self.n
        my_ctx_start = com_size + (c_size*2*self.cm*(3+3)+c_size)*self.my_id
        my_ctx_end = my_ctx_start + c_size*2*self.cm*(3+3) + c_size
        ctx_bytes = proposal[my_ctx_start:my_ctx_end]
        # print(f"id: {self.my_id} proposal1: {proposal[com_size:com_size+ctx_size]}")

        # print(f"my id: {self.my_id} ctx_bytes: {ctx_bytes}")

        # deserializing the ephemeral public key
        # 这里为什么会报错呢，公钥这里我没有动，按理来说应该不会报错
        ephkey = self.sr.deserialize_g(proposal[com_size+ctx_size:])
        
        return (ctx_bytes, commits, ephkey)
    
    def verify_proposal(self, dealer_id, dispersal_msg, commits, ephkey):
        # return True

        # 前一层不用验证
        if self.private_key == None:
            return True

        
        shared_key = ephkey**self.private_key
        
        try:
            sharesb = SymmetricCrypto.decrypt(shared_key.__getstate__(), dispersal_msg)
        except ValueError as e:  # TODO: more specific exception
            logger.warn(f"Implicate due to failure in decrypting: {e}")
            self.acss_status[dealer_id] = False
            return False
        
        shares = self.sr.deserialize_fs(sharesb)

        
        
        phis, phis_hat = shares[:self.rand_num], shares[self.rand_num:]
        
        # check the feldman commitment of the first secret
        for i in range(self.rand_num):
            
            if not self.poly_commit.verify_eval(commits[i], self.my_id + 1, phis[i], phis_hat[i]): 
                self.acss_status[dealer_id] = False
                return False
        
        
        self.acss_status[dealer_id] = True
        self.data[dealer_id] = [commits, phis, phis_hat, ephkey, shared_key]
        return True

    def verify_proposal_trans(self, dealer_id, dispersal_msg, commits, ephkey):

        # 前一层不用验证
        if self.private_key == None:
            return True

        # return True

        shared_key = ephkey**self.private_key


        try:
            sharesb = SymmetricCrypto.decrypt(shared_key.__getstate__(), dispersal_msg)
        except ValueError as e:  # TODO: more specific exception
            logger.warn(f"Implicate due to failure in decrypting: {e}")
            self.acss_status[dealer_id] = False
            return False

        shares = self.sr.deserialize_fs(sharesb)
        phis, phis_hat = shares[:self.len_values], shares[self.len_values:]
        # check the feldman commitment of the first secret
        # 这里也是分开进行多项式承诺的检验的，所以 k=0 时候的 feldman 承诺是做什么用的还不清楚，目前看来没有它也可以
        for i in range(self.len_values):
            if not self.poly_commit.verify_eval(commits[i], self.my_id + 1, phis[i], phis_hat[i]): 
                self.acss_status[dealer_id] = False
                return False
            

        # 这里是反序列化的代码 
        g_size = self.sr.g_size
        f_size = self.sr.f_size
        serialized_masked_values = self.rbc_values[dealer_id][:f_size*self.len_values]
        serialized_masked_values_hat = self.rbc_values[dealer_id][f_size*self.len_values:2*f_size*self.len_values]
        serialized_c = self.rbc_values[dealer_id][2*f_size*self.len_values:(2*f_size+g_size)*self.len_values]

        de_masked_values = self.sr.deserialize_fs(serialized_masked_values)
        de_masked_values_hat = self.sr.deserialize_fs(serialized_masked_values_hat)
        de_c = self.sr.deserialize_gs(serialized_c)

        # 这里实现的是检测 masked values 是否是正确的，如果是正确的，我们将dealer 提供的 shares 存下来，如果不是则丢弃
        for i in range(self.len_values): 
            if self.multiexp([self.g, self.h], [de_masked_values[i], de_masked_values_hat[i]]) != de_c[i] * commits[i][0]: 
                self.acss_status[dealer_id] = False
                return False
        
        
        self.acss_status[dealer_id] = True
        self.data[dealer_id] = [commits, phis, phis_hat, ephkey, shared_key]
        return True
    
    def verify_proposal_aprep(self, dealer_id, dispersal_msg, commits, ephkey):

        # 前一层不用验证
        if self.private_key == None:
            return True

        shared_key = ephkey**self.private_key

        mult_triples_commits, chec_triples_commits = commits

        # 第一层嵌套的数组表示有几个 三元组，第二层嵌套的数组表示三元组中某个元素的承诺，第三层嵌套表示的是具体到三元组中某个元素的多项式承诺的具体系数
        # print(f"mult_triples_commits[0]: {mult_triples_commits[0]}")
        # print(f"mult_triples_commits[0][0]: {mult_triples_commits[0][0]}")
        # print(f"mult_triples_commits[0][0][0]: {mult_triples_commits[0][0][0]}")

        try:
            sharesb = SymmetricCrypto.decrypt(shared_key.__getstate__(), dispersal_msg)
        except ValueError as e:  # TODO: more specific exception
            logger.warn(f"Implicate due to failure in decrypting: {e}")
            self.acss_status[dealer_id] = False
            return False

        shares = self.sr.deserialize_fs(sharesb)
        # print(f"shares: {shares}")
        # 这里反序列化需要把那几个三元组还有随机数分开，现在是合在一起的，例如 
        # phi_mult_triples_si_list 包含所有 cm 的三元组
        phi_mult_triples_si_list = shares[:self.cm*3]
        phi_mult_triples_hat_si_list = shares[self.cm*3:self.cm*3*2]
        phi_chec_triples_si_list = shares[self.cm*3*2:self.cm*3*3]
        phi_chec_triples_hat_si_list = shares[self.cm*3*3:self.cm*3*4]
        # phi_rand_values_si = shares[self.cm*3*4:self.cm*3*4+self.cm]
        # phi_rand_values_hat_si = shares[self.cm*3*4+self.cm:self.cm*3*4+self.cm*2]

        phi_mult_triples_si = [[] for _ in range(self.cm)]
        phi_mult_triples_hat_si = [[] for _ in range(self.cm)]
        phi_chec_triples_si = [[] for _ in range(self.cm)]
        phi_chec_triples_hat_si = [[] for _ in range(self.cm)]

        num = 0
        for i in range(self.cm): 
            phi_mult_triples_si[i] = phi_mult_triples_si_list[num:num+3]
            phi_mult_triples_hat_si[i] = phi_mult_triples_hat_si_list[num:num+3]
            phi_chec_triples_si[i] = phi_chec_triples_si_list[num:num+3]
            phi_chec_triples_hat_si[i] = phi_chec_triples_hat_si_list[num:num+3]

            num += 3
        
        # phis, phis_hat = shares[:self.sc], shares[self.sc:]
            
        # 检验通过 acss 步骤的乘法三元组中的所有元素是否能通过多项式评估
        for i in range(self.cm): 
            for j in range(3): 
                if not self.poly_commit.verify_eval(mult_triples_commits[i][j], self.my_id + 1, phi_mult_triples_si[i][j], phi_mult_triples_hat_si[i][j]): 
                    self.acss_status[dealer_id] = False
                    return False
                if not self.poly_commit.verify_eval(chec_triples_commits[i][j], self.my_id + 1, phi_chec_triples_si[i][j], phi_chec_triples_hat_si[i][j]): 
                    self.acss_status[dealer_id] = False
                    return False
            # if not self.poly_commit.verify_eval(rand_values_commits[i], self.my_id + 1, phi_rand_values_si[i], phi_rand_values_hat_si[i]): 
            #     self.acss_status[dealer_id] = False
            #     return False      
            
        
        self.acss_status[dealer_id] = True
        phis = (phi_mult_triples_si, phi_chec_triples_si)
        phis_hat = (phi_mult_triples_hat_si, phi_chec_triples_hat_si)
        self.data[dealer_id] = [commits, phis, phis_hat, ephkey, shared_key]
        return True
    
    #@profile    
    async def _process_avss_msg(self, avss_id, dealer_id, rbc_msg):
        tag = f"{dealer_id}-{avss_id}-B-AVSS"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)
        self._init_recovery_vars(tag)

        def multicast(msg):
            for i in range(self.n):
                send(i, msg)

        self.tagvars[tag]['io'] = [send, recv, multicast]
        self.tagvars[tag]['in_share_recovery'] = False
        # dispersal_msg, commits, ephkey = self.decode_proposal(rbc_msg)
        # dispersal_msg, commits, ephkey = self.decode_proposal(rbc_msg)
        
        ok_set = set()
        implicate_set = set()
        output = False

        self.tagvars[tag]['all_shares_valid'] = self._handle_dealer_msgs(tag, dealer_id)

        if self.tagvars[tag]['all_shares_valid']:
            # 每个节点的 shares 存在这里
            shares = {'msg': self.tagvars[tag]['shares'][0], 'rand':self.tagvars[tag]['shares'][1]}
            commitments = self.tagvars[tag]['commitments']
            self.output_queue.put_nowait((dealer_id, avss_id, shares, commitments))
            output = True
            logger.debug("[%d] Output", self.my_id)
            multicast((HbAVSSMessageType.OK, ""))
        else:
            multicast((HbAVSSMessageType.IMPLICATE, self.private_key))
            implicate_sent = True
            logger.debug("Implicate Sent [%d]", dealer_id)
            self.tagvars[tag]['in_share_recovery'] = True

        while True:
            # Bracha-style agreement
            sender, avss_msg = await recv()

            # IMPLICATE
            if avss_msg[0] == HbAVSSMessageType.IMPLICATE and not self.tagvars[tag]['in_share_recovery']:
                if sender not in implicate_set:
                    implicate_set.add(sender)
                    logger.debug("Handling Implicate Message [%d]", dealer_id)
                    # validate the implicate
                    #todo: implicate should be forwarded to others if we haven't sent one
                    if await self._handle_implication(tag, sender, avss_msg[1]):
                        # proceed to share recovery
                        logger.debug("Handle implication called [%d]", dealer_id)
                        self.tagvars[tag]['in_share_recovery'] = True
                        await self._handle_share_recovery(tag)
                        logger.debug("[%d] after implication", self.my_id)

            #todo find a more graceful way to handle different protocols having different recovery message types
            if avss_msg[0] in [HbAVSSMessageType.KDIBROADCAST, HbAVSSMessageType.RECOVERY1, HbAVSSMessageType.RECOVERY2]:
                await self._handle_share_recovery(tag, sender, avss_msg)
            # OK
            if avss_msg[0] == HbAVSSMessageType.OK and sender not in ok_set:
                # logger.debug("[%d] Received OK from [%d]", self.my_id, sender)
                ok_set.add(sender)

            # The only condition where we can terminate
            if (len(ok_set) == 3 * self.t + 1) and output:
                logger.debug("[%d] exit", self.my_id)
                break
    
    

    async def _process_avss_msg_trans(self, avss_id, dealer_id, rbc_msg):
        tag = f"{dealer_id}-{avss_id}-B-AVSS"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)
        self._init_recovery_vars(tag)

        def multicast(msg):
            for i in range(self.n):
                send(i, msg)

        self.tagvars[tag]['io'] = [send, recv, multicast]
        self.tagvars[tag]['in_share_recovery'] = False
        # dispersal_msg, commits, ephkey = self.decode_proposal(rbc_msg)
        # dispersal_msg, commits, ephkey = self.decode_proposal(rbc_msg)
        
        ok_set = set()
        implicate_set = set()
        output = False

        self.tagvars[tag]['all_shares_valid'] = self._handle_dealer_msgs_trans(tag, dealer_id)

        if self.tagvars[tag]['all_shares_valid']:
            # 每个节点的 shares 存在这里
            shares = {'msg': self.tagvars[tag]['shares'][0], 'rand':self.tagvars[tag]['shares'][1]}
            commitments = self.tagvars[tag]['commitments']
            self.output_queue.put_nowait((dealer_id, avss_id, shares, commitments))
            output = True
            logger.debug("[%d] Output", self.my_id)
            multicast((HbAVSSMessageType.OK, ""))
        else:
            multicast((HbAVSSMessageType.IMPLICATE, self.private_key))
            implicate_sent = True
            logger.debug("Implicate Sent [%d]", dealer_id)
            self.tagvars[tag]['in_share_recovery'] = True

        while True:
            # Bracha-style agreement
            sender, avss_msg = await recv()

            # IMPLICATE
            if avss_msg[0] == HbAVSSMessageType.IMPLICATE and not self.tagvars[tag]['in_share_recovery']:
                if sender not in implicate_set:
                    implicate_set.add(sender)
                    logger.debug("Handling Implicate Message [%d]", dealer_id)
                    # validate the implicate
                    #todo: implicate should be forwarded to others if we haven't sent one
                    if await self._handle_implication(tag, sender, avss_msg[1]):
                        # proceed to share recovery
                        logger.debug("Handle implication called [%d]", dealer_id)
                        self.tagvars[tag]['in_share_recovery'] = True
                        await self._handle_share_recovery(tag)
                        logger.debug("[%d] after implication", self.my_id)

            #todo find a more graceful way to handle different protocols having different recovery message types
            if avss_msg[0] in [HbAVSSMessageType.KDIBROADCAST, HbAVSSMessageType.RECOVERY1, HbAVSSMessageType.RECOVERY2]:
                await self._handle_share_recovery(tag, sender, avss_msg)
            # OK
            if avss_msg[0] == HbAVSSMessageType.OK and sender not in ok_set:
                # logger.debug("[%d] Received OK from [%d]", self.my_id, sender)
                ok_set.add(sender)

            # The only condition where we can terminate
            if (len(ok_set) == 3 * self.t + 1) and output:
                logger.debug("[%d] exit", self.my_id)
                break

    
    async def _process_avss_msg_aprep(self, avss_id, dealer_id, rbc_msg):
        tag = f"{dealer_id}-{avss_id}-B-AVSS"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)
        self._init_recovery_vars(tag)

        def multicast(msg):
            for i in range(self.n):
                send(i, msg)

        self.tagvars[tag]['io'] = [send, recv, multicast]
        self.tagvars[tag]['in_share_recovery'] = False
        # dispersal_msg, commits, ephkey = self.decode_proposal(rbc_msg)
        # dispersal_msg, commits, ephkey = self.decode_proposal(rbc_msg)
        
        ok_set = set()
        implicate_set = set()
        output = False

        self.tagvars[tag]['all_shares_valid'] = self._handle_dealer_msgs_aprep(tag, dealer_id)

        # print(f"self.tagvars[tag]['shares'][0]: {self.tagvars[tag]['shares'][0]}")

        if self.tagvars[tag]['all_shares_valid']:
            # 每个节点的 shares 存在这里
            shares = {'msg': self.tagvars[tag]['shares'][0], 'rand':self.tagvars[tag]['shares'][1]}
            commitments = self.tagvars[tag]['commitments']
            self.output_queue.put_nowait((dealer_id, avss_id, shares, commitments))
            output = True
            logger.debug("[%d] Output", self.my_id)
            multicast((HbAVSSMessageType.OK, ""))
        else:
            multicast((HbAVSSMessageType.IMPLICATE, self.private_key))
            implicate_sent = True
            logger.debug("Implicate Sent [%d]", dealer_id)
            self.tagvars[tag]['in_share_recovery'] = True

        while True:
            # Bracha-style agreement
            sender, avss_msg = await recv()

            # IMPLICATE
            if avss_msg[0] == HbAVSSMessageType.IMPLICATE and not self.tagvars[tag]['in_share_recovery']:
                if sender not in implicate_set:
                    implicate_set.add(sender)
                    logger.debug("Handling Implicate Message [%d]", dealer_id)
                    # validate the implicate
                    #todo: implicate should be forwarded to others if we haven't sent one
                    if await self._handle_implication(tag, sender, avss_msg[1]):
                        # proceed to share recovery
                        logger.debug("Handle implication called [%d]", dealer_id)
                        self.tagvars[tag]['in_share_recovery'] = True
                        await self._handle_share_recovery(tag)
                        logger.debug("[%d] after implication", self.my_id)

            #todo find a more graceful way to handle different protocols having different recovery message types
            if avss_msg[0] in [HbAVSSMessageType.KDIBROADCAST, HbAVSSMessageType.RECOVERY1, HbAVSSMessageType.RECOVERY2]:
                await self._handle_share_recovery(tag, sender, avss_msg)
            # OK
            if avss_msg[0] == HbAVSSMessageType.OK and sender not in ok_set:
                # logger.debug("[%d] Received OK from [%d]", self.my_id, sender)
                ok_set.add(sender)

            # The only condition where we can terminate
            if (len(ok_set) == 3 * self.t + 1) and output:
                logger.debug("[%d] exit", self.my_id)
                break
    
    #@profile
    def _get_dealer_msg(self, values, n):
        # Sample B random degree-(t) polynomials of form φ(·)
        # such that each φ_i(0) = si and φ_i(j) is Pj’s share of si
        # The same as B (batch_size)
        """
        while len(values) % (batch_size) != 0:
            values.append(0)
        """

        self.rand_num = len(values)

        # 这里 phi 和 phi_hat 都是根据 sc 来的
        phi = [None]*self.rand_num
        phi_hat = [None]*self.rand_num
        commitments = [None]*self.rand_num
        # BatchPolyCommit
        #   Cs  <- BatchPolyCommit(SP,φ(·,k))
        # TODO: Whether we should keep track of that or not
        for k in range(self.rand_num):
                phi[k] = self.poly.random(self.t, values[k])
                # 后面生成的 rand 是不是都是从这里来的
                phi_hat[k] = self.poly.random(self.t, self.field.rand())
                # 这里的 commitments 有两个元素，分别是 g 和 h 
                commitments[k] = self.poly_commit.commit(phi[k], phi_hat[k])


        ephemeral_secret_key = self.field.rand()
        ephemeral_public_key = self.g**ephemeral_secret_key
        dispersal_msg_list = bytearray()
        for i in range(n):
            shared_key = self.public_keys[i]**ephemeral_secret_key
            phis_i = [phi[k](i + 1) for k in range(self.rand_num)]
            phis_hat_i = [phi_hat[k](i + 1) for k in range(self.rand_num)]
            ciphertext = SymmetricCrypto.encrypt(shared_key.__getstate__(), self.sr.serialize_fs(phis_i+ phis_hat_i))
            dispersal_msg_list.extend(ciphertext)


        g_commits = []
        # print(f"g_commits: {g_commits}")
        for k in range(self.rand_num):
            g_commits = g_commits + commitments[k]
        # print(f"g_commits: {g_commits}")
        datab = self.sr.serialize_gs(g_commits) # Serializing commitments
        # print(f"datab commits all: {datab}")
        # print(f"len commits all: {len(datab)}")
        datab.extend(dispersal_msg_list)
        # print(f"len dispersal_msg_list: {len(dispersal_msg_list)}")
        # print(f"len ephemeral_public_key: {len(self.sr.serialize_g(ephemeral_public_key))}")
        datab.extend(self.sr.serialize_g(ephemeral_public_key))

        return bytes(datab)
    
    def _get_dealer_msg_trans(self, values, n):
        # Sample B random degree-(t) polynomials of form φ(·)
        # such that each φ_i(0) = si and φ_i(j) is Pj’s share of si
        # The same as B (batch_size)
        """
        while len(values) % (batch_size) != 0:
            values.append(0)
        """
        trans_values, trans_values_hat = values

        # 这里 phi 和 phi_hat 都是根据 sc 来的
        phi = [None] * len(trans_values)
        phi_hat = [None] * len(trans_values)
        commitments = [None] * len(trans_values)
        # BatchPolyCommit
        #   Cs  <- BatchPolyCommit(SP,φ(·,k))
        # TODO: Whether we should keep track of that or not
        for k in range(len(trans_values)):
            # TODO(@sourav): Implement FFT here
            phi[k] = self.poly.random(self.t, trans_values[k])
            # 后面生成的 rand 是不是都是从这里来的
            phi_hat[k] = self.poly.random(self.t, trans_values_hat[k])
            # 这里的 commitments 有两个元素，分别是 g 和 h 
            commitments[k] = self.poly_commit.commit(phi[k], phi_hat[k])


        ephemeral_secret_key = self.field.rand()
        ephemeral_public_key = self.g**ephemeral_secret_key
        dispersal_msg_list = bytearray()
        for i in range(n):
            shared_key = self.public_keys[i]**ephemeral_secret_key
            phis_i = [phi[k](i + 1) for k in range(len(trans_values))]
            phis_hat_i = [phi_hat[k](i + 1) for k in range(len(trans_values))]
            ciphertext = SymmetricCrypto.encrypt(shared_key.__getstate__(), self.sr.serialize_fs(phis_i+ phis_hat_i))
            dispersal_msg_list.extend(ciphertext)

        g_commits = []
        for k in range(len(trans_values)):
            g_commits = g_commits + commitments[k]
        datab = self.sr.serialize_gs(g_commits) # Serializing commitments
        # print(f"dispersal_msg_list: {dispersal_msg_list}")
        datab.extend(dispersal_msg_list)
        datab.extend(self.sr.serialize_g(ephemeral_public_key))

        return bytes(datab)
    
    def _get_dealer_msg_aprep(self, values, n):
        # Sample B random degree-(t) polynomials of form φ(·)
        # such that each φ_i(0) = si and φ_i(j) is Pj’s share of si
        # The same as B (batch_size)
        """
        while len(values) % (batch_size) != 0:
            values.append(0)
        """
        # 这里分两种情况，values 是 trans 协议来的或者是 aprep 协议来的
        mult_triples, chec_triples, self.cm = values

        # 这里 phi 和 phi_hat 都是根据 sc 来的
        phi_mult_triples = [[None for _ in range(3)] for _ in range(self.cm)]
        phi_mult_triples_hat = [[None for _ in range(3)] for _ in range(self.cm)]
        phi_chec_triples = [[None for _ in range(3)] for _ in range(self.cm)]
        phi_chec_triples_hat = [[None for _ in range(3)] for _ in range(self.cm)]
        # phi_rand_values = [None] * self.cm
        # phi_rand_values_hat = [None] * self.cm
        commit_mult_triples = [[None for _ in range(3)] for _ in range(self.cm)]
        commit_chec_triples = [[None for _ in range(3)] for _ in range(self.cm)]
        # commit_rand_values = [None] * self.cm

        # BatchPolyCommit
        #   Cs  <- BatchPolyCommit(SP,φ(·,k))
        # TODO: Whether we should keep track of that or not

        # 为两个 三元组的每个随机数生成多项式和承诺
        for i in range(self.cm):
            for j in range(3): 
                phi_mult_triples[i][j] = self.poly.random(self.t, mult_triples[i][j])
                phi_mult_triples_hat[i][j] = self.poly.random(self.t, self.field.rand())
                phi_chec_triples[i][j] = self.poly.random(self.t, chec_triples[i][j])
                phi_chec_triples_hat[i][j] = self.poly.random(self.t, self.field.rand())
                commit_mult_triples[i][j] = self.poly_commit.commit(phi_mult_triples[i][j], phi_mult_triples_hat[i][j])
                commit_chec_triples[i][j] = self.poly_commit.commit(phi_chec_triples[i][j], phi_chec_triples_hat[i][j])
            # phi_rand_values[i] = self.poly.random(self.t, rand_values[i])
            # phi_rand_values_hat[i] = self.poly.random(self.t, self.field.rand())
            # commit_rand_values[i] = self.poly_commit.commit(phi_rand_values[i], phi_rand_values_hat[i])
        

        ephemeral_secret_key = self.field.rand()
        ephemeral_public_key = self.g**ephemeral_secret_key
        dispersal_msg_list = bytearray()
        # 这个循环是在生成每个多项式上各个点的评估值

        # print(f"commit_mult_triples: {commit_mult_triples}")
        # print(f"commit_chec_triples: {commit_chec_triples}")
        # print(f"commit_rand_values: {commit_rand_values}")
        
        for i in range(n):
            shared_key = self.public_keys[i]**ephemeral_secret_key
            phi_mult_triples_si = [[phi_mult_triples[j][k](i+1) for k in range(3)] for j in range(self.cm)]
            phi_mult_triples_hat_si = [[phi_mult_triples_hat[j][k](i+1) for k in range(3)] for j in range(self.cm)]
            phi_chec_triples_si = [[phi_chec_triples[j][k](i+1) for k in range(3)] for j in range(self.cm)]
            phi_chec_triples_hat_si = [[phi_chec_triples_hat[j][k](i+1) for k in range(3)] for j in range(self.cm)]
            # phi_rand_values_si = [phi_rand_values[k](i + 1) for k in range(self.cm)]
            # phi_rand_values_hat_si = [phi_rand_values_hat[k](i + 1) for k in range(self.cm)]

            # 这里测试一下每个点的评估值是否和承诺是对应的
            # for x in range(self.cm):
            #     for y in range(3): 
            #         if not self.poly_commit.verify_eval(commit_mult_triples[x][y], i + 1, phi_mult_triples_si[x][y], phi_mult_triples_hat_si[x][y]): 
            #             print("False")
            #         if not self.poly_commit.verify_eval(commit_chec_triples[x][y], i + 1, phi_chec_triples_si[x][y], phi_chec_triples_hat_si[x][y]): 
            #             print("False")
            #     if not self.poly_commit.verify_eval(commit_rand_values[x], i + 1, phi_rand_values_si[x], phi_rand_values_hat_si[x]): 
            #         print("Fales")
            
            phi_mult_triples_si_list, phi_mult_triples_hat_si_list = [], []
            phi_chec_triples_si_list, phi_chec_triples_hat_si_list = [], []

            for j in range(self.cm): 
                phi_mult_triples_si_list = phi_mult_triples_si_list + phi_mult_triples_si[j]
                phi_mult_triples_hat_si_list = phi_mult_triples_hat_si_list + phi_mult_triples_hat_si[j]
                phi_chec_triples_si_list = phi_chec_triples_si_list + phi_chec_triples_si[j]
                phi_chec_triples_hat_si_list = phi_chec_triples_hat_si_list + phi_chec_triples_hat_si[j]

            
            
            ciphertext = SymmetricCrypto.encrypt(shared_key.__getstate__(), self.sr.serialize_fs(phi_mult_triples_si_list+ phi_mult_triples_hat_si_list
                                                                                                 +phi_chec_triples_si_list+phi_chec_triples_hat_si_list
                                                                                                 ))
            # print(f"i: {i} ciphertext: {ciphertext}")
            # ctx_size = self.sr.f_size*3*self.cm*(3+3+1)
            # print(f"i: {i} ciphertext1: {ciphertext[0:ctx_size]}")
            dispersal_msg_list.extend(ciphertext)

        

        g_commits = []
        for i in range(self.cm): 
            mult_list, chec_list = [], []
            for j in range(3): 
                mult_list += commit_mult_triples[i][j]
                chec_list += commit_chec_triples[i][j]
            g_commits = g_commits + mult_list + chec_list

        datab = self.sr.serialize_gs(g_commits) # Serializing commitments
        # print(f"id: {self.my_id} datab: {datab}")
        # print(f"len datab: {len(datab)}")
        datab.extend(dispersal_msg_list)
        # print(f"len datab: {len(datab)}")
        # print(f"id: {self.my_id} datab2: {datab}")
        datab.extend(self.sr.serialize_g(ephemeral_public_key))
        # print(f"len datab: {len(datab)}")
        # print(f"id: {self.my_id} datab3: {datab}")
        # com_size = self.sr.g_size*(self.t+1)*(self.cm)*(3+3+1)
        # ctx_size = self.sr.f_size*2*self.cm*(3+3+1)+self.sr.f_size
        # tem_size = ctx_size * 4
        # print(f"datab4: {datab[com_size:com_size + tem_size]}")
        # print(f"datab5: {datab[com_size+tem_size:]}")

        # print(f"ephemeral_public_key: {self.sr.serialize_g(ephemeral_public_key)}")

        return bytes(datab)
    
    #@profile
    def _handle_dealer_msgs(self, tag, dealer_id):
        # TODO(@sourav): To add a check here to match hash
        commits, phis, phis_hat, ephkey, shared_key = self.data[dealer_id]
        self.tagvars[tag]['shared_key'] = shared_key
        self.tagvars[tag]['commitments'] = commits
        self.tagvars[tag]['ephemeral_public_key'] = ephkey
        
        # shares = self.sr.deserialize_fs(sharesb)
        if self.acss_status[dealer_id]: 
            # self.tagvars[tag]['shares'] =  [shares[:self.sc], shares[self.sc:]]
            # 知道为什么 msg 包含的元素是两个了，我们的 sc = 2，所以 phis 有两个元素，其中 k = 1 的 phis 还对应着一个 phis_hat ，phis_hat 的元素放到了 rand 里面
            self.tagvars[tag]['shares'] =  [phis, phis_hat]
            self.tagvars[tag]['witnesses'] = [None]
            return True
        return False
    
    def _handle_dealer_msgs_trans(self, tag, dealer_id):
        # TODO(@sourav): To add a check here to match hash
        commits, phis, phis_hat, ephkey, shared_key = self.data[dealer_id]
        self.tagvars[tag]['shared_key'] = shared_key
        self.tagvars[tag]['commitments'] = commits
        self.tagvars[tag]['ephemeral_public_key'] = ephkey
        
        # shares = self.sr.deserialize_fs(sharesb)
        if self.acss_status[dealer_id]: 
            # self.tagvars[tag]['shares'] =  [shares[:self.sc], shares[self.sc:]]
            # 知道为什么 msg 包含的元素是两个了，我们的 sc = 2，所以 phis 有两个元素，其中 k = 1 的 phis 还对应着一个 phis_hat ，phis_hat 的元素放到了 rand 里面
            self.tagvars[tag]['shares'] =  [phis, phis_hat]
            self.tagvars[tag]['witnesses'] = [None]
            return True
        return False
    
    def _handle_dealer_msgs_aprep(self, tag, dealer_id):
        # TODO(@sourav): To add a check here to match hash
        commits, phis, phis_hat, ephkey, shared_key = self.data[dealer_id]
        self.tagvars[tag]['shared_key'] = shared_key
        self.tagvars[tag]['commitments'] = commits
        self.tagvars[tag]['ephemeral_public_key'] = ephkey
        
        # shares = self.sr.deserialize_fs(sharesb)
        if self.acss_status[dealer_id]: 
            # self.tagvars[tag]['shares'] =  [shares[:self.sc], shares[self.sc:]]
            # 知道为什么 msg 包含的元素是两个了，我们的 sc = 2，所以 phis 有两个元素，其中 k = 1 的 phis 还对应着一个 phis_hat ，phis_hat 的元素放到了 rand 里面
            self.tagvars[tag]['shares'] =  [phis, phis_hat]
            self.tagvars[tag]['witnesses'] = [None]
            return True
        return False

    #@profile
    async def avss(self, avss_id, values=None, dealer_id=None):
        """
        An acss with share recovery
        """
        # If `values` is passed then the node is a 'Sender'
        # `dealer_id` must be equal to `self.my_id`
        if values is not None:
            if dealer_id is None:
                dealer_id = self.my_id
            assert dealer_id == self.my_id, "Only dealer can share values."
        # If `values` is not passed then the node is a 'Recipient'
        # Verify that the `dealer_id` is not the same as `self.my_id`
        elif dealer_id is not None:
            assert dealer_id != self.my_id
        assert type(avss_id) is int

        n = self.n
        rbctag = f"{dealer_id}-{avss_id}-B-RBC"
        acsstag = f"{dealer_id}-{avss_id}-B-AVSS"

        self.tagvars[acsstag] = {}
        self.tagvars[acsstag]['tasks'] = []

        broadcast_msg = None
        if self.my_id == dealer_id:
            # 这里的做法是把每个节点的份额用那个节点的公钥加密，然后打包在一起，放到 broadcast_msg 这个消息里，通过广播信道广播出去
            broadcast_msg = self._get_dealer_msg(values, n)

        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        logger.debug("[%d] Starting reliable broadcast", self.my_id)

        async def predicate(_m):
            dispersal_msg, commits, ephkey = self.decode_proposal(_m)
            # print(f"original avss my id: {self.my_id} dealer id: {dealer_id}")
            return self.verify_proposal(dealer_id, dispersal_msg, commits, ephkey)
        
        output = asyncio.Queue()
        asyncio.create_task(
        optqrbc(
            rbctag,
            self.my_id,
            self.n,
            self.t,
            dealer_id,
            predicate,
            broadcast_msg,
            output.put_nowait,
            send,
            recv,
        ))
        rbc_msg = await output.get()

        # avss processing
        # logger.debug("starting acss")
        await self._process_avss_msg(avss_id, dealer_id, rbc_msg)
        
        for task in self.tagvars[acsstag]['tasks']:
            task.cancel()
        self.tagvars[acsstag] = {}
        del self.tagvars[acsstag]

   
    async def avss_trans(self, avss_id, len_values, values=None, dealer_id=None):
        """
        An acss with share recovery
        """
        # If `values` is passed then the node is a 'Sender'
        # `dealer_id` must be equal to `self.my_id`
        # 这里存的是各方广播的 masked values
        if values is not None:
            if dealer_id is None:
                dealer_id = self.my_id
            assert dealer_id == self.my_id, "Only dealer can share values."
        # If `values` is not passed then the node is a 'Recipient'
        # Verify that the `dealer_id` is not the same as `self.my_id`
        elif dealer_id is not None:
            assert dealer_id != self.my_id
        assert type(avss_id) is int

        self.len_values = len_values
        n = self.n
        rbctag = f"{dealer_id}-{avss_id}-B-RBC"
        acsstag = f"{dealer_id}-{avss_id}-B-AVSS"

        self.tagvars[acsstag] = {}
        self.tagvars[acsstag]['tasks'] = []

        broadcast_msg = None
        if self.my_id == dealer_id:
            # 这里的做法是把每个节点的份额用那个节点的公钥加密，然后打包在一起，放到 broadcast_msg 这个消息里，通过广播信道广播出去
            # broadcast_msg = self._get_dealer_msg_trans(values, n)
            broadcast_msg = self._get_dealer_msg_trans(values, n)

        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        logger.debug("[%d] Starting reliable broadcast", self.my_id)

        async def predicate(_m):
            dispersal_msg, commits, ephkey = self.decode_proposal_trans(_m)
            # print(f"protocol trans my id: {self.my_id} dealer id: {dealer_id}")
            return self.verify_proposal_trans(dealer_id, dispersal_msg, commits, ephkey)
        
        output = asyncio.Queue()
        asyncio.create_task(
        optqrbc(
            rbctag,
            self.my_id,
            self.n,
            self.t,
            dealer_id,
            predicate,
            broadcast_msg,
            output.put_nowait,
            send,
            recv,
        ))
        rbc_msg = await output.get()

        # avss processing
        # logger.debug("starting acss")
        await self._process_avss_msg_trans(avss_id, dealer_id, rbc_msg)
        
        for task in self.tagvars[acsstag]['tasks']:
            task.cancel()
        self.tagvars[acsstag] = {}
        del self.tagvars[acsstag]

    async def avss_aprep(self, avss_id, values=None, dealer_id=None):
        """
        An acss with share recovery
        """
        # If `values` is passed then the node is a 'Sender'
        # `dealer_id` must be equal to `self.my_id`
        if values is not None:
            if dealer_id is None:
                dealer_id = self.my_id
            assert dealer_id == self.my_id, "Only dealer can share values."
        # If `values` is not passed then the node is a 'Recipient'
        # Verify that the `dealer_id` is not the same as `self.my_id`
        elif dealer_id is not None:
            assert dealer_id != self.my_id
        assert type(avss_id) is int

        n = self.n
        rbctag = f"{dealer_id}-{avss_id}-B-RBC"
        acsstag = f"{dealer_id}-{avss_id}-B-AVSS"

        self.tagvars[acsstag] = {}
        self.tagvars[acsstag]['tasks'] = []

        broadcast_msg = None
        if self.my_id == dealer_id:
            # 这里的做法是把每个节点的份额用那个节点的公钥加密，然后打包在一起，放到 broadcast_msg 这个消息里，通过广播信道广播出去
            broadcast_msg = self._get_dealer_msg_aprep(values, n)

        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        logger.debug("[%d] Starting reliable broadcast", self.my_id)

        async def predicate(_m):
            dispersal_msg, commits, ephkey = self.decode_proposal_aprep(_m)
            # print(f"protocol aprep my id: {self.my_id} dealer id: {dealer_id}")
            return self.verify_proposal_aprep(dealer_id, dispersal_msg, commits, ephkey)
        
        output = asyncio.Queue()
        asyncio.create_task(
        optqrbc(
            rbctag,
            self.my_id,
            self.n,
            self.t,
            dealer_id,
            predicate,
            broadcast_msg,
            output.put_nowait,
            send,
            recv,
        ))
        rbc_msg = await output.get()

        await self._process_avss_msg_aprep(avss_id, dealer_id, rbc_msg)
        
        for task in self.tagvars[acsstag]['tasks']:
            task.cancel()
        self.tagvars[acsstag] = {}
        del self.tagvars[acsstag]

# ACSS_Pre:用来做广播之前的所有事情（包括广播）
class ACSS_Pre(ACSS):
    def __init__(self, public_keys, g, h, n, t, deg, sc, my_id, send, recv, pc, field, G1, mpc_instance, private_key=None, rbc_values=None):
        
        # 增加了一个属性self.rand_instance，用来指向 Rand 实例
        self.mpc_instance = mpc_instance

        # 可以调用父类的 __init__ 来继承原始类的行为
        super().__init__(public_keys, private_key, g, h, n, t, deg, sc, my_id, send, recv, pc, field, G1, rbc_values)

    # 在这部分中，本层committee只需要做到用公钥加密待传递的消息，并把消息广播给下一层committe就好。
    async def avss_aprep(self, avss_id, values=None, dealer_id=None):
        # If `values` is passed then the node is a 'Sender'
        # `dealer_id` must be equal to `self.my_id`
        if values is not None:
            if dealer_id is None:
                dealer_id = self.my_id
            assert dealer_id == self.my_id, "Only dealer can share values."
        # If `values` is not passed then the node is a 'Recipient'
        # Verify that the `dealer_id` is not the same as `self.my_id`
        elif dealer_id is not None:
            assert dealer_id != self.my_id
        assert type(avss_id) is int

        n = self.n
        rbctag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID + 1}-B-RBC"
        acsstag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID + 1}-B-AVSS"

        broadcast_msg = None
        if self.my_id == dealer_id:
            # 这里的做法是把每个节点的份额用那个节点的公钥加密，然后打包在一起，放到 broadcast_msg 这个消息里，通过广播信道广播出去
            broadcast_msg = self._get_dealer_msg_aprep(values, n)

        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        logger.debug("[%d] Starting reliable broadcast", self.my_id)

        async def predicate(_m):
            # print(f"my layer ID: {self.mpc_instance.layer_ID} rbctag: {rbctag}, send: {send}, recv: {recv}")
            dispersal_msg, commits, ephkey = self.decode_proposal_aprep(_m)
            return self.verify_proposal_aprep(dealer_id, dispersal_msg, commits, ephkey)
        
        output = asyncio.Queue()

        # 把信号放入mpcnode 中
        my_mpc_instance = self.mpc_instance
        admpc_control_instance = self.mpc_instance.admpc_control_instance

        member_list = [(self.mpc_instance.layer_ID) * self.n + self.my_id]
        for i in range(self.n): 
            member_list.append(n * (self.mpc_instance.layer_ID + 1) + i)
        asyncio.create_task(
        optqrbc_dynamic(
            rbctag,
            self.my_id,
            self.n+1,
            self.t,
            self.my_id,
            predicate,
            broadcast_msg,
            output.put_nowait,
            send,
            recv,
            member_list
        ))
    
    async def avss_trans(self, avss_id, values=None, dealer_id=None):
        # If `values` is passed then the node is a 'Sender'
        # `dealer_id` must be equal to `self.my_id`
        if values is not None:
            if dealer_id is None:
                dealer_id = self.my_id
            assert dealer_id == self.my_id, "Only dealer can share values."
        # If `values` is not passed then the node is a 'Recipient'
        # Verify that the `dealer_id` is not the same as `self.my_id`
        elif dealer_id is not None:
            assert dealer_id != self.my_id
        assert type(avss_id) is int

        self.len_values = len(values[0])
        n = self.n
        rbctag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID + 1}-B-RBC"

        broadcast_msg = None
        if self.my_id == dealer_id:
            # 这里的做法是把每个节点的份额用那个节点的公钥加密，然后打包在一起，放到 broadcast_msg 这个消息里，通过广播信道广播出去
            broadcast_msg = self._get_dealer_msg_trans(values, n)

        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        logger.debug("[%d] Starting reliable broadcast", self.my_id)

        async def predicate(_m):
            # print(f"my layer ID: {self.mpc_instance.layer_ID} my id: {self.my_id}")
            dispersal_msg, commits, ephkey = self.decode_proposal_trans(_m)
            return self.verify_proposal_trans(dealer_id, dispersal_msg, commits, ephkey)
        
        output = asyncio.Queue()

        # 把信号放入mpcnode 中
        my_mpc_instance = self.mpc_instance
        admpc_control_instance = self.mpc_instance.admpc_control_instance

        member_list = [(self.mpc_instance.layer_ID) * self.n + self.my_id]
        for i in range(self.n): 
            member_list.append(n * (self.mpc_instance.layer_ID + 1) + i)
        asyncio.create_task(
        optqrbc_dynamic(
            rbctag,
            self.my_id,
            self.n+1,
            self.t,
            self.my_id,
            predicate,
            broadcast_msg,
            output.put_nowait,
            send,
            recv,
            member_list
        ))
    
    
    async def avss(self, avss_id, values=None, dealer_id=None):
        # If `values` is passed then the node is a 'Sender'
        # `dealer_id` must be equal to `self.my_id`
        if values is not None:
            if dealer_id is None:
                dealer_id = self.my_id
            assert dealer_id == self.my_id, "Only dealer can share values."
        # If `values` is not passed then the node is a 'Recipient'
        # Verify that the `dealer_id` is not the same as `self.my_id`
        elif dealer_id is not None:
            assert dealer_id != self.my_id
        assert type(avss_id) is int

        n = self.n
        rbctag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID + 1}-B-RBC"
        acsstag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID + 1}-B-AVSS"

        broadcast_msg = None
        if self.my_id == dealer_id:
            # 这里的做法是把每个节点的份额用那个节点的公钥加密，然后打包在一起，放到 broadcast_msg 这个消息里，通过广播信道广播出去
            broadcast_msg = self._get_dealer_msg(values, n)

        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        logger.debug("[%d] Starting reliable broadcast", self.my_id)

        async def predicate(_m):
            # print(f"my layer ID: {self.mpc_instance.layer_ID} rbctag: {rbctag}, send: {send}, recv: {recv}")
            dispersal_msg, commits, ephkey = self.decode_proposal(_m)
            return self.verify_proposal(dealer_id, dispersal_msg, commits, ephkey)
        
        output = asyncio.Queue()

        # 把信号放入mpcnode 中
        my_mpc_instance = self.mpc_instance
        admpc_control_instance = self.mpc_instance.admpc_control_instance

        member_list = [(self.mpc_instance.layer_ID) * self.n + self.my_id]
        for i in range(self.n): 
            member_list.append(n * (self.mpc_instance.layer_ID + 1) + i)
        asyncio.create_task(
        optqrbc_dynamic(
            rbctag,
            self.my_id,
            self.n+1,
            self.t,
            self.my_id,
            predicate,
            broadcast_msg,
            output.put_nowait,
            send,
            recv,
            member_list
        ))



# ACSS_Foll:用来做收到广播之后的所有事情
class ACSS_Foll(ACSS):
    def __init__(self, public_keys, private_key, g, h, n, t, deg, sc, my_id, send, recv, pc, field, G1, mpc_instance, rbc_values=None):
        self.mpc_instance = mpc_instance
        if rbc_values is not None: 
            self.rbc_values = rbc_values

        # 可以调用父类的 __init__ 来继承原始类的行为
        super().__init__(public_keys, private_key, g, h, n, t, deg, sc, my_id, send, recv, pc, field, G1, rbc_values)

    async def _process_avss_msg_dynamic(self, avss_id, dealer_id, rbc_msg):
        tag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID}-B-AVSS"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)
        self._init_recovery_vars(tag)

        multi_list = []
        for i in range(self.n): 
            multi_list.append(i + (self.mpc_instance.layer_ID) * self.n)

        def multicast(msg):
            for i in range(self.n):
                send(multi_list[i], msg)

        self.tagvars[tag]['io'] = [send, recv, multicast]
        self.tagvars[tag]['in_share_recovery'] = False
                
        ok_set = set()
        implicate_set = set()
        output = False

        self.tagvars[tag]['all_shares_valid'] = self._handle_dealer_msgs(tag, dealer_id)

        if self.tagvars[tag]['all_shares_valid']:
            # 每个节点的 shares 存在这里
            shares = {'msg': self.tagvars[tag]['shares'][0], 'rand':self.tagvars[tag]['shares'][1]}
            commitments = self.tagvars[tag]['commitments']
            # 这里测试一下
            self.output_queue.put_nowait((dealer_id, avss_id, shares, commitments))
            output = True
            logger.debug("[%d] Output", self.my_id)
            multicast((HbAVSSMessageType.OK, ""))
            return (dealer_id, avss_id, shares, commitments)
        else:
            multicast((HbAVSSMessageType.IMPLICATE, self.private_key))
            implicate_sent = True
            logger.debug("Implicate Sent [%d]", dealer_id)
            self.tagvars[tag]['in_share_recovery'] = True
        

        while True:
            # Bracha-style agreement
            sender, avss_msg = await recv()

            # IMPLICATE
            if avss_msg[0] == HbAVSSMessageType.IMPLICATE and not self.tagvars[tag]['in_share_recovery']:
                if sender not in implicate_set:
                    implicate_set.add(sender)
                    logger.debug("Handling Implicate Message [%d]", dealer_id)
                    # validate the implicate
                    #todo: implicate should be forwarded to others if we haven't sent one
                    if await self._handle_implication(tag, sender, avss_msg[1]):
                        # proceed to share recovery
                        logger.debug("Handle implication called [%d]", dealer_id)
                        self.tagvars[tag]['in_share_recovery'] = True
                        await self._handle_share_recovery(tag)
                        logger.debug("[%d] after implication", self.my_id)

            #todo find a more graceful way to handle different protocols having different recovery message types
            if avss_msg[0] in [HbAVSSMessageType.KDIBROADCAST, HbAVSSMessageType.RECOVERY1, HbAVSSMessageType.RECOVERY2]:
                await self._handle_share_recovery(tag, sender, avss_msg)
            # OK
            if avss_msg[0] == HbAVSSMessageType.OK and sender not in ok_set:
                # logger.debug("[%d] Received OK from [%d]", self.my_id, sender)
                ok_set.add(sender)

            # The only condition where we can terminate
            if (len(ok_set) == 3 * self.t + 1) and output:
                logger.debug("[%d] exit", self.my_id)
                break
    
    
    async def avss_aprep(self, avss_id, dealer_id, cm):
        self.cm = cm
        if dealer_id is None:
            dealer_id = self.my_id

        # admpc_control_instance 是控制所有 MPC 实例的对象
        admpc_control_instance = self.mpc_instance.admpc_control_instance
        my_mpc_instance = self.mpc_instance

        async def predicate(_m):
            # print(f"my layer ID: {self.mpc_instance.layer_ID}")
            predicate_time = time.time()
            dispersal_msg, commits, ephkey = self.decode_proposal_aprep(_m)
            # print(f"my layer ID: {self.mpc_instance.layer_ID} my id: {self.my_id} dealer id: {dealer_id}")
            flag = self.verify_proposal_aprep(dealer_id, dispersal_msg, commits, ephkey)
            predicate_time = time.time() - predicate_time
            print(f"predicate_time: {predicate_time}")
            return flag

        # 下一层也运行optrbc ，接受到上一层optrbc的结果
        # 改变一下 rbctag 进行测试
        rbctag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID}-B-RBC"
        acsstag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID}-B-AVSS"

        self.tagvars[acsstag] = {}
        self.tagvars[acsstag]['tasks'] = []

        output = asyncio.Queue()
        broadcast_msg = None
        
        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        # 没看懂这里的 signal 设置的意义
        # await signal.wait()
        # 重点！！这里的 my_id 要修改一下，不然会跟 上一层的 dealer_id 重合，导致 rbc过程失效

        member_list = [(self.mpc_instance.layer_ID - 1) * self.n + dealer_id]
        for i in range(self.n): 
            member_list.append(self.n * (self.mpc_instance.layer_ID) + i)
        if self.my_id < dealer_id: 
            asyncio.create_task(
            optqrbc_dynamic(
                rbctag,
                self.my_id,
                self.n+1,
                self.t,
                dealer_id,
                predicate,
                broadcast_msg,
                output.put_nowait,
                send,
                recv,
                member_list
            ))
        else: 
            asyncio.create_task(
            optqrbc_dynamic(
                rbctag,
                self.my_id+1,
                self.n+1,
                self.t,
                dealer_id,
                predicate,
                broadcast_msg,
                output.put_nowait,
                send,
                recv,
                member_list
            ))

        # signal = admpc_control_instance.admpc_lists[my_mpc_instance.layer_ID - 1][dealer_id].Signal

        rbc_msg = await output.get()

        # avss processing
        (dealer, _, shares, commitments) = await self._process_avss_msg_dynamic(avss_id, dealer_id, rbc_msg)
        return (dealer, _, shares, commitments)
        
        # for task in self.tagvars[acsstag]['tasks']:
        #     task.cancel()
        # self.tagvars[acsstag] = {}
        # del self.tagvars[acsstag]
    
    async def avss_trans(self, avss_id, dealer_id, len_values):
        self.len_values = len_values

        # admpc_control_instance 是控制所有 MPC 实例的对象
        admpc_control_instance = self.mpc_instance.admpc_control_instance
        my_mpc_instance = self.mpc_instance

        async def predicate(_m):
            # print(f"my layer ID: {self.mpc_instance.layer_ID}")
            dispersal_msg, commits, ephkey = self.decode_proposal_trans(_m)
            # print(f"my layer ID: {self.mpc_instance.layer_ID} my id: {self.my_id} dealer id: {dealer_id}")
            return self.verify_proposal_trans(dealer_id, dispersal_msg, commits, ephkey)

        # 下一层也运行optrbc ，接受到上一层optrbc的结果
        # 改变一下 rbctag 进行测试
        rbctag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID}-B-RBC"
        acsstag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID}-B-AVSS"

        self.tagvars[acsstag] = {}
        self.tagvars[acsstag]['tasks'] = []

        output = asyncio.Queue()
        broadcast_msg = None
        
        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        # 没看懂这里的 signal 设置的意义
        # await signal.wait()
        # 重点！！这里的 my_id 要修改一下，不然会跟 上一层的 dealer_id 重合，导致 rbc过程失效

        member_list = [(self.mpc_instance.layer_ID - 1) * self.n + dealer_id]
        for i in range(self.n): 
            member_list.append(self.n * (self.mpc_instance.layer_ID) + i)
        if self.my_id < dealer_id: 
            asyncio.create_task(
            optqrbc_dynamic(
                rbctag,
                self.my_id,
                self.n+1,
                self.t,
                dealer_id,
                predicate,
                broadcast_msg,
                output.put_nowait,
                send,
                recv,
                member_list
            ))
        else: 
            asyncio.create_task(
            optqrbc_dynamic(
                rbctag,
                self.my_id+1,
                self.n+1,
                self.t,
                dealer_id,
                predicate,
                broadcast_msg,
                output.put_nowait,
                send,
                recv,
                member_list
            ))

        # signal = admpc_control_instance.admpc_lists[my_mpc_instance.layer_ID - 1][dealer_id].Signal

        rbc_msg = await output.get()

        # avss processing
        (dealer, _, shares, commitments) = await self._process_avss_msg_dynamic(avss_id, dealer_id, rbc_msg)
        return (dealer, _, shares, commitments)
        
        # for task in self.tagvars[acsstag]['tasks']:
        #     task.cancel()
        # self.tagvars[acsstag] = {}
        # del self.tagvars[acsstag]
    
    
    # 下一层committee只需要接受上一层发来的广播，接着处理即可
    async def avss(self, avss_id, dealer_id, rounds):
        if dealer_id is None:
            dealer_id = self.my_id

        # admpc_control_instance 是控制所有 MPC 实例的对象
        admpc_control_instance = self.mpc_instance.admpc_control_instance
        my_mpc_instance = self.mpc_instance

        self.rand_num = rounds
        async def predicate(_m):
            # print(f"my layer ID: {self.mpc_instance.layer_ID}")
            acss_decode_time = time.time()
            dispersal_msg, commits, ephkey = self.decode_proposal(_m)
            acss_decode_time = time.time() - acss_decode_time
            print(f"acss_decode_time: {acss_decode_time}")

            # print(f"my layer ID: {self.mpc_instance.layer_ID} my id: {self.my_id} dealer id: {dealer_id}")
            acss_verify_time = time.time()
            res = self.verify_proposal(dealer_id, dispersal_msg, commits, ephkey)
            acss_verify_time = time.time() - acss_verify_time
            print(f"acss_verify_time: {acss_verify_time}")
            return res

        # 下一层也运行optrbc ，接受到上一层optrbc的结果
        # 改变一下 rbctag 进行测试
        rbctag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID}-B-RBC"
        acsstag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID}-B-AVSS"

        self.tagvars[acsstag] = {}
        self.tagvars[acsstag]['tasks'] = []

        output = asyncio.Queue()
        broadcast_msg = None
        
        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        # 没看懂这里的 signal 设置的意义
        # await signal.wait()
        # 重点！！这里的 my_id 要修改一下，不然会跟 上一层的 dealer_id 重合，导致 rbc过程失效

        member_list = [(self.mpc_instance.layer_ID - 1) * self.n + dealer_id]
        for i in range(self.n): 
            member_list.append(self.n * (self.mpc_instance.layer_ID) + i)
        if self.my_id < dealer_id: 
            asyncio.create_task(
            optqrbc_dynamic(
                rbctag,
                self.my_id,
                self.n+1,
                self.t,
                dealer_id,
                predicate,
                broadcast_msg,
                output.put_nowait,
                send,
                recv,
                member_list
            ))
        else: 
            asyncio.create_task(
            optqrbc_dynamic(
                rbctag,
                self.my_id+1,
                self.n+1,
                self.t,
                dealer_id,
                predicate,
                broadcast_msg,
                output.put_nowait,
                send,
                recv,
                member_list
            ))

        # signal = admpc_control_instance.admpc_lists[my_mpc_instance.layer_ID - 1][dealer_id].Signal

        acss_rbc_time = time.time()
        rbc_msg = await output.get()
        acss_rbc_time = time.time() - acss_rbc_time
        print(f"acss_rbc_time: {acss_rbc_time}")

        # avss processing
        acss_process_time = time.time()
        (dealer, _, shares, commitments) = await self._process_avss_msg_dynamic(avss_id, dealer_id, rbc_msg)
        acss_process_time = time.time() - acss_process_time
        print(f"acss_process_time: {acss_process_time}")
        return (dealer, _, shares, commitments)
        
        # for task in self.tagvars[acsstag]['tasks']:
        #     task.cancel()
        # self.tagvars[acsstag] = {}
        # del self.tagvars[acsstag]



class ACSS_Fluid_Pre(ACSS):
    def __init__(self, public_keys, g, h, n, t, deg, sc, my_id, send, recv, pc, field, G1, mpc_instance, private_key=None, rbc_values=None):
        
        # 增加了一个属性self.rand_instance，用来指向 Rand 实例
        self.mpc_instance = mpc_instance

        # 可以调用父类的 __init__ 来继承原始类的行为
        super().__init__(public_keys, private_key, g, h, n, t, deg, sc, my_id, send, recv, pc, field, G1, rbc_values)

    # 在这部分中，本层committee只需要做到用公钥加密待传递的消息，并把消息广播给下一层committe就好。
    async def avss_aprep(self, avss_id, values=None, dealer_id=None):
        # If `values` is passed then the node is a 'Sender'
        # `dealer_id` must be equal to `self.my_id`
        if values is not None:
            if dealer_id is None:
                dealer_id = self.my_id
            assert dealer_id == self.my_id, "Only dealer can share values."
        # If `values` is not passed then the node is a 'Recipient'
        # Verify that the `dealer_id` is not the same as `self.my_id`
        elif dealer_id is not None:
            assert dealer_id != self.my_id
        assert type(avss_id) is int

        n = self.n
        rbctag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID + 1}-B-RBC"
        acsstag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID + 1}-B-AVSS"

        broadcast_msg = None
        if self.my_id == dealer_id:
            # 这里的做法是把每个节点的份额用那个节点的公钥加密，然后打包在一起，放到 broadcast_msg 这个消息里，通过广播信道广播出去
            broadcast_msg = self._get_dealer_msg_aprep(values, n)

        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        logger.debug("[%d] Starting reliable broadcast", self.my_id)

        async def predicate(_m):
            # print(f"my layer ID: {self.mpc_instance.layer_ID} rbctag: {rbctag}, send: {send}, recv: {recv}")
            dispersal_msg, commits, ephkey = self.decode_proposal_aprep(_m)
            return self.verify_proposal_aprep(dealer_id, dispersal_msg, commits, ephkey)
        
        output = asyncio.Queue()

        # 把信号放入mpcnode 中
        my_mpc_instance = self.mpc_instance
        admpc_control_instance = self.mpc_instance.admpc_control_instance

        member_list = [(self.mpc_instance.layer_ID) * self.n + self.my_id]
        for i in range(self.n): 
            member_list.append(n * (self.mpc_instance.layer_ID + 1) + i)
        asyncio.create_task(
        optqrbc_dynamic(
            rbctag,
            self.my_id,
            self.n+1,
            self.t,
            self.my_id,
            predicate,
            broadcast_msg,
            output.put_nowait,
            send,
            recv,
            member_list
        ))
    
    async def avss_trans(self, avss_id, values=None, dealer_id=None):
        # If `values` is passed then the node is a 'Sender'
        # `dealer_id` must be equal to `self.my_id`
        if values is not None:
            if dealer_id is None:
                dealer_id = self.my_id
            assert dealer_id == self.my_id, "Only dealer can share values."
        # If `values` is not passed then the node is a 'Recipient'
        # Verify that the `dealer_id` is not the same as `self.my_id`
        elif dealer_id is not None:
            assert dealer_id != self.my_id
        assert type(avss_id) is int

        self.len_values = len(values[0])
        n = self.n
        rbctag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID + 1}-B-RBC"

        broadcast_msg = None
        if self.my_id == dealer_id:
            # 这里的做法是把每个节点的份额用那个节点的公钥加密，然后打包在一起，放到 broadcast_msg 这个消息里，通过广播信道广播出去
            broadcast_msg = self._get_dealer_msg_trans(values, n)

        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        logger.debug("[%d] Starting reliable broadcast", self.my_id)

        async def predicate(_m):
            return True
        
        output = asyncio.Queue()

        # 把信号放入mpcnode 中
        my_mpc_instance = self.mpc_instance
        admpc_control_instance = self.mpc_instance.admpc_control_instance

        member_list = [(self.mpc_instance.layer_ID) * self.n + self.my_id]
        for i in range(self.n): 
            member_list.append(n * (self.mpc_instance.layer_ID + 1) + i)
        asyncio.create_task(
        optqrbc_dynamic(
            rbctag,
            self.my_id,
            self.n+1,
            self.t,
            self.my_id,
            predicate,
            broadcast_msg,
            output.put_nowait,
            send,
            recv,
            member_list
        ))
    
    
    async def avss(self, avss_id, values=None, dealer_id=None):
        # If `values` is passed then the node is a 'Sender'
        # `dealer_id` must be equal to `self.my_id`
        if values is not None:
            if dealer_id is None:
                dealer_id = self.my_id
            assert dealer_id == self.my_id, "Only dealer can share values."
        # If `values` is not passed then the node is a 'Recipient'
        # Verify that the `dealer_id` is not the same as `self.my_id`
        elif dealer_id is not None:
            assert dealer_id != self.my_id
        assert type(avss_id) is int

        n = self.n
        rbctag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID + 1}-B-RBC"
        acsstag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID + 1}-B-AVSS"

        broadcast_msg = None
        if self.my_id == dealer_id:
            # 这里的做法是把每个节点的份额用那个节点的公钥加密，然后打包在一起，放到 broadcast_msg 这个消息里，通过广播信道广播出去
            broadcast_msg = self._get_dealer_msg(values, n)

        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        logger.debug("[%d] Starting reliable broadcast", self.my_id)

        async def predicate(_m):
            return True
        
        output = asyncio.Queue()

        # 把信号放入mpcnode 中
        my_mpc_instance = self.mpc_instance
        admpc_control_instance = self.mpc_instance.admpc_control_instance

        member_list = [(self.mpc_instance.layer_ID) * self.n + self.my_id]
        for i in range(self.n): 
            member_list.append(n * (self.mpc_instance.layer_ID + 1) + i)
        asyncio.create_task(
        optqrbc_dynamic(
            rbctag,
            self.my_id,
            self.n+1,
            self.t,
            self.my_id,
            predicate,
            broadcast_msg,
            output.put_nowait,
            send,
            recv,
            member_list
        ))

class ACSS_Fluid_Foll(ACSS):
    def __init__(self, public_keys, private_key, g, h, n, t, deg, sc, my_id, send, recv, pc, field, G1, mpc_instance, rbc_values=None):
        self.mpc_instance = mpc_instance
        if rbc_values is not None: 
            self.rbc_values = rbc_values

        # 可以调用父类的 __init__ 来继承原始类的行为
        super().__init__(public_keys, private_key, g, h, n, t, deg, sc, my_id, send, recv, pc, field, G1, rbc_values)

    async def _process_avss_msg_dynamic(self, avss_id, dealer_id, rbc_msg):
        tag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID}-B-AVSS"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)
        self._init_recovery_vars(tag)

        multi_list = []
        for i in range(self.n): 
            multi_list.append(i + (self.mpc_instance.layer_ID) * self.n)

        def multicast(msg):
            for i in range(self.n):
                send(multi_list[i], msg)

        self.tagvars[tag]['io'] = [send, recv, multicast]
        self.tagvars[tag]['in_share_recovery'] = False
                
        ok_set = set()
        implicate_set = set()
        output = False
        self.tagvars[tag]['all_shares_valid'] = self._handle_dealer_msgs(tag, dealer_id)
        print("self.tagvars[tag]['all_shares_valid']")

        if self.tagvars[tag]['all_shares_valid']:
            # 每个节点的 shares 存在这里
            shares = {'msg': self.tagvars[tag]['shares'][0], 'rand':self.tagvars[tag]['shares'][1]}
            commitments = self.tagvars[tag]['commitments']
            # 这里测试一下
            self.output_queue.put_nowait((dealer_id, avss_id, shares, commitments))
            output = True
            logger.debug("[%d] Output", self.my_id)
            multicast((HbAVSSMessageType.OK, ""))
            return (dealer_id, avss_id, shares, commitments)
        else:
            multicast((HbAVSSMessageType.IMPLICATE, self.private_key))
            implicate_sent = True
            logger.debug("Implicate Sent [%d]", dealer_id)
            self.tagvars[tag]['in_share_recovery'] = True
        

        while True:
            # Bracha-style agreement
            sender, avss_msg = await recv()

            # IMPLICATE
            if avss_msg[0] == HbAVSSMessageType.IMPLICATE and not self.tagvars[tag]['in_share_recovery']:
                if sender not in implicate_set:
                    implicate_set.add(sender)
                    logger.debug("Handling Implicate Message [%d]", dealer_id)
                    # validate the implicate
                    #todo: implicate should be forwarded to others if we haven't sent one
                    if await self._handle_implication(tag, sender, avss_msg[1]):
                        # proceed to share recovery
                        logger.debug("Handle implication called [%d]", dealer_id)
                        self.tagvars[tag]['in_share_recovery'] = True
                        await self._handle_share_recovery(tag)
                        logger.debug("[%d] after implication", self.my_id)

            #todo find a more graceful way to handle different protocols having different recovery message types
            if avss_msg[0] in [HbAVSSMessageType.KDIBROADCAST, HbAVSSMessageType.RECOVERY1, HbAVSSMessageType.RECOVERY2]:
                await self._handle_share_recovery(tag, sender, avss_msg)
            # OK
            if avss_msg[0] == HbAVSSMessageType.OK and sender not in ok_set:
                # logger.debug("[%d] Received OK from [%d]", self.my_id, sender)
                ok_set.add(sender)

            # The only condition where we can terminate
            if (len(ok_set) == 3 * self.t + 1) and output:
                logger.debug("[%d] exit", self.my_id)
                break
    
    
    async def avss_aprep(self, avss_id, dealer_id, cm):
        self.cm = cm
        if dealer_id is None:
            dealer_id = self.my_id

        # admpc_control_instance 是控制所有 MPC 实例的对象
        admpc_control_instance = self.mpc_instance.admpc_control_instance
        my_mpc_instance = self.mpc_instance

        async def predicate(_m):
            # print(f"my layer ID: {self.mpc_instance.layer_ID}")
            predicate_time = time.time()
            dispersal_msg, commits, ephkey = self.decode_proposal_aprep(_m)
            # print(f"my layer ID: {self.mpc_instance.layer_ID} my id: {self.my_id} dealer id: {dealer_id}")
            flag = self.verify_proposal_aprep(dealer_id, dispersal_msg, commits, ephkey)
            predicate_time = time.time() - predicate_time
            print(f"predicate_time: {predicate_time}")
            return flag

        # 下一层也运行optrbc ，接受到上一层optrbc的结果
        # 改变一下 rbctag 进行测试
        rbctag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID}-B-RBC"
        acsstag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID}-B-AVSS"

        self.tagvars[acsstag] = {}
        self.tagvars[acsstag]['tasks'] = []

        output = asyncio.Queue()
        broadcast_msg = None
        
        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        # 没看懂这里的 signal 设置的意义
        # await signal.wait()
        # 重点！！这里的 my_id 要修改一下，不然会跟 上一层的 dealer_id 重合，导致 rbc过程失效

        member_list = [(self.mpc_instance.layer_ID - 1) * self.n + dealer_id]
        for i in range(self.n): 
            member_list.append(self.n * (self.mpc_instance.layer_ID) + i)
        if self.my_id < dealer_id: 
            asyncio.create_task(
            optqrbc_dynamic(
                rbctag,
                self.my_id,
                self.n+1,
                self.t,
                dealer_id,
                predicate,
                broadcast_msg,
                output.put_nowait,
                send,
                recv,
                member_list
            ))
        else: 
            asyncio.create_task(
            optqrbc_dynamic(
                rbctag,
                self.my_id+1,
                self.n+1,
                self.t,
                dealer_id,
                predicate,
                broadcast_msg,
                output.put_nowait,
                send,
                recv,
                member_list
            ))

        # signal = admpc_control_instance.admpc_lists[my_mpc_instance.layer_ID - 1][dealer_id].Signal

        rbc_msg = await output.get()

        # avss processing
        (dealer, _, shares, commitments) = await self._process_avss_msg_dynamic(avss_id, dealer_id, rbc_msg)
        return (dealer, _, shares, commitments)
        
        # for task in self.tagvars[acsstag]['tasks']:
        #     task.cancel()
        # self.tagvars[acsstag] = {}
        # del self.tagvars[acsstag]
    
    async def avss_trans(self, avss_id, dealer_id, len_values):
        self.len_values = len_values

        # admpc_control_instance 是控制所有 MPC 实例的对象
        admpc_control_instance = self.mpc_instance.admpc_control_instance
        my_mpc_instance = self.mpc_instance

        async def predicate(_m):
            # print(f"my layer ID: {self.mpc_instance.layer_ID}")
            dispersal_msg, commits, ephkey = self.decode_proposal_trans(_m)
            # print(f"my layer ID: {self.mpc_instance.layer_ID} my id: {self.my_id} dealer id: {dealer_id}")
            return self.verify_proposal_trans(dealer_id, dispersal_msg, commits, ephkey)

        # 下一层也运行optrbc ，接受到上一层optrbc的结果
        # 改变一下 rbctag 进行测试
        rbctag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID}-B-RBC"
        acsstag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID}-B-AVSS"

        self.tagvars[acsstag] = {}
        self.tagvars[acsstag]['tasks'] = []

        output = asyncio.Queue()
        broadcast_msg = None
        
        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        # 没看懂这里的 signal 设置的意义
        # await signal.wait()
        # 重点！！这里的 my_id 要修改一下，不然会跟 上一层的 dealer_id 重合，导致 rbc过程失效

        member_list = [(self.mpc_instance.layer_ID - 1) * self.n + dealer_id]
        for i in range(self.n): 
            member_list.append(self.n * (self.mpc_instance.layer_ID) + i)
        if self.my_id < dealer_id: 
            asyncio.create_task(
            optqrbc_dynamic(
                rbctag,
                self.my_id,
                self.n+1,
                self.t,
                dealer_id,
                predicate,
                broadcast_msg,
                output.put_nowait,
                send,
                recv,
                member_list
            ))
        else: 
            asyncio.create_task(
            optqrbc_dynamic(
                rbctag,
                self.my_id+1,
                self.n+1,
                self.t,
                dealer_id,
                predicate,
                broadcast_msg,
                output.put_nowait,
                send,
                recv,
                member_list
            ))

        # signal = admpc_control_instance.admpc_lists[my_mpc_instance.layer_ID - 1][dealer_id].Signal

        rbc_msg = await output.get()

        # avss processing
        (dealer, _, shares, commitments) = await self._process_avss_msg_dynamic(avss_id, dealer_id, rbc_msg)
        return (dealer, _, shares, commitments)
        
        # for task in self.tagvars[acsstag]['tasks']:
        #     task.cancel()
        # self.tagvars[acsstag] = {}
        # del self.tagvars[acsstag]
    
    
    # 下一层committee只需要接受上一层发来的广播，接着处理即可
    async def avss(self, avss_id, dealer_id, rounds):
        if dealer_id is None:
            dealer_id = self.my_id

        # admpc_control_instance 是控制所有 MPC 实例的对象
        admpc_control_instance = self.mpc_instance.admpc_control_instance
        my_mpc_instance = self.mpc_instance

        self.rand_num = rounds
        async def predicate(_m):
            # 在 Fluid MPC 这里，我们只是借用异步的广播，但是并不去验证这些 shares 的正确与否，因此所有的 predicate 函数我们都直接
            # return true 就行
            avss_fluid_foll_predicate_time = time.time()
            dispersal_msg, commits, ephkey = self.decode_proposal(_m)

            shared_key = ephkey**self.private_key
        
            try:
                sharesb = SymmetricCrypto.decrypt(shared_key.__getstate__(), dispersal_msg)
            except ValueError as e:  # TODO: more specific exception
                logger.warn(f"Implicate due to failure in decrypting: {e}")
                self.acss_status[dealer_id] = False
                return False
            
            shares = self.sr.deserialize_fs(sharesb)
            print(f"len shares: {len(shares)}")
            print(f"self.rand_num: {self.rand_num}")

            
            
            phis, phis_hat = shares[:self.rand_num], shares[self.rand_num:]
           
            
            self.acss_status[dealer_id] = True
            self.data[dealer_id] = [commits, phis, phis_hat, ephkey, shared_key]
            avss_fluid_foll_predicate_time = time.time() - avss_fluid_foll_predicate_time
            print(f"avss_fluid_foll_predicate_time: {avss_fluid_foll_predicate_time}")
            return True

        # 下一层也运行optrbc ，接受到上一层optrbc的结果
        # 改变一下 rbctag 进行测试
        rbctag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID}-B-RBC"
        acsstag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID}-B-AVSS"

        self.tagvars[acsstag] = {}
        self.tagvars[acsstag]['tasks'] = []

        output = asyncio.Queue()
        broadcast_msg = None
        
        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        # 没看懂这里的 signal 设置的意义
        # await signal.wait()
        # 重点！！这里的 my_id 要修改一下，不然会跟 上一层的 dealer_id 重合，导致 rbc过程失效

        member_list = [(self.mpc_instance.layer_ID - 1) * self.n + dealer_id]
        for i in range(self.n): 
            member_list.append(self.n * (self.mpc_instance.layer_ID) + i)
        if self.my_id < dealer_id: 
            asyncio.create_task(
            optqrbc_dynamic(
                rbctag,
                self.my_id,
                self.n+1,
                self.t,
                dealer_id,
                predicate,
                broadcast_msg,
                output.put_nowait,
                send,
                recv,
                member_list
            ))
        else: 
            asyncio.create_task(
            optqrbc_dynamic(
                rbctag,
                self.my_id+1,
                self.n+1,
                self.t,
                dealer_id,
                predicate,
                broadcast_msg,
                output.put_nowait,
                send,
                recv,
                member_list
            ))

        # signal = admpc_control_instance.admpc_lists[my_mpc_instance.layer_ID - 1][dealer_id].Signal

        acss_rbc_time = time.time()
        rbc_msg = await output.get()
        acss_rbc_time = time.time() - acss_rbc_time
        print(f"acss_rbc_time: {acss_rbc_time}")

        # avss processing
        acss_process_time = time.time()
        (dealer, _, shares, commitments) = await self._process_avss_msg_dynamic(avss_id, dealer_id, rbc_msg)
        acss_process_time = time.time() - acss_process_time
        print(f"acss_process_time: {acss_process_time}")
        print(f"layer ID: {self.mpc_instance.layer_ID} my id: {self.my_id} dealer: {dealer}")
        return (dealer, _, shares, commitments)
        
        # for task in self.tagvars[acsstag]['tasks']:
        #     task.cancel()
        # self.tagvars[acsstag] = {}
        # del self.tagvars[acsstag]

 