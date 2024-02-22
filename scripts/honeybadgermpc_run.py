from adkg.config import HbmpcConfig
from adkg.ipc import ProcessProgramRunner
from adkg.admpc import ADMPC
from adkg.honeybadger_mpc import ADMPC_Multi_Layer_Control, ADMPC
from adkg.poly_commit_hybrid import PolyCommitHybrid
from pypairing import ZR, G1, blsmultiexp as multiexp, dotprod
# from pypairing import Curve25519ZR as ZR, Curve25519G as G1, curve25519multiexp as multiexp, curve25519dotprod as dotprod
import asyncio
import time
import logging
import uvloop
import numpy as np

logger = logging.getLogger("benchmark_logger")
logger.setLevel(logging.ERROR)
# Uncomment this when you want logs from this file.
logger.setLevel(logging.NOTSET)

def get_avss_params(n):
    g, h = G1.rand(b'g'), G1.rand(b'h')
    public_keys, private_keys = [None] * n, [None] * n
    for i in range(n):
        # private_keys[i] = ZR.random()
        private_keys[i] = ZR.hash(str(i).encode())
        public_keys[i] = pow(g, private_keys[i])
    return g, h, public_keys, private_keys


def gen_vector(t, n, ZR):

    vm = np.array([[ZR(i+1)**j for j in range(n)] for i in range(n-t)])

    return (vm.tolist())

async def _run(peers, n, t, k, my_id, start_time, layers, my_send_id, total_cm):
    g, h, pks, sks = get_avss_params(n*layers)
    pc = PolyCommitHybrid(g, h, ZR, multiexp)
    deg = k
    mat = gen_vector(t, n, ZR)
    # 注意这里，在每个委员会中 servers 的编号都是从 0 开始的，因此在生成 send 和 recv 对的时候，要注意转换

    print(f"my_send_id: {my_send_id}")
    async with ProcessProgramRunner(peers, n*layers, t, my_send_id) as runner:
        send, recv = runner.get_send_recv("")
        logging.debug(f"Starting ADMPC: {(my_id)}")
        logging.debug(f"Start time: {(start_time)}, diff {(start_time-int(time.time()))}")

        benchmark_logger = logging.LoggerAdapter(
           logging.getLogger("benchmark_logger"), {"node_id": my_id}
        )
        curve_params = (ZR, G1, multiexp, dotprod)
        layerID = int(my_send_id/n)
        with ADMPC(pks, sks[my_send_id], g, h, n, t, deg, my_id, send, recv, pc, curve_params, mat, total_cm, layers) as admpc: 
            while True:
                if time.time() > start_time:
                    break
                time.sleep(0.1)
            begin_time = time.time()
            logging.info(f"ADMPC start time: {(begin_time)}")
            admpc_task = asyncio.create_task(admpc.run_admpc(begin_time))
            await admpc_task
            # admpc.kill()
            # admpc_task.cancel()
            exec_time = time.time() - begin_time
            print(f"my_send_id: {my_send_id} exec_time: {exec_time}")
            await asyncio.sleep(30)



        
        bytes_sent = runner.node_communicator.bytes_sent
        for k,v in runner.node_communicator.bytes_count.items():
            logging.info(f"[{my_id}] Bytes Sent: {k}:{v} which is {round((100*v)/bytes_sent,3)}%")
        logging.info(f"[{my_id}] Total bytes sent out aa: {bytes_sent}")

if __name__ == "__main__":
    from adkg.config import HbmpcConfig
    logging.info("Running ADMPC ...")
    HbmpcConfig.load_config()

    # admpc_controller = ADMPC_Multi_Layer_Control(HbmpcConfig.N, HbmpcConfig.t, HbmpcConfig.k, HbmpcConfig.layers)

    loop = uvloop.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(
            _run(
                HbmpcConfig.peers,
                HbmpcConfig.N,
                HbmpcConfig.t,
                HbmpcConfig.k,
                HbmpcConfig.my_id,
                HbmpcConfig.time,
                HbmpcConfig.layers, 
                HbmpcConfig.my_send_id,
                HbmpcConfig.total_cm
            )
        )
    finally:
        loop.close()
