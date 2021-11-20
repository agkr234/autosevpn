import subprocess
import time

from ping3 import ping
import sevpn
import sys
import socket
import os
import logging
import json

logging.basicConfig(level=logging.DEBUG, format='%(message)s')
logger = logging.getLogger(__name__)
COUNT = 4
CUR_VPN_ADDR = None
CUR_VPN_PORT = None
LOCAL_HOST = socket.gethostname()
sock = None
LAST_VPNS = []

MAX_PING = 40

ping_table = None
reliable_srvs = None
reliable_srvs_idx = 0
dest_addr = None
net_mask = None

def init(setting):
    global CUR_VPN_ADDR
    global CUR_VPN_PORT
    global LAST_VPNS
    conn = sevpn.get_conn(None)
    cur = conn.cursor()
    #cur.execute('SELECT * FROM guam_view ORDER BY ping_avg ASC ping_ploss ASC last_update DESC')
    cur.execute('SELECT g.addr, g.port, g.ping_avg, g.last_update FROM {} AS g JOIN (select id, addr, MAX(last_update) AS last_update FROM {} GROUP BY addr) AS g2 ON g.addr = g2.addr AND g.last_update = g2.last_update ORDER BY g.ping_avg'.format(ping_table, ping_table))
    vpn_srvs = cur.fetchall()
    for srv in vpn_srvs:
        if srv[0] in LAST_VPNS:
            continue
        res = sevpn.getping(srv[0], COUNT, interface=None, port=srv[1], timeout=1)
        if res[0] != 999:
            if sevpn.connect_vpn({'ip': srv[0], 'port': int(srv[1])}, (setting), check_target_ping):
                CUR_VPN_ADDR = srv[0]
                CUR_VPN_PORT = int(srv[1])
                LAST_VPNS.append(CUR_VPN_ADDR)
                return True
            else:
                sevpn.disconnect_vpn(srv[0])
                continue
    cur.close()
    conn.close()
    return False  # Failed to connect any of the vpns


def check_target_ping(argv):
    s = reliable_srvs[0]
    res = sevpn.getping(s, 10, interface=sevpn.NIC_NAME)
    if res[0] < MAX_PING:
        return True
    return False


def get_reliable_ping_srv():
    global reliable_srvs
    global reliable_srvs_idx
    ping_srv = reliable_srvs[reliable_srvs_idx]
    reliable_srvs_idx = (reliable_srvs_idx + 1) % len(reliable_srvs)
    return ping_srv


def record_target_ping_sql(cur, id, dtime):
    s = reliable_srvs[0]
    res = sevpn.getping(s, COUNT, interface=sevpn.NIC_NAME, timeout=1)
    cur.execute(
        'INSERT INTO {} VALUES ({}, "{}", {}, {}, {}, {}, {}, {}, "{}", "{}")'.format(ping_table, id,
                                                                                             CUR_VPN_ADDR,
                                                                                             CUR_VPN_PORT,
                                                                                             res[0], res[1],
                                                                                             res[2],
                                                                                             res[3], COUNT,
                                                                                             s,
                                                                                             dtime))


def record_vpn_ping_sql(cur, dtime):
    vpn_ping = sevpn.getping(CUR_VPN_ADDR, COUNT, interface=None, port=CUR_VPN_PORT)
    cur.execute('INSERT INTO sevpn_ping VALUES (NULL, "{}", {}, {}, {}, {}, {}, {}, "{}", "{}")'.format(CUR_VPN_ADDR, CUR_VPN_PORT,
                                                                                            vpn_ping[0], vpn_ping[1], vpn_ping[2],
                                                                                            vpn_ping[3], COUNT, "JAPAN", dtime))


def loop_ping():
    ping_srv = get_reliable_ping_srv()
    res = sevpn.getping(ping_srv, COUNT, interface=sevpn.NIC_NAME, timeout=1)
    logger.debug("ping: {} [{}->{}]".format(res[0], CUR_VPN_ADDR, ping_srv))
    if res[0] > MAX_PING:
        for _ in range(len(reliable_srvs)):
            s = get_reliable_ping_srv()
            res = sevpn.getping(s, COUNT, interface=sevpn.NIC_NAME, timeout=1)
            logger.debug("ping: {} [{}->{}]".format(res[0], CUR_VPN_ADDR, s))
            if res[0] > MAX_PING:
                continue
            else:
                break
        else:
            if is_player_in_qwfwd():
                return True
            return False
    return True


def is_player_in_qwfwd():
    sock.sendto(b'\xff\xff\xff\xffstatus 2', ('0.0.0.0', QWFWD_PORT))
    t = time.time()
    while True:
        delta = time.time() - t
        if delta > 10:
            return False
        msg, address = sock.recvfrom(32768)
        if address[0] == "127.0.0.1" and address[1] == QWFWD_PORT:
            if msg[:5] == b"\xff\xff\xff\xffn":
                for b in msg[5:]:
                    if b != b'\x00':
                        return True
                else:
                    return False


if __name__=='__main__':
    try:
        sevpn.init_logger()
        sevpn.get_logger(logger, __name__)
        if len(sys.argv) < 2:
            print("Please specify which config to use")
            exit()
        else:
            ping_table=sevpn.config.get(sys.argv[1], 'ping_table')
            reliable_srvs=json.loads(sevpn.config.get(sys.argv[1], 'reliable'))
            dest_addr=sevpn.config.get(sys.argv[1], 'dest_addr')
            net_mask=sevpn.config.get(sys.argv[1], 'net_mask')
        if len(sys.argv) > 2 and sys.argv[2].isdigit():
            MAX_PING = int(sys.argv[2])

        if len(sys.argv) > 3 and sys.argv[3] == "debug":
            import ptvsd
            print("waiting...")
            ptvsd.enable_attach(address=('0.0.0.0', 5678))
            ptvsd.wait_for_attach()
        QWFWD_PATH = sevpn.config.get('general', 'qwfwd_path')
        QWFWD_PORT = sevpn.config.getint('general', 'qwfwd_port')
        """if len(sys.argv) < 2:
            print("Please type path to qwfwd.bin and qwfwd's port number as arguments")
            exit()
        QWFWD_START_PATH = sys.argv[1]
        if not sys.argv[2].isdigit():
            print('Invalid port number {}'.format(sys.argv[2]))
            exit()
        QWFWD_PORT = int(sys.argv[2])
        if QWFWD_PORT > 65535 or QWFWD_PORT < 1:
            print('Invalid port number: {}'.format(QWFWD_PORT))
            exit()"""
        
        sevpn.init_globalip()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('', 0))
        while True:
            #sevpn.query_oq_table()
            if not init(sys.argv[1]):
                logger.error("couldn't find any vpn to connect")
                exit()
            #p = subprocess.Popen([QWFWD_START_PATH], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run("screen -dmS qwfwd {}/qwfwd_start.sh".format(QWFWD_PATH), shell=True)
            while loop_ping():
                time.sleep(15)
            #p.communicate(input=b'quit\n')
            subprocess.run("screen -S qwfwd -X stuff 'quit^M'", shell=True)
            while os.path.exists('{}/qwfwdrun'.format(QWFWD_PATH)):
                pass
            #p2 = subprocess.Popen(['ps', '-A'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            #p2.wait(timeout=2)
            #p.stdin.write(b'quit\^M')
            #p.stdin.flush()
            sevpn.disconnect_vpn(CUR_VPN_ADDR)
    except Exception:
        logger.debug("Exception", exc_info=True)

