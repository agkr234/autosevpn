import urllib.request
from bs4 import BeautifulSoup
import re
import ping3
import subprocess
import math
from subprocess import PIPE
import shlex
import mysql.connector
import time
from datetime import datetime
import traceback
import sys
import socket
import urllib.request
import copy
import logging
import logging.handlers
import os
import configparser
import json
import argparse

logging.basicConfig(level=logging.DEBUG, format='%(message)s')
logger = logging.getLogger(__name__)
fmt = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s", "%Y-%m-%dT%H:%M:%S")

VPN_CMD = '/usr/vpncmd/vpncmd localhost /CLIENT /CMD'
ACCOUNT_NAME = 'myconnection'
NIC_NAME = 'default'
ACCOUNT_NIC_NAME = 'myadapter'
IP_REQ_ADDR='http://inet-ip.info/ip'
GLOBAL_IP = None
config_secret = configparser.ConfigParser()
config_secret.read('secret.ini', encoding='utf-8')
ACCOUNT = config_secret.get('general', 'account')
PASSWORD = config_secret.get('general', 'password')
DATABASE = config_secret.get('general', 'db')
SQL_ADDR = config_secret.get('general', 'sql_addr')

config = configparser.ConfigParser()
config.read('sevpn.ini', encoding='utf-8')

sevpn_table=config.get('general', 'sevpn_table')
sevpn_failed_table=config.get('general', 'sevpn_failed_table')

reliable_srvs = None
ping_table=None
failed_table=None
unreach_table=None
dest_addr=None
net_mask=None
sevpn999_skip=None
unreach_skip=None

tables = []
oq_srvs = None
oq_srvs_idx = 0

ping_srvs={}

def get_logger_handlers(modulename):
    sh = logging.StreamHandler(sys.stdout)
    sh.setLevel(logging.DEBUG)
    sh.setFormatter(fmt)
    n = os.path.splitext(sys.argv[0])[0]
    logname = "{}/{}".format(n, modulename)
    if not os.path.exists(n):
        os.makedirs(n)
    #sh2 = logging.FileHandler(logname)
    sh2 = logging.handlers.RotatingFileHandler(logname, maxBytes=10*1024*1024, backupCount=5)
    sh2.setLevel(logging.DEBUG)
    sh2.setFormatter(fmt)
    return sh, sh2


def get_logger(lgr, modulename):
    stdlog, filelog = get_logger_handlers(modulename)
    lgr.addHandler(stdlog)
    lgr.addHandler(filelog)


def init_logger():
    get_logger(logger, __name__)


def init_globalip():
    GLOBAL_IP = get_globalip()


def get_globalip():
    return urllib.request.urlopen(urllib.request.Request(IP_REQ_ADDR)).read().decode()

class ConnectedPingError(Exception):
    def __init__(self, vpn_addr, vpn_port, ping_srv_addrs, message="ConnectedPingError"):
        self.vpn_addr = vpn_addr
        self.vpn_port = vpn_port
        self.ping_srv_addrs = ping_srv_addrs
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        srvs_str = ' '.join(self.ping_srv_addrs)
        vpn_ipport = ':'.join([self.vpn_addr, self.vpn_port])
        msg = '{}: It seems {} cannot reach {}'.format(self.message, vpn_ipport, srvs_str)
        logger.error(msg)
        return msg



def get_host_fromurl(url):
    return url.split('//')[1].split('/')[0]


def scan(ip, port=None, interface=None, timeout=None):
    if not port:
        iface = 'vpn_{}'.format(interface) if interface else None
        return ping3.ping(ip, unit='ms', interface=iface, timeout=timeout if timeout else 2)
    else:
        port=int(port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout if timeout else 2);
        t = time.time()
        code = sock.connect_ex((ip, port))
        ping = (time.time() - t)*1000
        if code == 0:
            if ping >= 999:
                logger.debug('{}:{} ping higher than 999 ({})'.format(ip, port, ping))
                return None
            return ping
        else:
            logger.debug('{}:{} not open {}'.format(ip, port, ping))
            return None


def get_servers(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'curl/7.55.1'})
    page = urllib.request.urlopen(req)

    soup = BeautifulSoup(page)

    srvs = {}
    rows = soup.find('table', {'id': 'vpngate_main_table'}).find_all('tr')
    for row in rows[17:]:
        items = row.find_all('td', {'class': re.compile('vg_table_row_*')}, recursive=False)
        if not items:
            continue
        try:
            ip = row.contents[2].contents[2].text
            port = row.contents[5]
            country = row.contents[1].contents[2]
            if len(port) is 0:
                continue
            port = port.contents[2].text
            if 'TCP' in port:
                port = int(port.replace('TCP: ', ''))
            else:
                continue
            if country != 'Japan':
                continue
            ipport = "{}:{}".format(ip, port)
            srvs[ipport] = {'country': country}
        except Exception:
            logger.error('got wrong html format when parsing ip, port and country')
    return srvs


def calcping(pingList, attempt):
    mean = sum(pingList) / len(pingList)
    ploss = attempt - len(pingList)
    return mean, max(pingList), min(pingList), ploss


def getping(ip, maxcount, interface=None, port=None, timeout=None):
    pingList = []
    i = 0
    while maxcount > len(pingList):
        logger.info('start: {}'.format(i))
        if i - len(pingList) > maxcount - 1:
            return 999, 999, 999, i - len(pingList)
        res = scan(ip, port=port, interface=interface, timeout=timeout)
        if res:
            pingList.append(res)
        i += 1
    return calcping(pingList, i)


def procrun(mycmd, timeout=None):
    p = subprocess.Popen(mycmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    t = time.time()
    for line in iter(p.stdout.readline, b''):
        if timeout and time.time() - t > timeout:
            p.kill()
        logger.debug(line.rstrip().decode("utf8"))
    return p


def get_conn(conn=None):
    if conn and conn.is_connected():
        conn.ping(True)
    else:
        conn = mysql.connector.connect(user=f'{ACCOUNT}', password=f'{PASSWORD}', host=f'{SQL_ADDR}', database=f'{DATABASE}', charset='utf8')
    return conn


def get_mirrors():
    req = urllib.request.Request('https://www.vpngate.net/ja/sites.aspx', headers={'User-Agent': 'curl/7.55.1'})
    page = urllib.request.urlopen(req)

    soup = BeautifulSoup(page)

    mirrors = []
    rows = soup.find('td', {'id': 'vpngate_inner_contents_td'}).find_all('ul')[1].find_all('li')
    for row in rows:
        link = row.find('a').get('href')
        mirrors.append(link)
    return mirrors


def run_sql(conn, cmd):
    cur = conn.cursor()
    cur.execute(cmd)
    return cur


def query_oq_table():
    global oq_srvs
    global oq_srvs_idx
    oq_srvs_idx = 0
    conn = get_conn(None)
    cur = conn.cursor()
    #cur.execute('SELECT oneqode_srvs.addr, oneqode_srvs.ping, last_update FROM oneqode_srvs INNER JOIN ( SELECT addr, ping, MAX(last_update) AS maxup FROM oneqode_srvs GROUP BY addr) ms ON oneqode_srvs.addr = ms.addr AND oneqode_srvs.last_update = maxup WHERE oneqode_srvs.ping < 90 AND oneqode_srvs.failed < 3;')
    
    """cur.execute('SELECT o1.addr, o1.ping, o1.last_update FROM oneqode_srvs o1 JOIN ( SELECT addr, MAX(last_update) AS last_update FROM oneqode_srvs GROUP BY addr) AS o2 ON o1.addr = o2.addr AND o1.last_update = o2.last_update WHERE o1.ping < 90 AND o1.failed < 3;')
    oq_srvs = cur.fetchall()"""
    oq_srvs = copy.deepcopy(reliable_srvs)


def get_oq_srv():
    global oq_srvs
    global oq_srvs_idx
    ping_srv = oq_srvs[oq_srvs_idx]
    oq_srvs_idx = (oq_srvs_idx + 1) % len(oq_srvs)
    return ping_srv

def record_target_ping(argv):
    conn, cur, srv, id, dtime, update_tables = argv
    for table in update_tables:
        failed_list = []
        p_addrs = ping_srvs[table]['reliable']
        count = len(p_addrs) if len(p_addrs) < 4 else 4
        for _ in range(count):
            ping_srv = p_addrs[ping_srvs[table]['idx']]
            ping_srvs[table]['idx'] += 1
            ping_srvs[table]['idx'] %= len(p_addrs)
            res = getping(ping_srv, COUNT, interface=NIC_NAME)
            if res[0] == 999:
                failed_list.append(ping_srv)
            else:
                break
        else:
            srvs_str = ' '.join(failed_list)
            vpn_ipport = ':'.join([srv['ip'], srv['port']])
            logger.warning('It seems {} cannot reach {}'.format(vpn_ipport, srvs_str))
        cur.execute(
            'INSERT INTO {} VALUES ({}, "{}", {}, {}, {}, {}, {}, {}, "{}", "{}")'.format(config[table]['ping_table'], id,
                                                                                                srv['ip'],
                                                                                                srv['port'],
                                                                                                res[0], res[1],
                                                                                                res[2],
                                                                                                res[3], COUNT,
                                                                                                ping_srv,
                                                                                                dtime))
        # increment items of 999 oneqode server on the table
        if 'failed_table' in config[table]:
            for failed_ip in failed_list:
                # update oneqode_srvs, (SELECT id FROM oneqode_srvs WHERE addr='103.151.64.8' ORDER BY last_update DESC LIMIT 1) AS o SET oneqode_srvs.failed=oneqode_srvs.failed+1 WHERE oneqode_srvs.id = o.id;
                # update oneqode_srvs SET oneqode_srvs.failed=oneqode_srvs.failed+1 WHERE id IN (SELECT id FROM (SELECT MAX(last_update) FROM oneqode_srvs WHERE addr='103.151.64.8' AND addr='103.151.64.8') AS t );
                cur.execute(
                    'update {} SET failed=failed+1 WHERE last_update=(SELECT MAX(last_update) FROM (SELECT * FROM {}) AS t WHERE addr="{}") AND addr="{}";'.format(config[table]['failed_table'], config[table]['failed_table'],
                        failed_ip, failed_ip))
        logger.debug('addr:{} (avg:{} max:{} min:{} ploss:{}) to (table:{} ip:{})'.format(srv['ip'], res[0], res[1], res[2], res[3], table, ping_srv))
    conn.commit()
    return True


def disconnect_vpn(ip):
    procrun('{} AccountDisconnect {}'.format(VPN_CMD, ACCOUNT_NAME))
    procrun('{} AccountDelete {}'.format(VPN_CMD, ACCOUNT_NAME))
    p = subprocess.Popen("dhclient vpn_{}".format(NIC_NAME), shell=True)
    #procrun('timeout -t 2 dhclient vpn_{}'.format(NIC_NAME))
    procrun('route del {}'.format(ip))
    while True:
        p2 = subprocess.Popen(["route", "-n"], stdout=subprocess.PIPE)
        p3 = subprocess.Popen(["grep", "vpn_default"], stdin=p2.stdout, stdout=subprocess.PIPE)
        p2.stdout.close()
        out, err = p3.communicate()
        if not out:
            p.terminate()
            break
        time.sleep(0.5)
    subprocess.run("pkill dhclient", shell=True)


def connect_vpn(srv, update_tables, callback=None, argv=None):
    try:
        mask = ' '
        dest = ' '
        for table in update_tables:
            mask += '"{}" '.format(config[table]['net_mask'])
            dest += '"{}" '.format(config[table]['dest_addr'])
        proc = procrun(
            'bash -c \'VPN_SERVER="{}"; VPN_PORT="{}"; TAP_IPADDR="dhclient"; NIC_NAME="default"; IP_REQ_ADDR="{}"; declare -a NET_MASK=({}); declare -a DEST_ADDR=({}); . ./start.sh\''.format(
                srv['ip'],
                srv['port'], get_host_fromurl(IP_REQ_ADDR), mask, dest))
        if proc.returncode:
            logger.debug("start.sh returned error code {} {}".format(proc.returncode, srv['ip']))
            raise Exception()
        subprocess.run("pkill dhclient", shell=True)
        for _ in range(4):
            cur_globalip = get_globalip()
            if cur_globalip != GLOBAL_IP:
                break
            logger.debug("failed to get vpn global address. retrying...")
            time.sleep(1)
        else:
            logger.debug('vpn may not be able to resolve ddns {}'.format(srv['ip']))
            raise Exception()
        if callback:
            if not callback(argv):
                return False
    except Exception:
        #traceback.print_exc(file=sys.stdout)
        logger.debug("Exception", exc_info=True)
        return False
    else:
        return True


def sql_fetchoneone(cur, cmd):
    cur.execute(cmd)
    return cur.fetchone()[0]


def check_update_time(cur, table, srv, skip_var):
    cur.execute('SELECT ping_avg, NOW() - last_update FROM {} WHERE last_update IN (SELECT MAX(last_update) FROM {} GROUP BY addr) AND addr = \'{}\' AND port = {}'.format(table, table, srv['ip'], srv['port']))
    last_trg_try = cur.fetchone()
    if last_trg_try:
        ping = last_trg_try[0]
        elapsed = last_trg_try[1]
        if not skip_var and ping == 999:
            return True
        elif elapsed < 7000: # 30 MINUTE
            logger.debug('Too early to ping to {} in {}'.format(srv['ip'], table))
            return False
    return True




COUNT = 4
#SELECT addr, ping_avg, MAX(last_update) FROM guam_ping WHERE last_update IN (SELECT MAX(last_update) FROM guam_ping GROUP BY addr) AND addr = '219.100.37.132' AND last_update > NOW() - INTERVAL 1 DAY;
def update_ping(srvs):
    try:
        for s in srvs:
            ipport = s.split(':')
            srv = {'ip': ipport[0], 'port': ipport[1], 'country': srvs[s]['country']}
            if re.search('219\.100\.37\.[0-9]{1,3}', srv['ip']):
                logger.debug('Skipping for {}'.format(srv['ip']))
                continue
            conn = get_conn(None)
            cur = conn.cursor()
            if not check_update_time(cur, sevpn_table, srv, config.getboolean('general', 'sevpn999_skip')):
                continue
            update_tables=[]
            for table in tables:
                if check_update_time(cur, config[table]['ping_table'], srv, config.getboolean(table, 'unreach_skip')):
                    update_tables.append(table)
            if not update_tables:
                logger.debug("no need to update for {}. skipping".format(srv['ip']))
                continue
            logger.debug('Try connecting to {}'.format(srv['ip']))
            res = getping(srv['ip'], COUNT, interface=None, port=srv['port'])
            dtime = sql_fetchoneone(cur, "SELECT NOW()")
            auto_increment = sql_fetchoneone(cur, "SELECT `AUTO_INCREMENT` FROM INFORMATION_SCHEMA.`TABLES` WHERE TABLE_SCHEMA = 'vpn' AND TABLE_NAME = '{}';".format(sevpn_table))
            cur.execute('INSERT INTO {} VALUES (NULL, "{}", {}, {}, {}, {}, {}, {}, "{}", "{}")'.format(sevpn_table, srv['ip'], srv['port'],
                                                                                            res[0], res[1], res[2],
                                                                                            res[3], COUNT, srv['country'], dtime))
            if res[0] == 999:
                conn.commit()
                logger.debug('Host does not exist {}'.format(srv['ip']))
                continue
            logger.debug('{} {}'.format(srv['ip'], res[0]))
            connect_vpn(srv, update_tables, record_target_ping, (conn, cur, srv, auto_increment, dtime, update_tables))
            disconnect_vpn(srv['ip'])
        cur.close()
        conn.close()
    except Exception:
        conn.rollback()
        print("owari")
        logger.debug("Exception", exc_info=True)
        #traceback.print_exc(file=sys.stdout)
    if conn and conn.is_connected():
        if cur:
            cur.close()
        conn.close()

"""def parse_html(url):
    global oq_srvs_idx
    last_srv = None
    try:
        srvs = get_servers(url)
        for srv in srvs:
            if re.search('219\.100\.37\.[0-9]{1,3}', srv['ip']):
                print('Skipping for {}'.format(srv['ip']))
                continue
            conn = get_conn(None)
            cur = conn.cursor()
            cur.execute('SELECT COUNT(*) FROM sevpn_ping WHERE last_update IN (SELECT MAX(last_update) FROM sevpn_ping GROUP BY addr) AND addr = \'{}\' AND port = {} AND last_update > NOW() - INTERVAL 30 MINUTE;'.format(srv['ip'], srv['port']))
            last_count = cur.fetchone()[0]
            if last_count > 0:
                continue
            cur.execute("SELECT `AUTO_INCREMENT` FROM INFORMATION_SCHEMA.`TABLES` WHERE TABLE_SCHEMA = 'vpn' AND TABLE_NAME = 'sevpn_ping';")
            auto_increment = cur.fetchone()[0]
            cur.execute("SELECT NOW()")
            dtime = cur.fetchone()[0]
            #dtime = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            print('Try connecting to {}'.format(srv['ip']))
            res = getping(srv['ip'], COUNT, interface=None, port=srv['port'])
            #conn = get_conn(conn)
            sevpn_insert_cmd = 'INSERT INTO sevpn_ping VALUES (NULL, "{}", {}, {}, {}, {}, {}, {}, "{}", "{}")'.format(srv['ip'], srv['port'],
                                                                                            res[0], res[1], res[2],
                                                                                            res[3], COUNT, srv['country'], dtime)
            #conn.commit()
            if res[0] == 999:
                print('Host does not exist {}'.format(srv['ip']))
                conn.rollback()
                continue
            print('{} {}'.format(srv['ip'], res[0]))
            last_srv = srv
            proc = procrun(
                'VPN_SERVER="{}" VPN_PORT="{}" TAP_IPADDR="dhclient" NIC_NAME="default" IP_REQ_ADDR="{}" sh start.sh'.format(srv['ip'],
                                                                                                            srv['port'], get_host_fromurl(IP_REQ_ADDR)))
            try:
                cur_globalip = get_globalip()
                if not proc.returncode and cur_globalip != GLOBAL_IP:
                    failed_list = []
                    for i in range(4):
                        ping_srv = get_oq_srv()
                        res = getping(ping_srv[0], COUNT, interface=NIC_NAME)
                        if res[0] == 999:
                            failed_list.append(ping_srv[0])
                        else:
                            break
                    else:
                        raise ConnectedPingError(srv['ip'], srv['port'], failed_list)
                    #conn = get_conn(conn)
                    cur.execute('INSERT INTO guam_ping VALUES ({}, "{}", {}, {}, {}, {}, {}, {}, "{}", "{}")'.format(auto_increment, srv['ip'], srv['port'],
                                                                                                   res[0], res[1], res[2],
                                                                                                   res[3], COUNT, ping_srv[0], dtime))
                    #increment items of 999 oneqode server on the table
                    for failed_ip in failed_list:
                        #update oneqode_srvs, (SELECT id FROM oneqode_srvs WHERE addr='103.151.64.8' ORDER BY last_update DESC LIMIT 1) AS o SET oneqode_srvs.failed=oneqode_srvs.failed+1 WHERE oneqode_srvs.id = o.id;
                        #update oneqode_srvs SET oneqode_srvs.failed=oneqode_srvs.failed+1 WHERE id IN (SELECT id FROM (SELECT MAX(last_update) FROM oneqode_srvs WHERE addr='103.151.64.8' AND addr='103.151.64.8') AS t );
                        cur.execute('update oneqode_srvs SET failed=failed+1 WHERE last_update=(SELECT MAX(last_update) FROM (SELECT * FROM oneqode_srvs) AS t WHERE addr="{}") AND addr="{}";'.format(failed_ip))
                    cur.execute(sevpn_insert_cmd)
                    conn.commit()
                    print('addr:{} (avg:{} max:{} min:{} ploss:{}'.format(srv['ip'], res[0], res[1], res[2], res[3]))
                else:
                    if cur_globalip != GLOBAL_IP:
                        print('vpn may not be able to resolve ddns')
                    print('error: {}'.format(srv['ip']))
                    conn.rollback()
            except Exception:
                traceback.print_exc(file=sys.stdout)
                conn.rollback()
            procrun('{} AccountDisconnect {}'.format(VPN_CMD, ACCOUNT_NAME))
            procrun('{} AccountDelete {}'.format(VPN_CMD, ACCOUNT_NAME))
            procrun('timeout -t 2 dhclient vpn_{}'.format(NIC_NAME))
            procrun('route del {}'.format(srv['ip']))
            time.sleep(3)
            last_srv = None
        conn.close()
        cur.close()
    except Exception:
        if conn and conn.is_connected():
            conn.rollback()
            conn.close()
            if cur:
                cur.close()
        if last_srv:
            procrun('{} AccountDisconnect {}'.format(VPN_CMD, ACCOUNT_NAME))
            procrun('{} AccountDelete {}'.format(VPN_CMD, ACCOUNT_NAME))
            procrun('timeout -t 2 dhclient vpn_{}'.format(NIC_NAME))
            procrun('route del {}'.format(last_srv['ip']))
        traceback.print_exc(file=sys.stdout)"""

def add_vpns_from_sql(table):
    srvs = {}
    conn = get_conn(None)
    cur = conn.cursor()
    cur.execute("SELECT se.addr, se.port, se.country FROM {} se JOIN ( SELECT addr, port, MAX(last_update) AS last_update FROM {} GROUP BY addr) AS se2 ON se.addr = se2.addr AND se.last_update = se2.last_update".format(table, table))
    vpns_sql = cur.fetchall()
    for v in vpns_sql:
        ipport = ':'.join([v[0], str(v[1])])
        srvs[ipport] = {'country': v[2]}
    return srvs


def task():
    global oq_srvs
    global reliable_srvs
    global ping_table
    global failed_table
    mirrors = ['https://www.vpngate.net/ja/']
    mirrors.extend(get_mirrors())
    query_oq_table()
    srvs = {}
    srvs.update(add_vpns_from_sql("sevpn_ping"))
    srvs.update(add_vpns_from_sql("sevpn"))
    for m in mirrors:
        srvs.update(get_servers(m))
    update_ping(srvs)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    keys = list(config.keys())
    keys.remove('general')
    parser.add_argument('--settings', '-s', nargs='*', choices=keys, required=True)
    parser.add_argument('--debug', '-d', action='store_true')
    args = parser.parse_args()
    if args.debug:
        import ptvsd
        print("waiting...")
        ptvsd.enable_attach(address=('0.0.0.0', 5678))
        ptvsd.wait_for_attach()
    tables.extend(args.settings)
    for table in tables:
        reliable = json.loads(config.get(table, 'reliable'))
        ping_srvs[table] = {'reliable': reliable, 'idx': 0}
    print(args)
    """if (len(sys.argv) < 2):
        print('Please specify the config section you want to load')
        exit()
    reliable_srvs = json.loads(config.get(sys.argv[1], 'reliable'))
    ping_table = config.get(sys.argv[1], 'ping_table')
    dest_addr = config.get(sys.argv[1], 'dest_addr')
    net_mask = config.get(sys.argv[1], 'net_mask')
    failed_table = config.get(sys.argv[1], 'failed_table') if 'failed_table' in config[sys.argv[1]] else None
    unreach_table = config.get(sys.argv[1], 'unreach_table') if 'unreach_table' in config[sys.argv[1]] else None
    sevpn999_skip = config.getboolean(sys.argv[1], 'sevpn999_skip') if 'sevpn999_skip' in config[sys.argv[1]] else False
    unreach_skip = config.getboolean(sys.argv[1], 'unreach_skip') if 'unreach_skip' in config[sys.argv[1]] else False"""
    init_logger()
    init_globalip()
    last = 0
    try:
        while True:
            if time.time() - last > 60:
                task()
                last = time.time()
            time.sleep(60)
    except Exception:
        logger.error("Exception", exc_info=True)
