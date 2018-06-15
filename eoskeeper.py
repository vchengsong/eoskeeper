#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import time
import threading
import re
import ConfigParser
from sh import tail
import requests
import subprocess
import json
import logging
import socket


# -- 这是一个右进左出的list --
# get函数把最右边的当成第0个元素

class List:
    def __init__(self, max_length):
        self.__list = []
        self.__maxLength = max_length
        self.__lock = threading.Lock()

    def append(self, data):
        self.__lock.acquire()
        if self.__list.__len__() >= self.__maxLength:
            self.__list.pop(0)
        self.__list.append(data)
        self.__lock.release()

    def read(self, length):
        self.__lock.acquire()
        res = self.__list[(self.__list.__len__() - length):]
        self.__lock.release()
        return res

    def get(self, index):
        res = ""
        self.__lock.acquire()
        if self.__list.__len__() - 1 > index:
            res = self.__list[(self.__list.__len__() - index - 1)]
        self.__lock.release()
        return res

    def length(self):
        return self.__list.__len__()

    def dump(self):
        print self.__list


# -- 从配置文件加载参数 --
class NewConfigParser(ConfigParser.RawConfigParser):
    def get(self, section, option):
        val = ConfigParser.RawConfigParser.get(self, section, option)
        return val.strip('"').strip("'")


config = NewConfigParser()

try:
    config.read('/etc/eoskeeper/config.ini')
    config.read('config.ini')
except:
    pass

role = config.get("global", "role")
block_producer_name = config.get("global", "block_producer_name")
eosio_log_file = config.get("global", "eosio_log_file")
eoskeeper_log_file = config.get("global", "eoskeeper_log_file")
infulxdb_url = config.get("global", "infulxdb_url")
mobiles = config.get("global", "mobiles")

logging.basicConfig(filename=eoskeeper_log_file, level="INFO")

# -- 全局变量 --
l_http_json_ok = List(1000)  # 记录http端口是否返回数据，及是否是json格式；正确则记录1，错误则记录为2
l_http_hbp = List(1000)  # head_block_producer
l_http_hbn = List(1000)  # head_block_num
l_http_lib = List(1000)  # last_irreversible_block_id
t_producing_block = 0  # the latest time of producing block
nodeos_pid = 0
current_links = ""  # strings
current_linkn = 0  # link number
hostname = ""
local_ip = ""
is_paused = "unknown"  # /v1/producer/paused
current_alarm_msg = ""
server_version = ""

# -- 全局常量 --
re1 = r'.*producer_plugin.cpp.*] Produced block .* (#\d+) @.*'
url = 'http://127.0.0.1:8888/v1/chain/get_info'
sms_url = "https://dx.ipyy.net/smsJson.aspx"


# -- init ---


def now():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def log_info(msg):
    print "INFO: " + now() + "  " + msg
    logging.info("  " + now() + "  " + msg)


def log_err(msg):
    print "ERROR: " + now() + "  " + msg
    logging.error("  " + now() + "  " + msg)


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip


def init():
    global nodeos_pid, hostname, local_ip, is_paused
    ret = ""
    try:
        ret = subprocess.check_output(["lsof", "-i:8888"])
    except:
        log_info("ERROR! run lsof -i:8888\nExit!")
        exit(1)

    lines = ret.split("\n")
    line = lines[1]
    cols = re.split(r" +", line)
    nodeos_pid = cols[1]
    hostname = socket.gethostname()
    is_paused = is_produce_paused()
    try:
        local_ip = get_local_ip()
    except:
        pass


# -- LogParser --
def log_parse(line):
    global t_producing_block
    res1 = re.match(re1, line)  # 只有本节点出块时匹配此项。
    if res1:
        t_producing_block = time.time()
        log_info("  ******* Produce block " + res1.group(1) + " ********")


class LogParser(threading.Thread):
    def run(self):
        log_info("Run thread LogParser")
        while True:
            try:
                for line in tail("-n", 1, "-f", eosio_log_file, _iter=True):
                    log_parse(line)
            except:
                log_err("eosio log file:" + eosio_log_file + " parse failed!")
            time.sleep(10)


# -- HttpParser --
def http_parse():
    try:
        r = requests.get(url)
    except:
        l_http_json_ok.append(2)
        logging.error("/v1/chain/get_info get failed")
    else:
        try:
            res = r.json()
        except:
            l_http_json_ok.append(2)
            logging.error("/v1/chain/get_info didn't return json")
        else:
            l_http_json_ok.append(1)
            server_version = res["server_version"]
            l_http_hbn.append(res["head_block_num"])
            l_http_hbp.append(res["head_block_producer"])
            l_http_lib.append(res["last_irreversible_block_num"])


class HttpParser(threading.Thread):
    def run(self):
        log_info("Run thread HttpParser")
        while True:
            http_parse()
            time.sleep(1)  # 必须是1秒，不可更改


# -- LsofParser --
def lsof_parser():
    global current_links, current_linkn
    count = 0
    links = ""
    ret = subprocess.check_output(["lsof", "-nP", "-p", nodeos_pid])
    lines = ret.split("\n")
    for line in lines:
        if re.match(r'.*TCP 172.*', line):
            count += 1
            cols = re.split(r" +", line)
            links += cols[len(cols) - 2] + "\n"
    current_linkn = count
    current_links = links
    # log_info("\nlink_num: " + str(current_linkn) + "\nlink_str:\n" + current_links)
    log_info("\nlink_num: " + str(current_linkn) + "\n")


class LsofParser(threading.Thread):
    def run(self):
        log_info("Run thread LsofParser")
        while True:
            try:
                lsof_parser()
            except:
                log_err("lsof parser failed.")
            time.sleep(300)


# -- 是否需要启动出块命令 --

def start_produce():
    global is_paused
    # ret = requests.post("http://127.0.0.1:8888/v1/producer/resume")  # ABP阶段
    if not ret.ok:
        log_err("/v1/producer/resume failed")
    else:
        is_paused = False


def is_produce_paused():
    ret = requests.post("http://127.0.0.1:8888/v1/producer/paused")
    if not ret.ok:
        log_err("/v1/producer/paused failed")
        return

    if ret.content == "false":
        return False
    elif ret.content == "true":
        return True


def produce_or_not():
    log_info("run produce_or_not()")

    if l_http_json_ok.read(50) == [1] * 50 and int(l_http_lib.get(0)) > int(l_http_lib.get(20)):
        if role == "B":
            ret = l_http_hbp.read(250)
        elif role == "C":
            ret = l_http_hbp.read(850)
        else:
            return
        bps = set()
        count = 0
        for r in ret:
            if r == block_producer_name:
                count += 1
            bps.add(r)
        log_info("There are " + str(count) + "bp name records in list l_http_hbp")
        if block_producer_name not in bps:
            start_produce()
            log_info(" ++++++++ START PRODUCE BLOCK  ++++++++")
        else:
            if is_produce_paused():
                log_info("Production Paused")
            else:
                log_info(block_producer_name + " produced block " + str(
                    int(time.time() - t_producing_block)) + " seconds ago")


bp_status = "unknown"  # "unknown"  "bp" "nonbp"


class ProduceOrNot(threading.Thread):
    def run(self):
        log_info("Run thread ProduceOrNot")

        global bp_status

        if role == "B":
            time.sleep(280)
        elif role == "C":
            time.sleep(900)
        else:
            log_info("Assert ERROR!\nExit")
            exit(1)

        while True:
            res = is_21ebp()
            if res == "true":
                if bp_status == "nonbp":
                    bp_status = "bp"
                    time.sleep(250)
                try:
                    produce_or_not()
                except:
                    log_err("produce_or_not() failed.")

            elif res == "false":
                bp_status = "nonbp"

            time.sleep(10)


class Messenger(object):
    def __init__(self):
        pass

    def access_server(self):
        CorpID = "wx************"   # use your own info
        Secret = "T3CLEw4s****************************************"  # use your own info
        url1 = "https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=%s&corpsecret=%s" % (CorpID, Secret)
        r = requests.get(url1)
        # 获取access_token
        access_token = json.loads(r.text)['access_token']
        return access_token

    def send_weixin(self, title, hostname, messages):
        news = {
            "touser": "**************************************", # use your own info
            # 用户ID    多个ID 可以用|隔开
            # "touser": "wo_weixinni",
            "toparty": " 2 ",  # 部门ID
            "totag": "  ",
            "msgtype": "news",
            "agentid": 0,
            "news": {
                "articles": [
                    {
                        "title": "%s|%s" % (title, hostname),
                        "description": messages + now()
                    },
                ]
            }
        }

        token = self.access_server()
        body = json.dumps(news, ensure_ascii=False)
        url4 = "https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=%s" % token
        r = requests.post(url4, data=body)
        status = json.loads(r.text)['errmsg']
        if status == 'ok':
            print "报警发送成功!"
            return True
        else:
            print "报警发送失败!"
            return False


msger = Messenger()


def send_mobile_msg(msg):    # use your own sms info
    sign = '请及时处理。【EOS主网运维】'
    querystring = {"action": "send",
                   "userid": "5*******",
                   "account": "A*******",
                   "password": "240F0F87************",
                   "mobile": mobiles,
                   "content": msg + sign,
                   "sendTime": "", "extno": ""}

    headers = {
        'Cache-Control': "no-cache",
        'Postman-Token': "0bca5e96-cd0e-476*************"
    }

    status = ""
    try:
        res = requests.request("GET", sms_url, headers=headers, params=querystring)
        rj = json.loads(res.content)
        status = rj['returnstatus']
    except:
        pass

    return status == "Success"


t_last_alarm = 0


def alarm(msg):
    global t_last_alarm
    if (time.time() - t_last_alarm) > 1800:
        t_last_alarm = time.time()
        try:
            if not msger.send_weixin("EOS故障报警", hostname, local_ip + " " + msg):
                log_err("send wechat msg failed.")
            if not send_mobile_msg("故障信息:" + hostname + "|" + local_ip + "|" + msg):
                log_err("send mobile msg failed.")
        except:
            log_err("msger.send_weixin() or send_mobile_msg() failed.")


# -- 告警分析 --
def err_parse():
    global current_alarm_msg
    msg = ""

    # 分析连接数量是否正常
    if current_linkn < 5:
        msg += "节点peer连接数(" + str(current_linkn) + ")过低!  "

    # 分析http端口是否正常
    if l_http_json_ok.length() > 5:
        if l_http_json_ok.read(5) == [2] * 5:
            msg += "http api 请求异常!  "

    # 分析http返回的lib是否正常
    if l_http_lib.length() > 30:
        res = l_http_lib.read(20)
        if res[0] == res[18]:
            msg += "20秒内lib未增加，严重故障!"

    # 分析http返回的bps是否正常
    if l_http_hbp.length() > 60:
        bps = set()
        for bp in l_http_hbp.read(60):
            bps.add(bp)
        if bps.__len__() < 5:
            msg += "1分钟内捕获的BP个数(" + str(bps.__len__()) + ")太少!  "

    # 分析http返回的hbn是否正常
    if l_http_hbn.length() > 10:
        res = l_http_hbn.read(10)
        if res[0] == res[9]:
            msg += "10秒内head_block_num未增加!  "

    current_alarm_msg = msg
    if msg != "":
        alarm(msg)
        log_err(msg)


class ErrAlarm(threading.Thread):
    def run(self):
        log_info("Run thread ErrAlarm")
        while True:
            time.sleep(5)
            err_parse()


def get_hour_min():
    t = time.strftime("%H:%M", time.localtime())
    return t.split(':')


t_last_notice = 0


def wechat_and_sms(msg):
    msger.send_weixin("EOS日常信息", hostname, local_ip + msg)
    send_mobile_msg("日常信息:" + hostname + "|" + local_ip + "|" + msg)


def daily_notice():
    global t_last_notice, role
    if role == "F":
        msg = hostname + "|hbn:" + str(l_http_hbn.get(0)) + "|lib:" + str(l_http_lib.get(0)) \
              + "|linkn:" + str(current_linkn) + "|info:" + current_alarm_msg

        if time.time() - t_last_notice > 3600:
            h, m = get_hour_min()
            if (h == "7" or h == "19") and m < 30:
                t_last_notice = time.time()
                wechat_and_sms(msg)
    else:
        msg = hostname + "|hbn:" + str(l_http_hbn.get(0)) + "|lib:" + str(l_http_lib.get(0)) + "|linkn:" + str(
            current_linkn) \
              + "|t_pb:" + str(t_producing_block) + "|info:" + current_alarm_msg
        if time.time() - t_last_notice > 3600:
            h, m = get_hour_min()
            if (h == "7" or h == "13" or h == "19") and m < 30:
                t_last_notice = time.time()
                wechat_and_sms(msg)


class DailyNotice(threading.Thread):
    def run(self):
        log_info("Run thread DailyNotice")
        while True:
            daily_notice()
            time.sleep(300)


def dump_var():
    # l_http_json_ok.dump()
    # l_http_lib.dump()
    # l_http_hbn.dump()
    l_http_hbp.dump()


class DumpVar(threading.Thread):
    def run(self):
        log_info("Run thread DumpVar")
        while True:
            dump_var()
            time.sleep(5)


# str      int  int   int   str    str     str
def post_bpn_info_to_infulxdb(host_name, hbn, lib, linkn, lpbt, paused, info):
    table_name = "eos_bp_node_info"

    if paused == "unknown":
        paused = "~"
    elif paused:
        paused = "是"
    else:
        paused = "否"

    t = time.time()
    if t - lpbt > 3600:
        lpbt_msg = "~"
    elif t - lpbt > 150:
        lpbt_msg = str(int(int(t - lpbt) / 60)) + "分钟前"
    else:
        lpbt_msg = str(int(t - lpbt)) + "秒前"

    tag_str = "host=" + host_name
    fields_str = "hbn/当前块=" + str(hbn) + ","
    fields_str += "lib/不可逆块=" + str(lib) + ","
    fields_str += "linkn/连接数量=" + str(linkn) + ","
    fields_str += "lpbt/上次出块时间=\"" + lpbt_msg + "\","
    fields_str += "paused=\"" + paused + "\","
    fields_str += "info/告警信息=\"" + info + "\""

    data = table_name + "," + tag_str + " " + fields_str
    ret = requests.post(infulxdb_url, data)
    return ret.ok, ret.content


#                                str      int  int   int   str
def post_fulln_info_to_infulxdb(host_name, hbn, lib, linkn, info):
    table_name = "eos_full_node_info"

    tag_str = "host=" + host_name
    fields_str = "hbn/当前块=" + str(hbn) + ","
    fields_str += "lib/不可逆块=" + str(lib) + ","
    fields_str += "linkn/连接数量=" + str(linkn) + ","
    fields_str += "info/告警信息=\"" + info + "\""

    data = table_name + "," + tag_str + " " + fields_str

    ret = ""
    try:
        ret = requests.post(infulxdb_url, data)
    except:
        pass
    return ret.ok, ret.content


def push_fulln_msg():
    global current_alarm_msg
    ok, content = post_fulln_info_to_infulxdb(hostname, l_http_hbn.get(0), l_http_lib.get(0), current_linkn,
                                              current_alarm_msg)
    if not ok:
        log_err("push_fulln_msg()  " + content)


def push_bpn_msg():
    global is_paused, current_alarm_msg
    ok, content = post_bpn_info_to_infulxdb(hostname, l_http_hbn.get(0), l_http_lib.get(0), current_linkn,
                                            t_producing_block, is_paused, current_alarm_msg)
    if not ok:
        log_err("push_bpn_msg() " + content)


class PushMsg(threading.Thread):
    def run(self):
        log_info("Run thread PushMsg")
        time.sleep(2)
        while True:
            if role == "F":
                try:
                    push_fulln_msg()
                except:
                    log_err("push_full_node_msg() failed.")
            else:
                try:
                    push_bpn_msg()
                except:
                    log_err("push_bpn_msg() failed.")
            time.sleep(3)


def is_21ebp():
    try:
        r = requests.post("http://127.0.0.1:8888/v1/chain/get_producers", '{"json":"true"}')
        if r.ok:
            ret = r.json()
            bps = ret["rows"]
            ebps = list(map(lambda bp: bp["owner"], bps[:21]))
            if block_producer_name in ebps:
                return "true"
            else:
                return "false"
    except:
        pass
    return "req_err"


if __name__ == '__main__':
    log_info("eoskeeper start. " + now())

    log_info("config.ini :\n" + role + "\n" + block_producer_name + "\n" + eosio_log_file + "\n"
             + eoskeeper_log_file + "\n" + infulxdb_url + "\n" + mobiles + "\n")

    res = is_21ebp()
    if res == "true":
        log_info('*' * 15 + " WE ARE BP NOW " + '*' * 15)
    elif res == "false":
        log_info('-' * 15 + " we aren't bp " + '-' * 15)
    else:
        log_info('/' * 15 + " FATAL ERROR! " + '/' * 15 + "\nExit!")
        exit(1)

    init()

    log_parser_t = LogParser()
    log_parser_t.setDaemon(True)
    log_parser_t.start()

    http_parser_t = HttpParser()
    http_parser_t.setDaemon(True)
    http_parser_t.start()

    lsof_parser_t = LsofParser()
    lsof_parser_t.setDaemon(True)
    lsof_parser_t.start()

    push_msg_t = PushMsg()
    push_msg_t.setDaemon(True)
    push_msg_t.start()

    err_alarm_t = ErrAlarm()
    err_alarm_t.setDaemon(True)
    err_alarm_t.start()

    daily_t = DailyNotice()
    daily_t.setDaemon(True)
    daily_t.start()

    # dump_var_t = DumpVar()
    # dump_var_t.setDaemon(True)
    # dump_var_t.start()

    if role == "B" or role == "C":
        produce_or_not_t = ProduceOrNot()
        produce_or_not_t.setDaemon(True)
        produce_or_not_t.start()

    while True:
        if not role == 'F':
            is_paused = is_produce_paused()
        time.sleep(600)

