#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
- author: Lkeme
- contact: Useri@live.cn
- file: bilibili.py
- time: 2020/12/23 20:24
- desc: 哔哩哔哩任务姬
"""
import re
import faker
import pymysql
import chardet
import functools
import hashlib
import os
import platform
import random
import requests
import sys
import time
import toml
from uuid import uuid4

try:
    from urllib import urlencode
except Exception as e:
    from urllib.parse import urlencode

from requests.packages.urllib3.exceptions import InsecureRequestWarning

# 禁用安全请求警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class Singleton:
    def __new__(cls, *args, **kw):
        if not hasattr(cls, '_instance'):
            cls._instance = object.__new__(cls, *args, **kw)
        return cls._instance


class Config(Singleton):
    config = None

    def __init__(self):
        self.load_config()

    def load_config(self):
        config_file = sys.argv[1] if len(sys.argv) > 1 else "config.toml"
        try:
            with open(config_file, "r",
                      encoding=self.detect_charset(config_file)) as f:
                self.config = toml.load(f)
        except Exception as e:
            print(f"无法加载配置文件 {e}")
            exit()

    @staticmethod
    def detect_charset(file, fallback="utf-8"):
        with open(file, "rb") as f:
            detector = chardet.UniversalDetector()
            for line in f.readlines():
                detector.feed(line)
                if detector.done:
                    return detector.result['encoding']
        return fallback

    def get(self, section, key):
        return self.config[section][key]

    def set(self, section, key, value):
        self.config[section][key] = value


class Logger:
    normal_log = None
    errors_log = None
    user = None
    filepath = None
    root_path = './logs/'

    def __init__(self):
        self.config = Config()
        self.load_log()

    def load_log(self):
        try:
            self.normal_log = self.config.get('log', 'normal_log')
            self.errors_log = self.config.get('log', 'errors_log')
        except Exception as e:
            print(f'无法加载日志文件 {e}')
            exit()

    @staticmethod
    def format_time():
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

    def set_user(self, user):
        self.user = user
        return self

    # 正常日志
    def i(self, message, mode='i'):
        log = self.log_handle(message, mode)
        self.write(log, mode)

    # 错误日志
    def e(self, message, mode='e'):
        log = self.log_handle(message, mode)
        self.write(log, mode)

    # 警告日志
    def w(self, message, mode='w'):
        log = self.log_handle(message, mode)
        self.write(log, mode)

    # 提醒日志
    def n(self, message, mode='n'):
        log = self.log_handle(message, mode)
        self.write(log, mode)

    def write(self, packet, mode):
        if not self.config.get('log', 'enable'):
            return
        self.path_handle(mode)
        with open(self.filepath, "a+", encoding="utf-8") as f:
            f.write(f'{packet}\n')

    def path_handle(self, mode):
        if not os.path.exists(self.root_path):
            os.makedirs(self.root_path)
        if mode in ['e', 'w']:
            self.filepath = f'{self.root_path}{self.errors_log}'
        else:
            self.filepath = f'{self.root_path}{self.normal_log}'

    def log_handle(self, message, mode):
        log = ''
        ori_log = f"[{self.format_time()}][{self.user if self.user else 'global'}] {message}"
        if mode == 'e':
            log = f'\033[1;31;40m{ori_log}\033[0m'
        if mode == 'i':
            log = f'\033[1;32;40m{ori_log}\033[0m'
        if mode == 'w':
            log = f'\033[1;33;40m{ori_log}\033[0m'
        if mode == 'n':
            log = f'\033[1;36;40m{ori_log}\033[0m'
        print(log, flush=True)
        return ori_log


class Db(Singleton):
    cur = None
    db = None
    db_fields = None

    def __init__(self):
        self.config = Config()
        self.log = Logger().set_user('DB')
        self.load_db()

    def load_db(self):
        try:
            db = pymysql.connect(
                host=self.config.get('database', 'host'),
                user=self.config.get('database', 'user'),
                password=self.config.get('database', 'pass'),
                db=self.config.get('database', 'name'),
                port=self.config.get('database', 'port'),
            )
            cur = db.cursor(cursor=pymysql.cursors.DictCursor)
            self.db, self.cur = db, cur
        except Exception as e:
            print(f"无法加载数据库 {e}")
            exit()

    def _get_users_sql(self, db_table, iden):
        # 过滤封禁
        if self.config.get('global', 'silence'):
            # sql = f"SELECT * from `{db_table}` where iden = '{iden}' AND `silence` = 2 AND `silence_up` = 2 AND `expires` != 0 AND `msg` like '%token%' AND `channel` != 'AppStore' LIMIT 1;"
            sql = f"SELECT * from `{db_table}` where iden = '{iden}' AND `silence` = 2 AND `silence_up` = 2 AND `expires` != 0 AND `msg` like '%token%';"
        else:
            sql = f"SELECT * from `{db_table}` where iden = '{iden}' AND `expires` != 0 AND `msg` like '%token%';"
        try:
            self.cur.execute(sql)
            self.db.commit()
            return self.cur.fetchall()
        except Exception as e:
            self.log.i(f"查询数据库错误 {e}")
            # 错误回滚
            # traceback.print_exc()
        finally:
            self.log.i(f"查询数据库完成")
        return []

    def get_users(self):
        infos = []
        db_table = self.config.get('database', 'table')
        iden_list = self.config.get('database', 'idens')
        for iden in iden_list:
            infos += self._get_users_sql(db_table, iden)
        return infos


class Filter(Singleton):
    labels = {}

    def __init__(self):
        pass

    def set_label_data(self, label, data):
        # 判断文件是否存在
        label_file = f'./filters/{label}.txt'
        # 不考虑文件存在 直接写入或者创建
        with open(label_file, 'a+', encoding='utf-8') as f:
            f.write(f'{data}\n')
        # 追加到标签数据
        self.labels[label] += f'{data}\n'
        return

    def get_label_data(self, label):
        # 判断内容是否存在
        if label in self.labels:
            return
        # 判断文件是否存在
        label_file = f'./filters/{label}.txt'
        if not os.path.exists(label_file):
            # 过滤文件不存在 直接赋值空
            self.labels[label] = ''
        else:
            # 过滤文件存在 赋值内容
            with open(label_file, 'r', encoding='utf-8') as f:
                self.labels[label] = f.read()
        return

    def get_filter(self, label, data):
        self.get_label_data(label)
        if data in self.labels[label]:
            return True
        return False

    def set_filter(self, label, data):
        self.get_label_data(label)
        self.set_label_data(label, data)
        return


class UsersTasks:
    users = None

    def __init__(self):
        self.db = Db()
        self.load_users()
        self.log = Logger().set_user('UsersTasks')
        self.config = Config()

    def load_users(self):
        try:
            self.users = self.db.get_users()
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"无法加载用户 {e}")
            exit()

    def get_mode_name(self, work_name):
        mode = random.choice(self.config.get(work_name, 'mode'))
        time.sleep(self.config.get(work_name, 'delay'))
        return f'{mode}_{work_name}'

    def work(self):
        self.log.i(f'加载 {len(self.users)} 个用户')
        # 乱序
        random.shuffle(self.users)
        for user in self.users:
            # 实例化任务
            instance = BiliTasks(user, self.config.get('global', 'mode'))
            try:
                videos = instance.fetch_videos()
                if instance.is_login():
                    # 观看
                    if self.config.get('watch', 'enable'):
                        name = self.get_mode_name('watch')
                        getattr(instance, name)(videos.pop())
                    # 分享
                    if self.config.get('share', 'enable'):
                        name = self.get_mode_name('share')
                        getattr(instance, name)(videos.pop())
                    # 直播间签到
                    if self.config.get('live_sign', 'enable'):
                        name = self.get_mode_name('live_sign')
                        getattr(instance, name)()
                    # 直播间送礼
                    if self.config.get('live_send', 'enable'):
                        gift_id = self.config.get('live_send', 'gift_id')
                        target_rid = self.config.get('live_send', 'target_rid')
                        target_uid = self.config.get('live_send', 'target_uid')
                        expires = self.config.get('live_send', 'expires')
                        name = self.get_mode_name('live_send')
                        getattr(instance, name)(
                            gift_id, expires, target_rid, target_uid
                        )
                    # 银瓜子兑换硬币
                    if self.config.get('silver2coin', 'enable'):
                        name = self.get_mode_name('silver2coin')
                        getattr(instance, name)()
            except Exception as e:
                instance.log.i(f'任务执行错误 {e}')
            time.sleep(self.config.get('global', 'delay'))


# {'code': 137004, 'message': '账号异常，操作失败', 'ttl': 1}


class BiliTasks:

    def __init__(self, user, mode):
        self.user = user
        self.mode = mode

        self.get_cookies = lambda: self.parse_info(self.user["cookie"])
        self.get_csrf = lambda: self.get_cookies().get("csrf", "")
        self.get_sid = lambda: self.get_cookies().get("sid", "")
        self.get_uid = lambda: self.get_cookies().get("uid", "")

        self._session = requests.Session()
        # self._session.verify = False
        self.info = {
            'ban': False,
            'coins': 0,
            'experience': {
                'current': 0,
                'next': 0,
            },
            'face': "",
            'level': 0,
            'nickname': "",
            'tel_status': False,
        }
        self.proxy = None

        self.log = Logger().set_user(self.get_uid())

        if 'pc' in self.mode:
            self.ua = self.random_pc_ua()

        if 'app' in self.mode:
            self.access_token = self.user['access_key']
            self.refresh_token = self.user['refres_key']
            self.username = ""
            self.password = ""
            if self.user['channel'] == 'AppStore':
                self.app_key = '27eb53fc9058f8c3'
                self.app_secret = 'c2ed53a74eeefe3cf99fbd01d8c9c375'
                self.ua = self.random_ios_ua()
            else:
                self.app_key = '1d8b6e7d45233436'
                self.app_secret = '560c52ccd288fed045859ed18bffd973'
                self.ua = self.random_android_ua()
            self.session_id = self.random_session_id()
            self.bfe_id = self.random_bfe_id()

        self.filter = Filter()

    # 匹配信息
    @staticmethod
    def parse_info(cookie):
        temp_csrf = re.search(r"bili_jct=(.{32})", cookie)
        csrf = str(temp_csrf.group(1))

        temp_sid = re.search(r"sid=(.{8})", cookie)
        sid = str(temp_sid.group(1))

        temp_uid = re.search(r"DedeUserID=(\d+)", cookie)
        uid = str(temp_uid.group(1))

        format_cookie = cookie.replace(" ", "").rstrip(";")
        user = {
            "sid": sid,
            "uid": uid,
            "csrf": csrf,
            "cookie": cookie,
            "format_cookie": format_cookie
        }

        return user

    # 随机生成UA
    @staticmethod
    def random_pc_ua():
        fake = faker.Faker(locale='zh_CN')
        while True:
            ua = fake.chrome(version_from=70, version_to=86, build_from=3500,
                             build_to=4200)
            if "Windows NT" not in ua or "Chrome" not in ua:
                continue
            version = re.findall(r"Windows NT (\d+\.\d+)", ua)[0]
            ua = ua.replace(f"Windows NT {version}",
                            "Windows NT 10.0; Win64; x64")
            version = re.findall(r"AppleWebKit/(\d+\.\d+)", ua)[0]
            ua = ua.replace(f"AppleWebKit/{version}", "AppleWebKit/537.36")
            ua = ua.replace(f"Safari/{version}", "Safari/537.36")
            return ua

    def random_android_ua(self):
        model = self.user['model']
        channel = self.user['channel']
        os_ver = self.user['osVer']
        return f'Mozilla/5.0 BiliDroid/6.15.0 (bbcallen@gmail.com) os/android model/{model} mobi_app/android build/6150400 channel/{channel} innerVer/6150400 osVer/{os_ver} network/2'

    def random_ios_ua(self):
        model = self.user['model']
        os_ver = self.user['osVer']
        return f'bili-universal/61500200 CFNetwork/1197 Darwin/20.0.0 os/ios model/{model} mobi_app/iphone build/61500200 osVer/{os_ver} network/2 channel/AppStore'

    def random_bfe_id(self):
        channel = self.user['channel']
        url = f"https://app.bilibili.com/x/v2/version/fawkes/bizapk?build=6150400&channel={channel}&nt=1&sn=4645887&ts={int(time.time())}&vn=6.15.0"
        headers = {
            'buvid': self.user['buvid'],
            'app-key': 'android' if channel == 'AppStore' else 'iphone',
            'env': 'prod',
            'APP-KEY': 'android' if channel == 'AppStore' else 'iphone',
            'User-Agent': self.ua,
            'Host': 'app.bilibili.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip',
        }
        try:
            response = self._requests('get', url, headers=headers,
                                      decode_level=0)
            id = re.findall(r"bfe_id=(.+?);", response.headers['Set-Cookie'])[
                0]
        except Exception as e:
            id = str(uuid4()).replace('-', '')
        return id

    def random_session_id(self):
        if self.user['session_id'] == '':
            return str(uuid4()).split('-')[0]
        return self.user['session_id']

    @staticmethod
    def ksort(d):
        return [(k, d[k]) for k in sorted(d.keys())]

    @staticmethod
    def __bvid_handle(args_index=None, kwargs_key="aid"):
        def decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                self = args[0]
                if args_index is not None and args_index < len(args):
                    result = BiliTasks.bvid_to_aid(args[args_index])
                    if result:
                        args = list(args)
                        self._log(f"{args[args_index]}被自动转换为av{result}")
                        args[args_index] = result
                if kwargs_key is not None and kwargs_key in kwargs:
                    result = BiliTasks.bvid_to_aid(kwargs[kwargs_key])
                    if result:
                        self._log(f"{kwargs[kwargs_key]}被自动转换为av{result}")
                        kwargs[kwargs_key] = result
                return func(*args, **kwargs)

            return wrapper

        return decorator

    def calc_sign(self, param):
        salt = self.app_secret
        sign_hash = hashlib.md5()
        sign_hash.update(f"{param}{salt}".encode())
        return sign_hash.hexdigest()

    def bvid_to_aid(bvid="BV1Ci4y1c7D8"):
        # Snippet source: https://www.zhihu.com/question/381784377/answer/1099438784
        table = "fZodR9XQDSUm21yCkr6zBqiveYah8bt4xsWpHnJE7jL5VG3guMTKNPAwcF"
        tr = {}
        for i in range(58):
            tr[table[i]] = i
        s = [11, 10, 3, 8, 4, 6]
        xor = 177451812
        add = 8728348608
        r = 0
        try:
            for i in range(6):
                r += tr[bvid[s[i]]] * 58 ** i
            return (r - add) ^ xor
        except:
            return None

    def _requests(self, method, url, decode_level=2, enable_proxy=True,
                  retry=10, timeout=15, **kwargs):
        if method in ["get", "post"]:
            for _ in range(retry + 1):
                try:
                    response = getattr(self._session, method)(url,
                                                              timeout=timeout,
                                                              proxies=self.proxy if enable_proxy else None,
                                                              **kwargs)
                    return response.json() if decode_level == 2 else response.content if decode_level == 1 else response
                except:
                    if enable_proxy:
                        self.set_proxy()
        return None

    def set_proxy(self, add=None):
        self.proxy = None
        return self.proxy

    def fetch_videos(self, retry=10, delay=1):
        videos = []
        for _ in range(retry):
            if len(videos) > 10:
                break
            url = 'https://api.bilibili.com/x/web-interface/dynamic/region?ps=12&rid=1'
            headers = {
                'accept': 'application/json, text/plain, */*',
                'accept-encoding': 'gzip, deflate, br',
                'accept-language': 'zh-CN,zh;q=0.9',
                'origin': 'https://www.bilibili.com',
                'referer': 'https://www.bilibili.com/',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-site',
                'user-agent': self.ua
            }
            response = self._requests("get", url, headers=headers)
            if response and response.get("code") == 0:
                for archive in response['data']['archives']:
                    videos.append({
                        'aid': archive['aid'],
                        'cid': archive['cid'],
                        'bvid': archive['bvid'],
                    })
                self.log.i('获取视频列表成功')
            else:
                self.log.e(f'获取视频列表失败 {response}')
            time.sleep(delay)

        return videos

    # 是否登录
    def is_login(self, **kwargs):
        return self.get_user_info_main()

    # 获取主站用户信息
    def get_user_info_main(self):
        url = f"https://api.bilibili.com/x/space/myinfo?jsonp=jsonp"
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'zh-CN,zh;q=0.9',
            'cookie': self.user['cookie'],
            'origin': 'https://space.bilibili.com',
            'referer': f'https://space.bilibili.com/{self.get_uid()}',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.ua
        }
        response = self._requests("get", url, headers=headers)
        if response and response.get("code") == 0:
            self.info['ban'] = bool(response['data']['silence'])
            self.info['coins'] = response['data']['coins']
            self.info['experience']['current'] = response['data']['level_exp'][
                'current_exp']
            self.info['experience']['next'] = response['data']['level_exp'][
                'next_exp']
            self.info['face'] = response['data']['face']
            self.info['level'] = response['data']['level']
            self.info['nickname'] = response['data']['name']
            self.info['tel_status'] = bool(response['data']['tel_status'])
            self.log.i(
                f"{self.info['nickname']}(UID={self.get_uid()}), Lv.{self.info['level']}({self.info['experience']['current']}/{self.info['experience']['next']}), 拥有{self.info['coins']}枚硬币, 账号{'状态正常' if not self.info['ban'] else '被封禁'}")
            self.log.i(f"[主站用户信息] 有效 {response['code']}")
            return True
        else:
            self.log.e(f"[主站用户信息] 无效 {response}")
            return False

    # 获取直播站用户信息
    def get_user_info_live(self):
        url = 'https://api.live.bilibili.com/xlive/web-ucenter/user/get_user_info'
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'zh-CN,zh;q=0.9',
            'cookie': self.user['cookie'],
            'origin': 'https://link.bilibili.com',
            'referer': 'https://link.bilibili.com/p/center/index',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.ua,
        }
        response = self._requests("get", url, headers=headers)
        if response and response.get("code") == 0:
            self.log.i(f"[直播站用户信息] 有效 {response['code']}")
            return response
        else:
            self.log.e(f"[直播站用户信息] 无效 {response}")
            return False

    # APP 观看
    def app_watch(self, video):
        if self.user['channel'] == 'AppStore':
            self.__ios_watch(video)
        else:
            self.__android_watch(video)

    # ANDROID 观看
    def __android_watch(self, video):
        aid, cid, bv_id = video['aid'], video['cid'], video['bvid']
        url = 'https://api.bilibili.com/x/report/heartbeat/mobile'
        headers = {
            'Buvid': self.user['buvid'],
            'Device-ID': self.user['device'],
            'fp_local': self.user['local_id'].lower(),
            'fp_remote': self.user['local_id'].lower(),
            'session_id': self.session_id,
            'env': 'prod',
            'APP-KEY': 'android',
            'User-Agent': self.ua,
            'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
            'Host': 'api.bilibili.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip',
            'Cookie': f'bfe_id={self.bfe_id}',
        }
        payload = {
            'access_key': self.access_token,
            'actual_played_time': '0',
            'aid': aid,
            'appkey': self.app_key,
            'auto_play': '0',
            'build': '6150400',
            'c_locale': 'zh_CN',
            'channel': self.user['channel'],
            'cid': cid,
            'epid': '0',
            'epid_status': '',
            'from': '7',
            'from_spmid': 'tm.recommend.0.0',
            'last_play_progress_time': '0',
            'list_play_time': '0',
            'max_play_progress_time': '0',
            'mid': self.get_uid(),
            'miniplayer_play_time': '0',
            'mobi_app': 'android',
            'network_type': '1',
            'paused_time': '0',
            'platform': 'android',
            'play_status': '0',
            'play_type': '1',
            'played_time': '0',
            'quality': '32',
            's_locale': 'zh_CN',
            'session': str(uuid4()).replace('-', ''),
            'sid': '0',
            'spmid': 'main.ugc-video-detail.0.0',
            'start_ts': '0',
            'statistics': '{"appId":1,"platform":3,"version":"6.15.0","abtest":""}',
            'sub_type': '0',
            'total_time': '0',
            'ts': int(time.time()),
            'type': '3',
            'user_status': '0',
            'video_duration': random.randint(10, 150),
        }
        payload['sign'] = self.calc_sign(urlencode(self.ksort(payload)))
        response = self._requests("post", url, data=payload,
                                  headers=headers)
        if response and response.get("code") == 0:
            self.log.i(f'[观看任务] av{aid} 观看成功')
            return True
        else:
            self.log.e(f'[观看任务] av{aid} 观看失败')
            return False

    # IOS 观看
    def __ios_watch(self, video):
        aid, cid, bv_id = video['aid'], video['cid'], video['bvid']
        url = 'https://api.bilibili.com/x/report/heartbeat/mobile'
        headers = {
            'Host': 'api.bilibili.com',
            'Connection': 'keep-alive',
            'User-Agent': self.ua,
            'Session_ID': self.session_id,
            'Buvid': self.user['buvid'],
            'APP-KEY': 'iphone',
            'ENV': 'prod',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept-Encoding': 'gzip, deflate, br',
            'Cookie': f"Buvid={self.user['buvid']}; {self.user['cookie']} bfe_id={self.bfe_id}"
        }
        payload = {
            'access_key': self.access_token,
            'actionKey': '	appkey',
            'actual_played_time': 0,
            'aid': aid,
            'appkey': self.app_key,
            'auto_play': 0,
            'build': 61500200,
            'cid': cid,
            'device': 'phone',
            'epid': 0,
            'epid_status': 0,
            'from': 7,
            'from_spmid': 'tm.recommend.0.0',
            'last_play_progress_time': 0,
            'list_play_time': 0,
            'max_play_progress_time': 0,
            'mid': self.get_uid(),
            'miniplayer_play_time': 0,
            'mobi_app': 'iphone',
            'network_type': 1,
            'paused_time': 0,
            'platform': 'ios',
            'play_mode': 1,
            'play_status': 0,
            'play_type': 1,
            'played_time': 0,
            'quality': 32,
            's_locale': 'zh-Hans_CN',
            'session': str(uuid4()).replace('-', ''),
            'sid': 0,
            'spmid': 'main.ugc-video-detail.0.0',
            'start_ts': 0,
            'statistics': '{"appId":1,"version":"6.15.0","abtest":"","platform":1}',
            'sub_type': 0,
            'total_time': 0,
            'ts': int(time.time()),
            'type': 3,
            'user_status': 0,
            'video_duration': random.randint(10, 150),
        }
        payload['sign'] = self.calc_sign(urlencode(self.ksort(payload)))
        response = self._requests("post", url, data=payload,
                                  headers=headers)
        if response and response.get("code") == 0:
            self.log.i(f'[观看任务] av{aid} 观看成功')
            return True
        else:
            self.log.e(f'[观看任务] av{aid} 观看失败')
            return False

    # 观看
    def pc_watch(self, video):
        aid, cid, bv_id = video['aid'], video['cid'], video['bvid']
        url = f'https://api.bilibili.com/x/click-interface/web/heartbeat'
        headers = {
            'accept': 'application/json, text/javascript, */*; q=0.01',
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'zh-CN,zh;q=0.9',
            'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'cookie': self.user['cookie'],
            'origin': 'https://www.bilibili.com',
            'referer': f'https://www.bilibili.com/video/{bv_id}',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.ua
        }
        payload = {
            'aid': aid,
            'cid': cid,
            'bvid': bv_id,
            'mid': self.get_uid(),
            'csrf': self.get_csrf,
            'played_time': 0,
            'real_played_time': 0,
            'realtime': 0,
            'start_ts': int(time.time()),
            'type': 3,
            'dt': 2,
            'play_type': 1,
        }
        response = self._requests("post", url, data=payload,
                                  headers=headers)
        if response and response.get("code") == 0:
            self.log.i(f'[观看任务] av{aid} 观看成功')
            return True
        else:
            self.log.e(f'[观看任务] av{aid} 观看失败')
            return False

    # APP 分享
    def app_share(self, video):
        if self.user['channel'] == 'AppStore':
            self.__ios_share(video)
        else:
            self.__android_share(video)

    # ANDROID 分享
    def __android_share(self, video):
        if self.filter.get_filter('share', self.get_uid()):
            self.log.i(f"[分享任务] 分享失败, 过滤列表中.")
            return
        aid, cid, bv_id = video['aid'], video['cid'], video['bvid']
        """
        url = 'https://app.bilibili.com/x/v2/view/share/click'
        headers = {
            'Buvid': self.user['buvid'],
            'Device-ID': self.user['device'],
            'fp_local': self.user['local_id'].lower(),
            'fp_remote': self.user['local_id'].lower(),
            'session_id': self.session_id,
            'env': 'prod',
            'APP-KEY': 'android',
            'User-Agent': self.ua,
            'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
            'Host': 'app.bilibili.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip',
            'Cookie': f'bfe_id={self.bfe_id}',
        }
        payload = {
            'access_key': self.access_token,
            'appkey': self.app_key,
            'build': '6150400',
            'c_locale': 'zh_CN',
            'channel': self.user['channel'],
            'ep_id': '',
            'from': '7',
            'from_spmid': 'main.ugc-video-detail.0.0',
            'mobi_app': 'android',
            'oid': aid,
            'platform': 'android',
            's_locale': 'zh_CN',
            'season_id': '',
            'share_channel': 'dynamic',
            'share_trace_id': str(uuid4()).replace('-', ''),
            'spmid': 'tm.recommend.0.0',
            'statistics': '{"appId":1,"platform":3,"version":"6.15.0","abtest":""}',
            'ts': int(time.time()),
            'type': 'av',
        }
        """
        url = 'https://app.bilibili.com/x/v2/view/share/complete'
        headers = {
            'Buvid': self.user['buvid'],
            'Device-ID': self.user['device'],
            'fp_local': self.user['local_id'].lower(),
            'fp_remote': self.user['local_id'].lower(),
            'session_id': self.session_id,
            'env': 'prod',
            'APP-KEY': 'android',
            'User-Agent': self.ua,
            'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
            'Host': 'app.bilibili.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip',
            'Cookie': f'bfe_id={self.bfe_id}',
        }
        payload = {
            'access_key': self.access_token,
            'appkey': self.app_key,
            'build': '6150400',
            'c_locale': 'zh_CN',
            'channel': self.user['channel'],
            'ep_id': '',
            'from': '7',
            'from_spmid': 'tm.recommend.0.0',
            'mobi_app': 'android',
            'oid': aid,
            'platform': 'android',
            's_locale': 'zh_CN',
            'season_id': '',
            'share_channel': 'dynamic',
            'share_trace_id': str(uuid4()).replace('-', ''),
            'spmid': 'main.ugc-video-detail.0.0',
            'statistics': '{"appId":1,"platform":3,"version":"6.15.0","abtest":""}',
            'ts': int(time.time()),
            'type': 'av',
        }
        payload['sign'] = self.calc_sign(urlencode(self.ksort(payload)))
        response = self._requests("post", url, data=payload,
                                  headers=headers)
        if response and response.get("code") == 0:
            self.log.i(f"[分享任务] av{aid} 分享成功")
            return True
        else:
            self.log.e(f"[分享任务] av{aid} 分享失败 {response}")
            if '账号异常' in response:
                self.filter.set_filter('share', self.get_uid())
            return False

    # IOS 分享
    def __ios_share(self, video):
        if self.filter.get_filter('share', self.get_uid()):
            self.log.i(f"[分享任务] 分享失败, 过滤列表中.")
            return
        aid, cid, bv_id = video['aid'], video['cid'], video['bvid']
        """
        url = 'https://app.bilibili.com/x/v2/view/share/click'
        headers = {
            'Host': 'app.bilibili.com',
            'Connection': 'keep-alive',
            'User-Agent': self.ua,
            'Session_ID': self.session_id,
            'Buvid': self.user['buvid'],
            'APP-KEY': 'iphone',
            'ENV': 'prod',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept-Encoding': 'gzip, deflate, br',
            'Cookie': f"Buvid={self.user['buvid']}; {self.user['cookie']} bfe_id={self.bfe_id}",
        }
        payload = {
            'type': 'av',
            'ts': int(time.time()),
            'statistics': '{"appId":1,"version":"6.15.0","abtest":"","platform":1}',
            'spmid': 'main.ugc-video-detail.0.0',
            'share_trace_id': str(uuid4()).replace('-', '').upper(),
            'share_channel': 'qq',
            's_locale': 'zh-Hans_CN',
            'platform': 'ios',
            'oid': aid,
            'mobi_app': 'iphone',
            'from_spmid': 'tm.recommend.0.0',
            'from': 7,
            'device': 'phone',
            'build': 61500200,
            'appkey': self.app_key,
            'actionKey': 'appkey',
            'access_key': self.access_token,
        }
        """
        url = 'https://app.bilibili.com/x/v2/view/share/complete'
        headers = {
            'Host': 'app.bilibili.com',
            'Connection': 'keep-alive',
            'User-Agent': self.ua,
            'Session_ID': self.session_id,
            'Buvid': self.user['buvid'],
            'APP-KEY': 'iphone',
            'ENV': 'prod',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept-Encoding': 'gzip, deflate, br',
            'Cookie': f"Buvid={self.user['buvid']}; {self.user['cookie']} bfe_id={self.bfe_id}",
        }
        payload = {
            'type': 'av',
            'ts': int(time.time()),
            'statistics': '{"appId":1,"version":"6.15.0","abtest":"","platform":1}',
            'spmid': 'main.ugc-video-detail.0.0',
            'share_trace_id': str(uuid4()).replace('-', '').upper(),
            'share_channel': 'qq',
            's_locale': 'zh-Hans_CN',
            'platform': 'ios',
            'oid': aid,
            'mobi_app': 'iphone',
            'from': 7,
            'from_spmid': 'tm.recommend.0.0',
            'device': 'phone',
            'build': 61500200,
            'appkey': self.app_key,
            'actionKey': 'appkey',
            'access_key': self.access_token,
        }
        payload['sign'] = self.calc_sign(urlencode(self.ksort(payload)))
        response = self._requests("post", url, data=payload,
                                  headers=headers)
        if response and response.get("code") == 0:
            self.log.i(f"[分享任务] av{aid} 分享成功")
            return True
        else:
            self.log.e(f"[分享任务] av{aid} 分享失败 {response}")
            if '账号异常' in response:
                self.filter.set_filter('share', self.get_uid())
            return False

    # PC 分享
    def pc_share(self, video):
        if self.filter.get_filter('share', self.get_uid()):
            self.log.i(f"[分享任务] 分享失败, 过滤列表中.")
            return
        aid, cid, bv_id = video['aid'], video['cid'], video['bvid']
        # aid = 稿件av号  bv_id = 原始
        url = 'https://api.bilibili.com/x/web-interface/share/add'
        payload = {
            'aid': aid,
            'csrf': self.get_csrf(),
        }
        headers = {
            'content-type': 'application/x-www-form-urlencoded',
            'cookie': self.user['cookie'],
            'origin': 'https://www.bilibili.com',
            'referer': f'https://www.bilibili.com/video/{bv_id}',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.ua,
            'Host': "api.bilibili.com",
            'Origin': "https://www.bilibili.com",
            'Referer': f"https://www.bilibili.com/video/av{aid}",
        }
        response = self._requests("post", url, data=payload,
                                  headers=headers)
        # {"code":0,"message":"0","ttl":1,"data":7961}
        if response and response.get("code") == 0:
            self.log.i(f"[分享任务] av{aid} 分享成功")
            return True
        else:
            self.log.e(f"[分享任务] av{aid} 分享失败 {response}")
            if '账号异常' in response:
                self.filter.set_filter('share', self.get_uid())
            return False

    # APP 直播签到
    def app_live_sign(self):
        if self.user['channel'] == 'AppStore':
            self.__ios_live_sign()
        else:
            self.__android_live_sign()

    # ANDROID 直播签到
    def __android_live_sign(self):
        if not self.info['tel_status'] or self.info['ban']:
            return
        url = 'https://api.live.bilibili.com/rc/v1/Sign/doSign?'
        headers = {
            'Buvid': self.user['buvid'],
            'fp_local': self.user['local_id'].lower(),
            'fp_remote': self.user['local_id'].lower(),
            'session_id': self.session_id,
            'User-Agent': self.ua,
            'Host': 'api.live.bilibili.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip',
        }
        payload = {
            'access_key': self.access_token,
            'actionKey': 'appkey',
            'appkey': self.app_key,
            'channel': self.user['channel'],
            'build': 6150400,
            'device': 'android',
            'mobi_app': 'android',
            'platform': 'android',
            'c_locale': 'zh_CN',
            's_locale': 'zh_CN',
            'statistics': '{"appId":1,"platform":3,"version":"6.15.0","abtest":""}',
            'ts': int(time.time()),
        }
        payload['sign'] = self.calc_sign(urlencode(self.ksort(payload)))
        url = f'{url}{urlencode(payload)}'
        response = self._requests("get", url, headers=headers)
        if response and response.get("code") == 0:
            self.log.i(f"[直播间签到任务] 签到成功 {response['data']['text']}")
            return True
        else:
            self.log.e(f"[直播间签到任务] 签到失败 {response}")
            return False

    # IOS 直播签到
    def __ios_live_sign(self):
        if not self.info['tel_status'] or self.info['ban']:
            return
        url = 'https://api.live.bilibili.com/rc/v1/Sign/doSign?'
        headers = {
            'Host': 'api.live.bilibili.com',
            'Connection': 'keep-alive',
            'User-Agent': self.ua,
            'Session_ID': self.session_id,
            'Buvid': self.user['buvid'],
            'APP-KEY': 'iphone',
            'ENV': 'prod',
            'Accept-Encoding': 'gzip',
            'Cookie': f"Buvid={self.user['buvid']}; {self.user['cookie']} bfe_id={self.bfe_id}"
        }
        payload = {
            'access_key': self.access_token,
            'actionKey': 'appkey',
            'appkey': self.app_key,
            'build': 61500200,
            'device': 'phone',
            'mobi_app': 'iphone',
            'platform': 'ios',
            's_locale': 'zh-Hans_CN',
            'statistics': '{"appId":1,"version":"6.15.0","abtest":"","platform":1}',
            'ts': int(time.time()),
        }
        payload['sign'] = self.calc_sign(urlencode(self.ksort(payload)))
        url = f'{url}{urlencode(payload)}'
        response = self._requests("get", url, headers=headers)
        if response and response.get("code") == 0:
            self.log.i(f"[直播间签到任务] 签到成功 {response['data']['text']}")
            return True
        else:
            self.log.e(f"[直播间签到任务] 签到失败 {response}")
            return False

    # PC 直播间签到
    def pc_live_sign(self):
        if not self.info['tel_status'] or self.info['ban']:
            return
        url = 'https://api.live.bilibili.com/xlive/web-ucenter/v1/sign/DoSign'
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'zh-CN,zh;q=0.9',
            'cookie': self.user['cookie'],
            'origin': 'https://link.bilibili.com',
            'referer': 'https://link.bilibili.com/p/center/index',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.ua,
        }
        response = self._requests("get", url, headers=headers)
        if response and response.get("code") == 0:
            self.log.i(f"[直播间签到任务] 签到成功 {response['data']['text']}")
            return True
        else:
            self.log.e(f"[直播间签到任务] 签到失败 {response}")
            return False

    # PC 直播间获取背包
    def fetch_bag_list(self, target_rid):
        url = f'https://api.live.bilibili.com/xlive/web-room/v1/gift/bag_list?t={int(time.time()) * 1000}&room_id={target_rid}'
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
            'cookie': self.user['cookie'],
            'origin': 'https://live.bilibili.com',
            'referer': 'https://live.bilibili.com/',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.ua,
        }
        response = self._requests("get", url, headers=headers)
        if response and response.get("code") == 0:
            self.log.i(f"[直播间送礼] 获取背包成功 {response['code']}")
            return response['data']['list']
        else:
            self.log.e(f"[直播间送礼] 获取背包成功 {response}")
            return []

    # PC 直播间赠送礼物
    def send_gift(self, bag, target_rid, target_uid):
        url = 'https://api.live.bilibili.com/gift/v2/live/bag_send'
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
            'content-type': 'application/x-www-form-urlencoded',
            'cookie': self.user['cookie'],
            'origin': 'https://live.bilibili.com',
            'referer': 'https://live.bilibili.com/',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.ua,
        }
        payload = {
            'uid': self.get_uid(),
            'gift_id': bag['gift_id'],
            'ruid': target_uid,
            'send_ruid': 0,
            'gift_num': bag['gift_num'],
            'bag_id': bag['bag_id'],
            'platform': 'pc',
            'biz_code': 'live',
            'biz_id': target_rid,
            'rnd': int(time.time()),
            'storm_beat_id': 0,
            'metadata': '',
            'price': 0,
            'csrf_token': self.get_csrf(),
            'csrf': self.get_csrf(),
            'visit_id': ''
        }
        response = self._requests("post", url, data=payload, headers=headers)
        if response and response.get("code") == 0:
            self.log.i(f"[直播间送礼] {bag['gift_name']}*{bag['gift_num']} 赠送成功")
            return True
        else:
            self.log.e(
                f"[直播间送礼] {bag['gift_name']}*{bag['gift_num']} 赠送失败 {response}")
            return False

    # PC 直播间赠送礼物
    def pc_live_send(self, gift_id, expires, target_rid, target_uid):
        if not self.info['tel_status'] or self.info['ban']:
            return
        valid_bag_list = []
        bag_list = self.fetch_bag_list(target_rid)
        if not bag_list:
            return
        for bag in bag_list:
            # 过滤永久礼物
            if bag['expire_at'] == 0 or bag['corner_mark'] == '永久':
                continue
            # 过滤有效期 和 有效的礼物id
            if bag['gift_id'] != gift_id:
                continue
            if (bag['expire_at'] - int(time.time())) > expires:
                continue
            valid_bag_list.append(bag)
        for bag in valid_bag_list:
            self.send_gift(bag, target_rid, target_uid)

    # PC 直播银瓜子兑换硬币
    def pc_silver2coin(self):
        if not self.info['tel_status'] or self.info['ban']:
            return
        live_info = self.get_user_info_live()
        if not live_info:
            return
        if live_info['data']['silver'] < 700:
            return
        url = 'https://api.live.bilibili.com/pay/v1/Exchange/silver2coin'
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'zh-CN,zh;q=0.9',
            'content-type': 'application/x-www-form-urlencoded',
            'cookie': self.user['cookie'],
            'origin': 'https://live.bilibili.com',
            'referer': 'https://live.bilibili.com/23058',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.ua,
        }
        payload = {
            'csrf_token': self.get_csrf(),
            'csrf': self.get_csrf(),
            'visit_id': 'visit_id',
        }
        response = self._requests("post", url, data=payload, headers=headers)
        if response and response.get("code") == 0:
            self.log.i(f"[银瓜子兑换硬币] 兑换成功")
            return True
        else:
            self.log.e(f"[银瓜子兑换硬币] 兑换失败 {response}")
            return False


if __name__ == "__main__":
    start_time = int(input('请输入程序启动时间(0-23)时: '))
    while True:
        # 定时任务
        if start_time != time.localtime().tm_hour:
            if int(time.time()) % 300 == 0:
                if start_time < time.localtime().tm_hour:
                    surplus_hour = (24 - time.localtime().tm_hour) + start_time
                else:
                    surplus_hour = start_time - time.localtime().tm_hour
                print(f"离预定执行时间还有 {surplus_hour} 小时左右")
            time.sleep(1)
            continue
        else:
            print(f"到达预定执行时间，启动程序")
        # 执行任务
        UsersTasks().work()
        if start_time != time.localtime().tm_hour:
            time.sleep(1 * 60 * (60 - time.localtime().tm_min))

    if platform.system() == "Windows":
        os.system("pause >nul | set /p =请按任意键退出")
