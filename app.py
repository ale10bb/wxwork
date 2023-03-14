# -*- coding: UTF-8 -*-
# Flask程序及函数
import ipaddress
from flask import Flask, request, g, abort
import xml.etree.ElementTree as ET
import requests
from weworkapi_callback.WXBizMsgCrypt3 import WXBizMsgCrypt

shm = {}

def init():
    global shm
    # 读取配置
    import os.path
    from configparser import ConfigParser
    config = ConfigParser()
    config.read(os.path.join('conf','wxwork.conf'), encoding='UTF-8')
    shm = dict(config._sections)

    app = Flask(__name__)
    app.logger.setLevel('INFO')
    return app

app = init()


@app.before_request
def before_request():
    g.client_ip = request.headers['X-Forwarded-For'].split(',')[0] if 'X-Forwarded-For' in request.headers else request.remote_addr
    ipaddress.ip_address(g.client_ip)


@app.route('/push/<module>')
def verify_URL(module):
    # 支持Http Get请求验证URL有效性
    # https://developer.work.weixin.qq.com/document/path/90930#31-%E6%94%AF%E6%8C%81http-get%E8%AF%B7%E6%B1%82%E9%AA%8C%E8%AF%81url%E6%9C%89%E6%95%88%E6%80%A7
    app.logger.info('mode: VerifyURL/<{}>'.format(module))
    wxcpt = WXBizMsgCrypt(shm[module]['token'], shm[module]['encodingaeskey'], shm[module]['corpid'])
    ret, plain_echostr = wxcpt.VerifyURL(
        request.args['msg_signature'], 
        request.args['timestamp'], 
        request.args['nonce'], 
        request.args['echostr'],
    )
    if ret:
        app.logger.error("ERR in VerifyURL: {}".format(ret))
        abort(500)
    app.logger.debug('plain_echostr: {}'.format(plain_echostr))
    return plain_echostr


@app.route('/push/rm', methods=['POST'])
def handle_rm():
    app.logger.info('message/<rm> from "{}"'.format(g.client_ip))
    # 支持Http Post请求接收业务数据
    # https://developer.work.weixin.qq.com/document/path/90930#32-%E6%94%AF%E6%8C%81http-post%E8%AF%B7%E6%B1%82%E6%8E%A5%E6%94%B6%E4%B8%9A%E5%8A%A1%E6%95%B0%E6%8D%AE
    wxcpt = WXBizMsgCrypt(shm['rm']['token'], shm['rm']['encodingaeskey'], shm['rm']['corpid'])
    ret, plain_msg = wxcpt.DecryptMsg(
        request.data, 
        request.args['msg_signature'], 
        request.args['timestamp'], 
        request.args['nonce'], 
    )
    if ret:
        app.logger.error('ERR in DecryptMsg: {}'.format(ret))
        abort(500)
    app.logger.debug('plain_msg: {}'.format(plain_msg))

    reply_content = ''
    xml_tree = ET.fromstring(plain_msg)
    msg_type = xml_tree.find("MsgType").text
    user = xml_tree.find("FromUserName").text

    match msg_type:
        case 'event':
            event = xml_tree.find("Event").text
            match event:
                case 'click':
                    # 处理“菜单事件”
                    event_key = xml_tree.find("EventKey").text
                    token = requests.get('{}/utils/genToken?user_id={}'.format(shm['rm']['forward'], user)).text
                    match event_key:
                        case 'RM_KNOCK':
                            app.logger.info('{}: event/click/RM_KNOCK'.format(user))
                            requests.post(
                                '{}/api/mail'.format(shm['rm']['forward']),
                                headers={'Authorization': 'Bearer {}'.format(token)}, 
                                json={},
                            )
                            reply_content = '[打机器人]已加入处理队列'
                        case 'RM_QUEUE':
                            app.logger.info('{}: event/click/RM_QUEUE'.format(user))
                            r = requests.post(
                                '{}/api/user/info'.format(shm['rm']['forward']),
                                headers={'Authorization': 'Bearer {}'.format(token)},
                                json={}
                            ).json()
                            assert not r['result'], r['err']
                            ret = r['data']['user']
                            if ret['status'] == 0:
                                status = '空闲'
                            elif ret['status'] == 1:
                                status = '不审加急'
                            elif ret['status'] == 2:
                                status = '不审报告'
                            else:
                                status = '未知'
                            reply_content = '===== 状态通知 =====\n\n你的状态: {}{}\n你的分配顺位: {}{}{}'.format(
                                status, 
                                '（跳过一篇）' if ret['skipped'] == 1 else '',
                                ret['priority'], 
                                ' (+{}页)'.format(ret['pages_diff']) if ret['pages_diff'] else '',
                                '\n你当前有{}个审核任务'.format(ret['current']) if ret['current'] else ''
                            )
                        case _:
                            app.logger.debug('{}: (unhandled) event/click/{}'.format(user, event_key))
                case 'subscribe':
                    app.logger.info('{}: event/subscribe'.format(user))
                    token = requests.get('{}/utils/genToken?user_id={}'.format(shm['rm']['forward'], user)).text
                    r = requests.post(
                        '{}/api/user/info'.format(shm['rm']['forward']),
                        headers={'Authorization': 'Bearer {}'.format(token)},
                        json={}
                    ).json()
                    if r['result']:
                        reply_content = '通知：启用\n用户：{}（无用户信息）'.format(user)
                    else:
                        ret = r['data']['user']
                        is_reviewer = '是' if ret['role'] else '否'
                        reply_content = '通知：启用\n用户：{}\n审核人：{}'.format(ret['name'], is_reviewer)
                        
                case 'view':
                    # 跳过打开网页的事件
                    app.logger.info('{}: event/view -> {}'.format(user, xml_tree.find("EventKey").text))
                case _:
                    app.logger.debug('{}: (unhandled) event/{}'.format(user, event))
        case _:
            app.logger.debug('{}: (unhandled) {}'.format(user, msg_type))

    # 加密回复信息
    app.logger.debug('reply_content: {}'.format(reply_content))
    ret, encrypted_msg = wxcpt.EncryptMsg(
        '<xml><ToUserName><![CDATA[{}]]></ToUserName><FromUserName><![CDATA[{}]]></FromUserName><CreateTime>{}</CreateTime><MsgType><![CDATA[text]]></MsgType><Content><![CDATA[{}]]></Content></xml>'.format(
            user,
            shm['rm']['corpid'],
            request.args['timestamp'],
            reply_content
        ),
        request.args['nonce'], 
        request.args['timestamp'],
    )
    if ret:
        app.logger.error('ERR in EncryptMsg: {}'.format(ret))
        abort(500)

    return encrypted_msg


@app.route('/push/<module>', methods=['POST'])
def handle_others(module):
    app.logger.info('message/<{}> from "{}"'.format(module, g.client_ip))
    # 支持Http Post请求接收业务数据
    # https://developer.work.weixin.qq.com/document/path/90930#32-%E6%94%AF%E6%8C%81http-post%E8%AF%B7%E6%B1%82%E6%8E%A5%E6%94%B6%E4%B8%9A%E5%8A%A1%E6%95%B0%E6%8D%AE
    wxcpt = WXBizMsgCrypt(shm[module]['token'], shm[module]['encodingaeskey'], shm[module]['corpid'])
    ret, plain_msg = wxcpt.DecryptMsg(
        request.data, 
        request.args['msg_signature'], 
        request.args['timestamp'], 
        request.args['nonce'], 
    )
    if ret:
        app.logger.error('ERR in DecryptMsg: {}'.format(ret))
        abort(500)
    app.logger.debug('plain_msg: {}'.format(plain_msg))

    # 加密回复信息
    ret, encrypted_msg = wxcpt.EncryptMsg(
        '<xml><ToUserName><![CDATA[{}]]></ToUserName><FromUserName><![CDATA[{}]]></FromUserName><CreateTime>{}</CreateTime><MsgType><![CDATA[text]]></MsgType><Content><![CDATA[{}]]></Content></xml>'.format(
            ET.fromstring(plain_msg).find("FromUserName").text,
            shm[module]['corpid'],
            request.args['timestamp'],
            'plain echo',
        ),
        request.args['nonce'], 
        request.args['timestamp'],
    )
    if ret:
        app.logger.error('ERR in EncryptMsg: {}'.format(ret))
        abort(500)

    return encrypted_msg
