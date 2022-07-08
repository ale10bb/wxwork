# -*- coding: UTF-8 -*-
# 读取配置
import os.path
from configparser import ConfigParser
config = ConfigParser()
config.read(os.path.join('conf','wxwork.conf'), encoding='UTF-8')
conf = dict(config._sections)
del config

# Flask程序及函数
from flask import Flask, request
import xml.etree.ElementTree as ET
import requests
from weworkapi_callback.WXBizMsgCrypt3 import WXBizMsgCrypt


app = Flask(__name__)
app.logger.setLevel('DEBUG')


def get_client_ip(request):
    x_forwarded_for = request.headers.get('X-Forwarded-For')
    return x_forwarded_for.split(',')[0] if x_forwarded_for else request.remote_addr


@app.route('/push/<module>', methods=['GET', 'POST'])
def push_rm(module):
    app.logger.info('request from "{}"/<{}>'.format(get_client_ip(request), module))

    # URL中包含msg_signature、timestamp、nonce参数
    msg_signature = request.args['msg_signature']
    timestamp = request.args['timestamp']
    nonce = request.args['nonce']
    
    # 支持Http Get请求验证URL有效性
    # https://developer.work.weixin.qq.com/document/path/90930#31-%E6%94%AF%E6%8C%81http-get%E8%AF%B7%E6%B1%82%E9%AA%8C%E8%AF%81url%E6%9C%89%E6%95%88%E6%80%A7
    if request.method == 'GET':
        app.logger.info('mode: VerifyURL')
        echostr = request.args['echostr']
        wxcpt = WXBizMsgCrypt(conf[module]['token'], conf[module]['encodingaeskey'], conf[module]['corpid'])
        ret, plain_echostr = wxcpt.VerifyURL(msg_signature, timestamp, nonce, echostr)
        if ret:
            app.logger.error("ERR: VerifyURL ret: {}".format(ret))
            return ret, 500
        app.logger.info('plain_echostr: {}'.format(plain_echostr))
        return plain_echostr

    # 支持Http Post请求接收业务数据
    # https://developer.work.weixin.qq.com/document/path/90930#32-%E6%94%AF%E6%8C%81http-post%E8%AF%B7%E6%B1%82%E6%8E%A5%E6%94%B6%E4%B8%9A%E5%8A%A1%E6%95%B0%E6%8D%AE
    if request.method == 'POST':
        app.logger.info('mode: DecryptMsg')
        wxcpt = WXBizMsgCrypt(conf[module]['token'], conf[module]['encodingaeskey'], conf[module]['corpid'])
        ret, plain_msg = wxcpt.DecryptMsg(request.data, msg_signature, timestamp, nonce)
        if ret:
            app.logger.error('ERR: DecryptMsg ret: {}'.format(ret))
            return ret, 500
        app.logger.debug('plain_msg: {}'.format(plain_msg))

        reply_content = ''
        xml_tree = ET.fromstring(plain_msg)
        msg_type = xml_tree.find("MsgType").text
        from_user = xml_tree.find("FromUserName").text

        if module == 'rm':
            if msg_type == 'event':
                event = xml_tree.find("Event").text
                app.logger.debug('[event/{}] message from "{}"'.format(event, from_user))
                # 处理“菜单事件”
                if event == 'click':
                    event_key = xml_tree.find("EventKey").text
                    app.logger.debug('EventKey: {}'.format(event_key))
                    if event_key == 'RM_KNOCK':
                        requests.post('{}/api/mail'.format(conf[module]['forward']), json={})
                        reply_content = '[打机器人]已加入处理队列'
                    elif event_key == 'RM_QUEUE':
                        r = requests.post('{}/api2/queue/list'.format(conf[module]['forward']), json={}).json()
                        assert not r['result'], r['err']
                        for idx, item in enumerate(r['data']['normal']):
                            if from_user != item['id']:
                                continue
                            if item['status'] == -1:
                                status = '(跳过1篇)'
                            elif item['status'] == 0:
                                status = '空闲'
                            elif item['status'] == 1:
                                status = '不审加急'
                            elif item['status'] == 2:
                                status = '不审报告'
                            else:
                                status = '未知'
                            reply_content = '===== 状态通知 =====\n\n你的状态: {}\n你的分配顺位: {}{}{}'.format(
                                status, 
                                idx + 1 if item['status'] != -1 else 'x', 
                                ' (+{}页)'.format(item['pages_diff']) if item['pages_diff'] else '',
                                '\n你当前有{}个审核任务'.format(item['current']) if item['current'] else ''
                            )
                    else:
                        pass
                elif event == 'subscribe':
                    r = requests.post('{}/api2/user/search'.format(conf[module]['forward']), json={'id': from_user}).json()
                    assert not r['result'], r['err']
                    if r['data']['user']:
                        ret = r['data']['user'][0]
                        is_reviewer = '是' if ret['role'] else '否'
                        reply_content = '通知：启用\n用户：{}\n审核人：{}'.format(ret['name'], is_reviewer)
                    else:
                        reply_content = '通知：启用\n用户：{}（无用户信息）'.format(from_user)
                # 跳过打开网页的事件
                elif event == 'view':
                    app.logger.debug('EventKey: {}'.format(xml_tree.find("EventKey").text))
                else:
                    pass
            else:
                app.logger.debug('unhandled MsgType [{}] from {}'.format(msg_type, from_user))

        # 加密回复信息
        app.logger.debug('reply_content: {}'.format(reply_content))
        ret, encrypted_msg = wxcpt.EncryptMsg(
            '<xml><ToUserName><![CDATA[{}]]></ToUserName><FromUserName><![CDATA[{}]]></FromUserName><CreateTime>{}</CreateTime><MsgType><![CDATA[text]]></MsgType><Content><![CDATA[{}]]></Content></xml>'.format(
                from_user,
                conf[module]['corpid'],
                timestamp,
                reply_content
            ),
            nonce, 
            timestamp
        )
        if ret:
            app.logger.error('ERR: EncryptMsg ret: {}'.format(ret))
            return ret, 500

        return encrypted_msg
