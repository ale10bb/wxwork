# -*- coding: UTF-8 -*-
# Flask程序及函数
import ipaddress
from flask import Flask, request, g, abort
import xml.etree.ElementTree as ET
import requests
from weworkapi_callback.WXBizMsgCrypt3 import WXBizMsgCrypt


app = Flask(__name__)


@app.before_first_request
def before_first_request():
    import os.path
    from configparser import ConfigParser
    config = ConfigParser()
    config.read(os.path.join('conf', 'wxwork.conf'), encoding='UTF-8')
    global shm
    shm = dict(config._sections)
    app.logger.setLevel('DEBUG')


@app.before_request
def before_request():
    g.client_ip = request.headers['X-Forwarded-For'].split(',')[0] \
        if 'X-Forwarded-For' in request.headers else request.remote_addr
    try:
        ipaddress.ip_address(g.client_ip)
    except ValueError as err:
        abort(400, err)
    app.logger.info('%s - %s %s ', g.client_ip, request.method, request.path)


@app.route('/push/<module>')
def verify_URL(module):
    ''' 支持Http Get请求验证URL有效性

    https://developer.work.weixin.qq.com/document/path/90930#31-%E6%94%AF%E6%8C%81http-get%E8%AF%B7%E6%B1%82%E9%AA%8C%E8%AF%81url%E6%9C%89%E6%95%88%E6%80%A7

    '''
    if module not in shm:
        abort(400)

    wxcpt = WXBizMsgCrypt(
        shm[module]['token'],
        shm[module]['encodingaeskey'],
        shm[module]['corpid'],
    )
    ret, plain_echostr = wxcpt.VerifyURL(
        request.args['msg_signature'],
        request.args['timestamp'],
        request.args['nonce'],
        request.args['echostr'],
    )
    if ret:
        app.logger.error('ERR in VerifyURL: %s', ret)
        abort(500)
    app.logger.debug('plain_echostr: %s', plain_echostr)
    return plain_echostr


@app.route('/push/<module>', methods=['POST'])
def handle_default(module):
    ''' 支持Http Post请求接收业务数据

    https://developer.work.weixin.qq.com/document/path/90930#32-%E6%94%AF%E6%8C%81http-post%E8%AF%B7%E6%B1%82%E6%8E%A5%E6%94%B6%E4%B8%9A%E5%8A%A1%E6%95%B0%E6%8D%AE

    '''
    if module not in shm:
        abort(400)

    wxcpt = WXBizMsgCrypt(shm[module]['token'], shm[module]
                          ['encodingaeskey'], shm[module]['corpid'])
    ret, plain_msg = wxcpt.DecryptMsg(
        request.data,
        request.args['msg_signature'],
        request.args['timestamp'],
        request.args['nonce'],
    )
    if ret:
        app.logger.error('ERR in DecryptMsg: %s', ret)
        abort(500)
    app.logger.debug('plain_msg: %s', plain_msg)

    # 加密回复信息
    ret, encrypted_msg = wxcpt.EncryptMsg(
        '<xml><ToUserName><![CDATA[{}]]></ToUserName><FromUserName><![CDATA[{}]]></FromUserName><CreateTime>{}</CreateTime><MsgType><![CDATA[text]]></MsgType><Content><![CDATA[{}]]></Content></xml>'.format(
            ET.fromstring(plain_msg).find("FromUserName").text,
            shm[module]['corpid'],
            request.args['timestamp'],
            f"no route for \"{module}\"\necho: {plain_msg}",
        ),
        request.args['nonce'],
        request.args['timestamp'],
    )
    if ret:
        app.logger.error('ERR in EncryptMsg: %s', ret)
        abort(500)
    return encrypted_msg


@app.route('/push/rm', methods=['POST'])
def handle_rm():
    ''' 支持Http Post请求接收业务数据

    https://developer.work.weixin.qq.com/document/path/90930#32-%E6%94%AF%E6%8C%81http-post%E8%AF%B7%E6%B1%82%E6%8E%A5%E6%94%B6%E4%B8%9A%E5%8A%A1%E6%95%B0%E6%8D%AE

    '''
    wxcpt = WXBizMsgCrypt(
        shm['rm']['token'],
        shm['rm']['encodingaeskey'],
        shm['rm']['corpid'],
    )
    ret, plain_msg = wxcpt.DecryptMsg(
        request.data,
        request.args['msg_signature'],
        request.args['timestamp'],
        request.args['nonce'],
    )
    if ret:
        app.logger.error('ERR in DecryptMsg: %s', ret)
        abort(500)
    app.logger.debug('plain_msg: %s', plain_msg)

    reply_content = ''
    xml_tree = ET.fromstring(plain_msg)
    msg_type = xml_tree.find("MsgType").text
    g.user = xml_tree.find("FromUserName").text

    match msg_type:
        case 'event':
            event = xml_tree.find("Event").text
            match event:
                case 'click':
                    # 菜单事件
                    event_key = xml_tree.find("EventKey").text
                    match event_key:
                        case 'RM_KNOCK':
                            app.logger.info('%s: event/click/RM_KNOCK', g.user)
                            reply_content = handle_click_RM_KNOCK(
                                g.user, g.client_ip)
                        case 'RM_QUEUE':
                            app.logger.info('%s: event/click/RM_QUEUE', g.user)
                            reply_content = handle_click_RM_QUEUE(
                                g.user, g.client_ip)
                        case _:
                            app.logger.debug(
                                '%s: (unhandled) event/click/%s', g.user, event_key)
                case 'subscribe':
                    app.logger.info('{}: event/subscribe'.format(g.user))
                    reply_content = handle_subscribe(g.user, g.client_ip)
                case 'view':
                    # 打开网页事件
                    event_key = xml_tree.find("EventKey").text
                    app.logger.info('%s: event/view -> %s', g.user, event_key)
                case _:
                    app.logger.debug('%s: (unhandled) event/%s', g.user, event)
        case _:
            app.logger.debug('%s: (unhandled) %s', g.user, msg_type)

    # 加密回复信息
    app.logger.debug('reply_content: %s', reply_content)
    ret, encrypted_msg = wxcpt.EncryptMsg(
        '<xml><ToUserName><![CDATA[{}]]></ToUserName><FromUserName><![CDATA[{}]]></FromUserName><CreateTime>{}</CreateTime><MsgType><![CDATA[text]]></MsgType><Content><![CDATA[{}]]></Content></xml>'.format(
            g.user,
            shm['rm']['corpid'],
            request.args['timestamp'],
            reply_content
        ),
        request.args['nonce'],
        request.args['timestamp'],
    )
    if ret:
        app.logger.error('ERR in EncryptMsg: %s', ret)
        abort(500)

    return encrypted_msg


def handle_click_RM_KNOCK(user_id: str, srcip: str) -> str:
    token = requests.get(
        f"{shm['rm']['forward']}/utils/genToken?user_id={user_id}"
    ).text
    r = requests.post(
        f"{shm['rm']['forward']}/api/mail",
        headers={
            'Authorization': f"Bearer {token}",
            'X-Forwarded-For': srcip,
        },
        json={},
    ).json()
    if r['result']:
        reply_content = f"[打机器人] 请求失败\nerr: {r['err']}"
    else:
        reply_content = '[打机器人] 已加入处理队列'
    return reply_content


def handle_click_RM_QUEUE(user_id: str, srcip: str) -> str:
    token = requests.get(
        f"{shm['rm']['forward']}/utils/genToken?user_id={user_id}"
    ).text
    r = requests.post(
        f"{shm['rm']['forward']}/api/queue/list",
        headers={
            'Authorization': f"Bearer {token}",
            'X-Forwarded-For': srcip,
        },
        json={}
    ).json()
    if r['result']:
        reply_content = f"- [审核队列] -\n\n请求失败: {r['err']}"
        return reply_content
    next_user_name = r['data']['queue'][0]['name'] \
        if r['data']['queue'][0]['id'] != user_id else r['data']['queue'][1]['name']
    reply_content = f"- [审核队列] -\n\n下一顺位: {next_user_name}"

    for reviewer in r['data']['queue']:
        if reviewer['id'] == user_id:
            if reviewer['status'] == 0:
                status = '空闲'
            elif reviewer['status'] == 1:
                status = '不审加急'
            elif reviewer['status'] == 2:
                status = '不审报告'
            else:
                status = '未知'
            reply_content += '\n你的顺位: {}{}\n你的状态: {}{}\n当前任务: {}'.format(
                reviewer['priority'] if reviewer['status'] != 2 else '-',
                f" (+{reviewer['pages_diff']}页)" if reviewer['pages_diff'] else '',
                status,
                '（跳过一篇）' if reviewer['skipped'] == 1 else '',
                reviewer['current'],
            )
            break
    return reply_content


def handle_subscribe(user_id: str, srcip: str) -> str:
    token = requests.get(
        f"{shm['rm']['forward']}/utils/genToken?user_id={user_id}"
    ).text
    r = requests.post(
        f"{shm['rm']['forward']}/api/user/info",
        headers={
            'Authorization': f"Bearer {token}",
            'X-Forwarded-For': srcip,
        },
        json={}
    ).json()
    if r['result']:
        reply_content = '通知：启用\n用户：{}（无用户信息）'.format(user_id)
    else:
        is_reviewer = '是' if r['data']['user']['role'] else '否'
        reply_content = '通知：启用\n用户：{}\n审核人：{}'.format(
            r['data']['user']['name'],
            is_reviewer,
        )
    return reply_content
