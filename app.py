# -*- coding: UTF-8 -*-
from flask import Flask, request, abort
import os.path
import datetime
from configparser import ConfigParser
import xml.etree.ElementTree as ET
import requests
from weworkapi_callback.WXBizMsgCrypt3 import WXBizMsgCrypt


app = Flask(__name__)
app.logger.setLevel('DEBUG')
config = ConfigParser()
config.read(os.path.join('conf', 'wxwork.conf'), encoding='UTF-8')
app.config['MODULES'] = config
cache = {}
for section in app.config['MODULES']:
    if section == 'DEFAULT':
        continue
    cache[section] = {
        'access_token': '',
        'expires_in': datetime.datetime.fromtimestamp(0),
    }


@app.post('/message/send/<module>')
def send_text(module):
    ''' 向列表中的用户发送text
    
    https://developer.work.weixin.qq.com/document/path/90236#%E6%96%87%E6%9C%AC%E6%B6%88%E6%81%AF

    Args:
        content: 通知内容
        to: 发送对象的userid列表
    '''
    parsed_data = request.get_json(force=True)
    app.logger.debug('args: %s', {
        'module': module, 'content': parsed_data['content'], 'to': parsed_data['to']
    })
    if module not in app.config['MODULES']:
        abort(404)

    try:
        url = f"https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token={get_access_token(module)}"
        r = requests.post(url, json={
            'touser': parsed_data['to'],
            'msgtype': 'text',
            'agentid': app.config['MODULES'][module]['agentid'],
            'text': {'content': parsed_data['content']}
        }).json()
        app.logger.debug('message/send response: %s', r)
        if r['errcode']:
            app.logger.error('message/send error: %s', r['errmsg'])
            return 500, r
    except:
        app.logger.error('message/send error', exc_info=True)
        return 500, {}
    return r


def get_access_token(module):
    ''' 检测access_token是否过期，并自动刷新
    '''
    global cache
    if datetime.datetime.now() < cache[module]['expires_in']:
        return cache[module]['access_token']
    session = requests.session()
    url = f"https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={app.config['MODULES'][module]['corpid']}&corpsecret={app.config['MODULES'][module]['secret']}"
    for _ in range(3):
        try:
            r = session.get(url).json()
            app.logger.debug('gettoken response: %s', r)
            if r['errcode']:
                app.logger.warning('gettoken error: %s', r['errmsg'])
                continue
            if cache[module]['access_token'] != r['access_token']:
                cache[module]['access_token'] = r['access_token']
                cache[module]['expires_in'] = datetime.datetime.now() + \
                    datetime.timedelta(seconds=r['expires_in'] - 600)
                app.logger.info('refreshed access_token')
            return cache[module]['access_token']
        except:
            app.logger.warning('gettoken error', exc_info=True)
    else:
        raise RuntimeError('Cannot get access_token.')


@app.get('/callback/<module>')
def verify_URL(module):
    ''' 支持Http Get请求验证URL有效性

    https://developer.work.weixin.qq.com/document/path/90930#31-%E6%94%AF%E6%8C%81http-get%E8%AF%B7%E6%B1%82%E9%AA%8C%E8%AF%81url%E6%9C%89%E6%95%88%E6%80%A7

    '''
    if module not in app.config['MODULES']:
        abort(404)

    wxcpt = WXBizMsgCrypt(
        app.config['MODULES'][module]['token'],
        app.config['MODULES'][module]['encodingaeskey'],
        app.config['MODULES'][module]['corpid'],
    )
    ret, plain_echostr = wxcpt.VerifyURL(
        request.args['msg_signature'],
        request.args['timestamp'],
        request.args['nonce'],
        request.args['echostr'],
    )
    if ret:
        app.logger.error('ERR in VerifyURL: %s', ret)
        abort(500, ret)
    app.logger.debug('plain_echostr: %s', plain_echostr)
    return plain_echostr


@app.post('/callback/<module>')
def handle_default(module):
    ''' 支持Http Post请求接收业务数据

    https://developer.work.weixin.qq.com/document/path/90930#32-%E6%94%AF%E6%8C%81http-post%E8%AF%B7%E6%B1%82%E6%8E%A5%E6%94%B6%E4%B8%9A%E5%8A%A1%E6%95%B0%E6%8D%AE

    '''
    if module not in app.config['MODULES']:
        abort(404)

    wxcpt = WXBizMsgCrypt(
        app.config['MODULES'][module]['token'],
        app.config['MODULES'][module]['encodingaeskey'],
        app.config['MODULES'][module]['corpid'],
    )
    ret, plain_msg = wxcpt.DecryptMsg(
        request.data,
        request.args['msg_signature'],
        request.args['timestamp'],
        request.args['nonce'],
    )
    if ret:
        app.logger.error('ERR in DecryptMsg: %s', ret)
        abort(500, ret)
    app.logger.debug('plain_msg: %s', plain_msg)

    # 加密回复信息
    ret, encrypted_msg = wxcpt.EncryptMsg(
        '<xml><ToUserName><![CDATA[{}]]></ToUserName><FromUserName><![CDATA[{}]]></FromUserName><CreateTime>{}</CreateTime><MsgType><![CDATA[text]]></MsgType><Content><![CDATA[{}]]></Content></xml>'.format(
            ET.fromstring(plain_msg).find("FromUserName").text,
            app.config['MODULES'][module]['corpid'],
            request.args['timestamp'],
            f"no route for \"{module}\"\necho: {plain_msg}",
        ),
        request.args['nonce'],
        request.args['timestamp'],
    )
    if ret:
        app.logger.error('ERR in EncryptMsg: %s', ret)
        abort(500, ret)
    return encrypted_msg


@app.post('/callback/rm')
def handle_rm():
    ''' 支持Http Post请求接收业务数据

    https://developer.work.weixin.qq.com/document/path/90930#32-%E6%94%AF%E6%8C%81http-post%E8%AF%B7%E6%B1%82%E6%8E%A5%E6%94%B6%E4%B8%9A%E5%8A%A1%E6%95%B0%E6%8D%AE

    '''
    wxcpt = WXBizMsgCrypt(
        app.config['MODULES']['rm']['token'],
        app.config['MODULES']['rm']['encodingaeskey'],
        app.config['MODULES']['rm']['corpid'],
    )
    ret, plain_msg = wxcpt.DecryptMsg(
        request.data,
        request.args['msg_signature'],
        request.args['timestamp'],
        request.args['nonce'],
    )
    if ret:
        app.logger.error('ERR in DecryptMsg: %s', ret)
        abort(500, ret)
    app.logger.debug('plain_msg: %s', plain_msg)

    reply_content = ''
    xml_tree = ET.fromstring(plain_msg)
    msg_type = xml_tree.find("MsgType").text
    from_user = xml_tree.find("FromUserName").text

    match msg_type:
        case 'event':
            event = xml_tree.find("Event").text
            match event:
                case 'click':
                    # 菜单事件
                    event_key = xml_tree.find("EventKey").text
                    match event_key:
                        case 'RM_KNOCK':
                            app.logger.info('%s: event/click/RM_KNOCK', from_user)
                            reply_content = handle_click_RM_KNOCK(from_user)
                        case 'RM_QUEUE':
                            app.logger.info('%s: event/click/RM_QUEUE', from_user)
                            reply_content = handle_click_RM_QUEUE(from_user)
                        case _:
                            app.logger.debug(
                                '%s: (unhandled) event/click/%s', from_user, event_key)
                case 'subscribe':
                    app.logger.info('%s: event/subscribe', from_user)
                    reply_content = handle_subscribe(from_user)
                case 'view':
                    # 打开网页事件
                    event_key = xml_tree.find("EventKey").text
                    app.logger.info('%s: event/view -> %s', from_user, event_key)
                case _:
                    app.logger.debug('%s: (unhandled) event/%s', from_user, event)
        case _:
            app.logger.debug('%s: (unhandled) %s', from_user, msg_type)

    # 加密回复信息
    app.logger.debug('reply_content: %s', reply_content)
    ret, encrypted_msg = wxcpt.EncryptMsg(
        '<xml><ToUserName><![CDATA[{}]]></ToUserName><FromUserName><![CDATA[{}]]></FromUserName><CreateTime>{}</CreateTime><MsgType><![CDATA[text]]></MsgType><Content><![CDATA[{}]]></Content></xml>'.format(
            from_user,
            app.config['MODULES']['rm']['corpid'],
            request.args['timestamp'],
            reply_content
        ),
        request.args['nonce'],
        request.args['timestamp'],
    )
    if ret:
        app.logger.error('ERR in EncryptMsg: %s', ret)
        abort(500, ret)

    return encrypted_msg


def handle_click_RM_KNOCK(user_id: str) -> str:
    token = requests.get(
        f"{app.config['MODULES']['rm']['forward']}/utils/genToken?user_id={user_id}"
    ).text
    r = requests.post(
        f"{app.config['MODULES']['rm']['forward']}/api/mail",
        headers={
            'Authorization': f"Bearer {token}",
            'X-Forwarded-For': request.environ.get("HTTP_X_FORWARDED_FOR", request.remote_addr),
        },
        json={},
    ).json()
    if r['result']:
        reply_content = f"[打机器人] 请求失败\nerr: {r['err']}"
    else:
        reply_content = '[打机器人] 已加入处理队列'
    return reply_content


def handle_click_RM_QUEUE(user_id: str) -> str:
    token = requests.get(
        f"{app.config['MODULES']['rm']['forward']}/utils/genToken?user_id={user_id}"
    ).text
    r = requests.post(
        f"{app.config['MODULES']['rm']['forward']}/api/queue/list",
        headers={
            'Authorization': f"Bearer {token}",
            'X-Forwarded-For': request.environ.get("HTTP_X_FORWARDED_FOR", request.remote_addr),
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


def handle_subscribe(user_id: str) -> str:
    token = requests.get(
        f"{app.config['MODULES']['rm']['forward']}/utils/genToken?user_id={user_id}"
    ).text
    r = requests.post(
        f"{app.config['MODULES']['rm']['forward']}/api/user/info",
        headers={
            'Authorization': f"Bearer {token}",
            'X-Forwarded-For': request.environ.get("HTTP_X_FORWARDED_FOR", request.remote_addr),
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


if __name__ == "__main__":
    app.run(debug=True)
