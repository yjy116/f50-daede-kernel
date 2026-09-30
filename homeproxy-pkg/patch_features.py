"""Patch only reviewed capability detection and visible F50 limitations."""
import hashlib
from pathlib import Path

from model import HERE, require

RPC_SHA = '9085d4f67735e549c7b0a636f6d23f56de46fc6bc3e6acfc56026679f96da3e3'
CLIENT_SHA = '532fa635a2050e5f15298af4fe5504cff9a5ff4b2d8b6bd866239dab48148736'
NOTICE = 'F50: UDP process-name, process-path and UID matching are unavailable on this kernel. Other routing conditions remain available.'


def replace_once(text, old, new):
    require(text.count(old) == 1, 'Patch anchor drift')
    return text.replace(old, new, 1)


def patch_rpc(content):
    require(hashlib.sha256(content).hexdigest() == RPC_SHA, 'RPC source SHA mismatch')
    text = content.decode()
    helper = (HERE / 'kernel_features.uc').read_text()
    text = replace_once(text, "const HP_DIR =", helper + "\nconst HP_DIR =")
    text = replace_once(text, 'let features = {};', 'let features = {};\n\t\t\tconst builtin = readBuiltinFeatures();')
    for name, symbol in [('tproxy', 'NFT_TPROXY'), ('tun', 'TUN')]:
        old = f'features.hp_has_{name} = '
        text = replace_once(text, old, old + f"builtin['CONFIG_{symbol}'] || ")
    return text.encode()


def patch_client(content):
    require(hashlib.sha256(content).hexdigest() == CLIENT_SHA, 'Client source SHA mismatch')
    anchor = "m = new form.Map('homeproxy', _('HomeProxy'),"
    return replace_once(content.decode(), anchor, anchor + "\n\t\t\t_('" + NOTICE + "') + '<br />' +").encode()


def patch_ui(source):
    patches = {'root/usr/share/rpcd/ucode/luci.homeproxy': patch_rpc,
               'htdocs/luci-static/resources/view/homeproxy/client.js': patch_client}
    for name, transform in patches.items():
        path = source / name
        path.write_bytes(transform(path.read_bytes()))
    po = source / 'po/zh_Hans/homeproxy.po'
    with po.open('a', encoding='utf-8') as stream:
        stream.write('\nmsgid "' + NOTICE + '"\nmsgstr "F50 当前内核不支持 UDP 连接的进程名、进程路径及 UID 匹配；其他路由条件仍可使用。"\n')
    return [*patches, 'po/zh_Hans/homeproxy.po']
