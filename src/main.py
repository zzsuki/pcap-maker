from data.payloads import playload_list
from data.constant import LOGO
from utils.packet import Client, Server, TCPFlow, UDPFlow
from prettytable import PrettyTable
import click
import random
import os

# pylint: disable=unused-argument

@click.command()
@click.help_option('-h', '--help', help='Show this help message and exit.')
def cli():
    """
    通信包生成工具，支持内置的payload生成对应的pcap包，可用于suricata规则测试
    """
    click.echo(LOGO)
    click.echo('Welcome to use this tool!')
    while True:
        keyword = click.prompt(text='[+]请输入黑名单关键字(忽略大小写，未输入则默认全部黑名单)', type=str, default="", show_default=False)
        click.echo(keyword)
        if not keyword:
            matched = playload_list
        else:
            matched = [payload for payload in playload_list if keyword in payload.get('name', '')]
        if not matched:
            click.echo(click.style("未在已支持的黑名单名称中查找到对应关键字", fg='red'))
            continue
        x = PrettyTable()
        x.field_names = ['序号', '名称', 'sid']
        x.add_rows([[i, payload.get("name", ""), payload.get("sid", "")]for i, payload in enumerate(matched, 1)])
        click.echo(x)
        while True:
            sid = click.prompt(text='输入目标sid进行相应流量包的生成(未输入则将全部导出)', type=int, default=-1, show_default=False)
            if sid == -1:
                selected = matched
            else:
                selected = [payload for payload in matched if sid == payload.get('sid', 0)]
            if not selected:
                click.echo(x)
                click.echo(click.style("检索结果中未发现对应sid，请重新输入", fg='yellow'))
                continue
            # batched = click.prompt(text='是否批量生成(默认单个生成，即每条结果生成一个pcap包)', type=bool, default=False, show_default=False)
            for payload in selected:
                sport = payload.get('sport', None) or random.randint(30000, 65535)
                dport = payload.get('dport', None) or random.randint(10000, 30000)
                sip = payload.get('sip', '192.168.0.3')
                dip = payload.get('dip', '192.168.0.4')
                client = Client(ip=sip, port=sport, mac='4c:ed:fb:73:54:6b')
                server = Server(ip=dip, port=dport, mac='00:17:c8:61:d0:16')
                if payload.get('pro', None) == 'TCP':
                    flow = TCPFlow(client, server)
                elif payload.get('pro', None) == 'UDP':
                    flow = UDPFlow(client, server)
                default_data = [{'payload': b'', 'direction': '0'}]
                for content in payload.get('data', default_data):
                    flow.send(content.get('payload', b''), content.get('direction', '0'))
                flow.dump(os.path.join('/mnt/bl-pcaps', f'{payload.get("sid", 0)}.pcap'))
            click.echo(click.style("生成完成", fg='green'))



if __name__ == '__main__':
    # for payload in playload_list:
    #     sport = payload.get('sport', None) or random.randint(30000, 65535)
    #     dport = payload.get('dport', None) or random.randint(10000, 30000)
    #     sip = payload.get('sip', None) or '192.168.0.3'
    #     dip = payload.get('dip', None) or '192.168.0.4'
    #     client = Client(ip='192.168.0.3', port=sport, mac='4c:ed:fb:73:54:6b')
    #     server = Server(ip='192.168.0.4', port=dport, mac='00:17:c8:61:d0:16')
    #     if payload.get('pro', None) == 'TCP':
    #         flow = TCPFlow(client, server)
    #     elif payload.get('pro', None) == 'UDP':
    #         flow = UDPFlow(client, server)
    #     flow.send(payload.get('data', b''))
    #     flow.dump(f'{payload.get("sid", 0)}.pcap')
    # pylint: disable=no-value-for-parameter
    cli()
