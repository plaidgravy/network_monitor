from time import sleep
import yaml
import io
import nmap
import slack
from config import CONFIG


class SlackHelper():

    def __init__(self):
        self.client = slack.WebClient(token=CONFIG['SLACK_API_TOKEN'])
        self.icon = 'https://66.media.tumblr.com/avatar_57661298164b_96.pnj'

    def post_message(self, channel, txt):
        if CONFIG['ENABLE_SLACK']:
            response = self.client.chat_postMessage(
                as_user=False,
                username='Moss',
                icon_url=self.icon,
                channel=channel,
                text=txt)
            assert response["ok"]
            # assert response["message"]["text"] == txt
        else:
            print('Slack messages are disabled')

    def post_blocks(self, channel, blocks):
        if CONFIG['ENABLE_SLACK']:
            response = self.client.chat_postMessage(
                as_user=False,
                username='Moss',
                icon_url=self.icon,
                channel=channel,
                text='TEST',
                blocks=blocks
            )
            assert response["ok"]
            # assert response["message"]["text"] == txt
        else:
            print('Slack messages are disabled')


class NetworkMonitor:
    nm = None

    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan_subnet(self):
        self.nm.scan(hosts=CONFIG['SUBNET_TO_SCAN'], arguments='-n -sn -PE -PA21,23,80,3389')

        hosts = []
        for x in self.nm.all_hosts():
            hosts.append(self.nm[x])

        return hosts

    def deep_scan(self, ipv4):
        self.nm.scan(hosts=ipv4, arguments='-sS -F -A')

        return self.nm[ipv4]

    def prepare_deepscan_results(self, mac, result):
        blocks = []

        try:
            if result['hostnames'][0]['name'] != '':
                blocks.append({
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Hostname*\n{result['hostnames'][0]['name']}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Type*\n{result['hostnames'][0]['type']}"
                        }
                    ]
                })
        except:
            pass

        try:
            blocks.append({
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*IPv4*\n{result['addresses']['ipv4']}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*OS*\n{result['osmatch'][0]['name']}"
                    }
                ]
            })
        except:
            pass

        try:
            blocks.append({
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*MAC*\n{result['addresses']['mac']}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Vender*\n{result['vendor'][mac]}"
                    }
                ]
            })
        except:
            pass

        try:
            blocks.append({
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Up Time*\n{result['uptime']['seconds']}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Last Boot*\n{result['uptime']['lastboot']}"
                    }
                ]
            })
        except:
            pass

        ports = []
        if 'tcp' in result:
            for port in result['tcp']:
                try:
                    if result['tcp'][port]['state'] != 'filtered':
                        ports.append({
                            "type": "mrkdwn",
                            "text": f"*{result['tcp'][port]['name']} ({port})*\n{result['tcp'][port]['state']}"
                        })
                except:
                    pass

        if len(ports) > 0:
            blocks.append({
                "type": "section",
                "fields": ports
            })

        return blocks


class DB():
    db = None

    def __init__(self):
        self.read_db()

    def read_db(self):
        with open("db.yaml", 'r') as stream:
            try:
                self.db = yaml.safe_load(stream)
                # print(self.db)
            except yaml.YAMLError as exc:
                print(exc)

    def mac_exists(self, mac):
        if mac in self.db['macs']['whitelist']:
            return True
        elif mac in self.db['macs']['greylist']:
            return True
        elif mac in self.db['macs']['blacklist']:
            return True
        return False

    def add_mac_greylist(self, mac):
        self.db['macs']['greylist'].append(mac)
        self.update_db()

    def update_db(self):
        # Write YAML file
        with io.open('db.yaml', 'w', encoding='utf8') as outfile:
            yaml.dump(self.db, outfile, default_flow_style=False, allow_unicode=True)


def main():
    print('Network Monitor')
    # print('---------------')

    # Read DB
    # print('Loading database:')
    db = DB()

    # Initialize Slack Client
    slack_helper = SlackHelper()

    # Initialize Network Scanner
    monitor = NetworkMonitor()

    # Main Loop
    while True:

        # Scan Network
        # print('Scanning network...')
        try:
            hosts = monitor.scan_subnet()
        except:
            print('Exception during scanning!')
            hosts = []

        # Check results for new MACs
        # print(f'Found hosts: {len(hosts)}')
        for host in hosts:
            # print(host)
            if 'mac' in host['addresses']:
                mac = host['addresses']['mac']
                if not db.mac_exists(mac):
                    print(f"Found a new device on the network: {host['addresses']['ipv4']} ({mac})")
                    slack_helper.post_message(CONFIG['SLACK_CHANNEL'], f"Found a new device on the network: {host['addresses']['ipv4']} ({mac})")
                    slack_helper.post_message(CONFIG['SLACK_CHANNEL'], f"Performing deep scan of {host['addresses']['ipv4']}")


                    # Deep scan
                    print(f"Performing deep scan of {host['addresses']['ipv4']}")
                    try:
                        result = monitor.deep_scan(host['addresses']['ipv4'])

                        # Notify
                        slack_helper.post_blocks(CONFIG['SLACK_CHANNEL'], monitor.prepare_deepscan_results(mac, result))
                    except:
                        slack_helper.post_message(CONFIG['SLACK_CHANNEL'],
                                                  f"Deep scan of {host['addresses']['ipv4']} failed!")

                    # Update DB
                    db.add_mac_greylist(mac)

        # Sleep
        sleep(CONFIG['SLEEP_TIME'])
        # print('-------------------------------------------------')


if __name__ == '__main__':
    main()
