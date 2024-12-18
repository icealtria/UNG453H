import telnetlib3
import requests
import sys
import asyncio
import re
import argparse

def enable_telnet():
    target_url = "http://192.168.1.1/boaform/set_telnet_enabled_url.cgi"
    data = {"telnet_port": "23", "telnet_lan_enabled": "1", "telnet_wan_enabled": "0"}
    try:
        response = requests.post(target_url, data=data)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Failed to enable telnet: {e}")
        sys.exit(1)

async def connect_telnet(host, port, username, password):
    try:
        reader, writer = await telnetlib3.open_connection(host, port)
        await reader.readuntil(b'login: ')
        writer.write(username + '\n')
        await reader.readuntil(b'Password:')
        writer.write(password + '\n')

        while True:
            chunk = await reader.read(1024)
            if not chunk:
                break
            if 'Login incorrect' in chunk:
                print("登录失败：密码错误")
                writer.close()
                sys.exit(1)
            elif '$ ' in chunk:
                break

        writer.write('cat /config/workb/backup_lastgood.xml\n')
        
        output = []
        while True:
            chunk = await reader.read(1024)
            if not chunk:
                break
            output.append(chunk)
            if '$ ' in chunk:
                break
        
        output = ''.join(output)
                
        super_pattern = r'aucTeleAccountName"\s+Value="([^"]+)"[^\n]*\n[^\n]*aucTeleAccountPassword"\s+Value="([^"]+)"'
        pppoe_pattern = r'aucUsername"\s+Value="([^"]+@[^"]+)"[^\n]*\n[^\n]*aucPassword"\s+Value="([^"]+)"'
        
        super_match = re.search(super_pattern, output)
        if super_match:
            print(f"账号: {super_match.group(1)}")
            print(f"密码: {super_match.group(2)}")
        
        pppoe_match = re.search(pppoe_pattern, output)
        if pppoe_match:
            print(f"pppoe 账号: {pppoe_match.group(1)}")
            print(f"pppoe 密码: {pppoe_match.group(2)}")
        
        writer.close()
        
    except Exception as e:
        print(f"Telnet connection failed: {e}")
        sys.exit(1)

async def main():
    HOST = "192.168.1.1"
    PORT = 23
    USERNAME = "user"
    
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--password')
    args = parser.parse_args()
    
    PASSWORD = args.password if args.password else input("路由器密码: ")
    
    enable_telnet()
    await connect_telnet(HOST, PORT, USERNAME, PASSWORD)

    input("\n按回车键退出...")

def cli():
    asyncio.run(main())

if __name__ == "__main__":
    cli()