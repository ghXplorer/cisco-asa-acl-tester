import os
import re
import sys
import yaml
import pyperclip
from getpass import getpass
from netmiko import ConnectHandler


def packet_tracer(device_name, acl_entries_final):
    '''Test an ASA access-list and add missing entries to it if needed'''

    os.system('color')
    ALLOWED = '\x1b[6;30;42m' + 'ALLOWED!' + '\x1b[0m'
    DENIED = '\x1b[6;37;41m' + 'DENIED!' + '\x1b[0m'

    ace_first = acl_entries_final[0]
    src_ip = re.search(r'(tcp|udp).*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', ace_first).group(2)

    net_connect = ConnectHandler(**device_name)

    output_show_route = net_connect.send_command('sh route {}'.format(src_ip))
    for i in output_show_route.splitlines():
        intf_match = re.search(r'via ([a-zA-Z0-9_-]+$)', i)
        if intf_match:
            pkt_tracer_intf = intf_match.group(1)
            print('\nInbound interface name:', pkt_tracer_intf)
            break
    else:
        output_show_route = net_connect.send_command('sh route 0.0.0.0')
        for i in output_show_route.splitlines():
            intf_match = re.search(r'via ([a-zA-Z0-9_-]+$)', i)
            if intf_match:
                pkt_tracer_intf = intf_match.group(1)
                print('\nInbound interface name:', pkt_tracer_intf)
                break

    packet_tracer_commands = []
    for ace in acl_entries_final:
        components = re.search(r'(tcp|udp).*?'
                                '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?'
                                '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?'
                                '(\d+)', ace)
        
        packet_tracer_commands.append('packet-tracer input {} {} {} 10240 {} {} xml'.format(
                                                                                   pkt_tracer_intf,
                                                                                   components.group(1),
                                                                                   components.group(2),
                                                                                   components.group(3),
                                                                                   components.group(4)))
    output_sh_run_acl_group = net_connect.send_command('sh run access-group')
    regex_pattern = r'access-group ([a-zA-Z0-9_-]+) in interface {}'.format(pkt_tracer_intf)
    for i in output_sh_run_acl_group.splitlines():
        intf_match = re.search(regex_pattern, i)
        if intf_match:
            acl_name = intf_match.group(1)
            print('ACL name:', intf_match.group(1), '\n')
            break
    
    acl_to_configure = []
    for index, command_entry in enumerate(packet_tracer_commands):
        output = net_connect.send_command(command_entry)
        for line in output.splitlines():
            search_result = re.search(r'<action>(\w+)</action>', line)
            if search_result:
                if search_result.group(1) == 'allow':
                    print(f'{command_entry} --> {ALLOWED}')
                    for line_x in output.splitlines():
                        search_result_x = re.search(r'access-list.*', line_x)
                        if search_result_x:
                            print('\t', search_result_x.group())
                            print()
                            break
                    for line in output.splitlines():
                        search_result_nat = re.search(r'Untranslate\s+([0-9.]+)/.+to\s+([0-9.]+)/', line)
                        if search_result_nat and (search_result_nat.group(1) != search_result_nat.group(2)):
                            print(f'\t\tNAT to {search_result_nat.group(2)} performed.\n')
                elif search_result.group(1) == 'drop':
                    print(f'{command_entry} --> {DENIED}')
                    for line_y in output.splitlines():
                        search_result_y = re.search(r'<drop-reason>(.+)</drop-reason>', line_y)
                        if search_result_y:
                            print('\t Reason:', search_result_y.group(1))
                            print()
                            break
                    for line in output.splitlines():
                        search_result_nat = re.search(r'Untranslate\s+([0-9.]+)/.+to\s+([0-9.]+)/', line)
                        if search_result_nat and (search_result_nat.group(1) != search_result_nat.group(2)):
                            print(f'\t\tNAT to {search_result_nat.group(2)} required.\n')
                            acl_to_configure.append(re.sub(r'(host.*host) ([0-9.]+)',
                                                           r'\1 ' + f'{search_result_nat.group(2)}',
                                                           acl_entries_final[index]))
                            break
                    else:
                        acl_to_configure.append(acl_entries_final[index])
                else:
                    print(f'{command_entry} --> UNKNOWN ACTION')

    if len(acl_to_configure) == 0:
        print('\nNo additional access-list entries need to be configured.')
    else:
        print('\n\nThe following ACL entries should be configured:\n')
        acl_name_replacement = r'access-list {} '.format(acl_name)
        config_commands = []
        for ace in acl_to_configure:
            ace_final = re.sub(r'access-list ([a-zA-Z0-9_-]+) ', acl_name_replacement, ace)
            config_commands.append(ace_final)
            print(ace_final)

        full_access_answer = input('\nWould you like to add full TCP/UDP acceess for these access rules (default - NO, y - YES)?:')
        print()
        config_commands_temp = []
        if full_access_answer == 'y':
            for line in config_commands:
                config_commands_temp.append(line.split()[:-2])
            config_commands.clear()
            for line in config_commands_temp:
                config_commands.append(' '.join(line))
            config_commands = list(set(config_commands))
            for line in config_commands:
                print(line)

        config_answer = input(f'\nWould you like to add these access rules to the ACL: {acl_name}? (y/n):')
        if config_answer == 'y':
            print('\nAdding rules to the ACL and saving config...')
            net_connect.send_config_set(config_commands)
            net_connect.send_command('write memory')
            print('\nDone.\n')
    
    print('\nClosing SSH session to the firewall...')
    net_connect.disconnect()
    print('Done.')


def main():
    username = 'ENTER_USERNAME_HERE'
    secret_pass = getpass('\nEnter your password: ')
    
    with open(r'./myscripts/net_devices.yml', 'r') as file:
            asa_params = yaml.load(file, Loader=yaml.FullLoader)
    
    acl_entries_final_range = [line for line in pyperclip.paste().splitlines() if len(line) != 0]
    print('\nACL contains {} entries:\n'.format(len(acl_entries_final_range)))
    for i in acl_entries_final_range:
        print(i)
   
    while True:
        answer = input('\nWould you like to test these ACL entries with packet-tracer on a firewall (y/n): ')
        
        msg = '''
        Choose the firewall:
        
        ASA_1  ----------  1
        ASA_2  ----------  2
        ASA_3  ----------  3
        
        : '''
        
        if answer == 'y':
            fw_number = int(input(msg))
            if fw_number == 1:
                print('\nTesting on ASA_1...\n')
                asa_params['asa_device_1']['username'] = username
                asa_params['asa_device_1']['password'] = secret_pass
                packet_tracer(asa_params['asa_device_1'], acl_entries_final_range)
            elif fw_number == 2:
                print('\nTesting on ASA_2...\n')
                asa_params['asa_device_2']['username'] = username
                asa_params['asa_device_2']['password'] = secret_pass
                packet_tracer(asa_params['asa_device_2'], acl_entries_final_range)
            elif fw_number == 3:
                print('\nTesting on ASA_3...\n')
                asa_params['asa_device_3']['username'] = username
                asa_params['asa_device_3']['password'] = secret_pass
                packet_tracer(asa_params['asa_device_3'], acl_entries_final_range)
        else:
            print('\nBye!')
            sys.exit()


if __name__ == '__main__':
    main()
