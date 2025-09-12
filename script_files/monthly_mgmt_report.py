
#pip install openpyxl
#python3 script_files/monthly_mgmt_report.py ea 2 February 2022  ---> from WSL
#-------------------
import sys
import pandas as pd
import sqlite3
pd.set_option('display.max_rows', 20)
from datetime import date, datetime
from openpyxl import Workbook
from openpyxl import load_workbook
import time

start_time = time.time()


########Vars##############
cust_id = sys.argv[1]
month = int(sys.argv[2])
mon_name = str(sys.argv[3])
year = int(sys.argv[4])
path_d = f'./database_files/{cust_id}/'
path_r = f'./report_files/{cust_id}/'
##########################


con = sqlite3.connect(path_d + 'database_'+cust_id+'.sqlite')
#data = pd.read_csv("C:\\DATA\\Scripts\\Pull data from Vision by Marcelo\\AutoReport_v3.9\\report_files\\USCC\\USCC 10 2021 attacks.csv", parse_dates=['startDate','endDate'], dtype={"name": "string","attackIpsId":"string","actionType":"string","risk":"string"})
data = pd.read_sql_query("SELECT * from attacks", con)
con.close()

data_month = data[(data.month == month) & (data.year == year)] # data for the speicific month

if month !=1:
    data_month_prev = data[(data.month == (month -1)) & (data.year == year)] # data for the speicific month
else:
    data_month_prev = data[(data.month == (month -1)) & (data.year == (year -1))] # data for the speicific month


## Events count count this month with previous month ##############################

total_events = data_month.name.count()
total_events_prev = data_month_prev.name.count()

events_delta = int(total_events) - float(total_events_prev)

if events_delta > 0:
    print(f'\r\nIncrease of {int(abs(events_delta))} events this month compared to the previous month.\r\n')
if events_delta < 0:
    print(f'\r\nDecrease of {int(abs(events_delta))} events this month compared to the previous month.\r\n')


## Maplicious packets count this month with previous month ##############################

total_mal_pkts = float(data_month['packetCount'].sum()/1000000)
total_mal_pkts_prev = float(data_month_prev['packetCount'].sum()/1000000)

pkts_delta = float(total_mal_pkts) - float(total_mal_pkts_prev)

if pkts_delta > 0:
    print(f'Increase of {format(abs(int(pkts_delta)), ",d")} Mil in malicious packets this month compared to the previous month.\r\n')
if pkts_delta < 0:
    print(f'Decrease of {format(abs(int(pkts_delta)), ",d")} Mil in malicious packets this month compared to the previous month.\r\n')

## Maplicious bandwidth count this month with previous month ##############################

total_mal_bw = float(data_month['packetBandwidth'].sum()/8000000000)
total_mal_bw_prev = float(data_month_prev['packetBandwidth'].sum()/8000000000)

bw_delta = float(total_mal_bw) - float(total_mal_bw_prev)
if bw_delta > 0:
    print(f'Increase of {"{:.2f}".format(abs(bw_delta))} TB in malicious bandwidth this month compared to the previous month.\r\n')
if bw_delta < 0:
    print(f'Decrease of {"{:.2f}".format(abs(bw_delta))} TB in malicious bandwidth this month compared to the previous month.\r\n')

## High level management Summary ##################################################################

print(f'{cust_id} on-premise Radware appliances scrubbed {"{:.2f}".format(float(total_mal_bw))}TB of attack traffic to protect titles and services.\r\n')

## Top #1 Attack summary by packet count ####################################

device = data_month.sort_values(by=['packetCount'], ascending=False).iloc[0]['deviceName']
policy = data_month.sort_values(by=['packetCount'], ascending=False).iloc[0]['ruleName']
attack_cat = data_month.sort_values(by=['packetCount'], ascending=False).iloc[0]['category']
attack_name = data_month.sort_values(by=['packetCount'], ascending=False).iloc[0]['name']
src_ip = data_month.sort_values(by=['packetCount'], ascending=False).iloc[0]['sourceAddress']
dst_ip = data_month.sort_values(by=['packetCount'], ascending=False).iloc[0]['destAddress']
attack_bw = ((data_month.sort_values(by=['packetCount'], ascending=False).iloc[0]['packetBandwidth'])/8000000)
attack_pkt = format((data_month.sort_values(by=['packetCount'], ascending=False).iloc[0]['packetCount']), ',d')
duration = (data_month.sort_values(by=['packetCount'], ascending=False).iloc[0]['endTime'])-(data_month.sort_values(by=['packetCount'], ascending=False).iloc[0]['startTime'])
dur = str('{:.1f}'.format(float(duration/60000))) + ' min /' + str(int(duration/1000)) + ' sec'
attack_start = data_month.sort_values(by=['packetCount'], ascending=False).iloc[0]['startDate']
attack_id = data_month.sort_values(by=['packetCount'], ascending=False).iloc[0]['attackIpsId']
attack_maxpps = data_month.sort_values(by=['packetCount'], ascending=False).iloc[0]['maxAttackPacketRatePps']
attack_maxbps = data_month.sort_values(by=['packetCount'], ascending=False).iloc[0]['maxAttackRateBps']


print(f"#1 attack by packet count:\r\n")
print(f"Threat Category: {attack_cat} ")
print(f"Attack Name: {attack_name}")
print(f"Attack source: {src_ip}")
print(f"Attack destination: {dst_ip}")
print(f"Attack date(UTC): {attack_start}")
print(f"Attack total packets: {attack_pkt}")
print(f"Attack total data: {'{:.2f}'.format(float(attack_bw))} GB")
print(f"Attack rate(PPS): {format(int(attack_maxpps), ',d')}")
print(f"Attack rate(Gbps): {'{:.2f}'.format(float(attack_maxbps/1000000000))} Gbps")
print(f"Attacked device: {device}")
print(f"Attacked policy: {policy}")
print(f"Attack duration: {dur}\r\n\r\n")



# print(f"The most aggressive DDoS attack mitigated by Radware Attack Mitigation Service by total attack packet count was a {attack_cat} type {attack_name}.\r\n  \
# The attack occured on {attack_start}(UTC), directed at destination IP {dst_ip} , dropping cumulatively {attack_pkt} packets, {attack_bw} GB, lasting {dur}")


## Top #1 Attack summary by bandwidth ####################################

device = data_month.sort_values(by=['packetBandwidth'], ascending=False).iloc[0]['deviceName']
policy = data_month.sort_values(by=['packetBandwidth'], ascending=False).iloc[0]['ruleName']
attack_cat = data_month.sort_values(by=['packetBandwidth'], ascending=False).iloc[0]['category']
attack_name = data_month.sort_values(by=['packetBandwidth'], ascending=False).iloc[0]['name']
src_ip = data_month.sort_values(by=['packetBandwidth'], ascending=False).iloc[0]['sourceAddress']
dst_ip = data_month.sort_values(by=['packetBandwidth'], ascending=False).iloc[0]['destAddress']
attack_bw = ((data_month.sort_values(by=['packetBandwidth'], ascending=False).iloc[0]['packetBandwidth'])/8000000)
attack_pkt = format((data_month.sort_values(by=['packetBandwidth'], ascending=False).iloc[0]['packetCount']), ',d')
duration = (data_month.sort_values(by=['packetBandwidth'], ascending=False).iloc[0]['endTime'])-(data_month.sort_values(by=['packetBandwidth'], ascending=False).iloc[0]['startTime'])
dur = str('{:.1f}'.format(float(duration/60000))) + ' min /' + str(int(duration/1000)) + ' sec'
attack_start = data_month.sort_values(by=['packetBandwidth'], ascending=False).iloc[0]['startDate']
attack_id = data_month.sort_values(by=['packetBandwidth'], ascending=False).iloc[0]['attackIpsId']
attack_maxpps = data_month.sort_values(by=['packetBandwidth'], ascending=False).iloc[0]['maxAttackPacketRatePps']
attack_maxbps = data_month.sort_values(by=['packetBandwidth'], ascending=False).iloc[0]['maxAttackRateBps']


print(f"Top #1 attack by total attack traffic in GB:\r\n")
print(f"Threat Category: {attack_cat} ")
print(f"Attack Name: {attack_name}")
print(f"Attack source: {src_ip}")
print(f"Attack destination: {dst_ip}")
print(f"Attack date(UTC): {attack_start}")
print(f"Attack total packets: {attack_pkt}")
print(f"Attack total data: {'{:.2f}'.format(float(attack_bw))} GB")
print(f"Attack rate(PPS): {format(int(attack_maxpps), ',d')}")
print(f"Attack rate(Gbps): {'{:.2f}'.format(float(attack_maxbps/1000000000))} Gbps")
print(f"Attacked device: {device}")
print(f"Attacked policy: {policy}")
print(f"Attack duration: {dur}\r\n\r\n")


# print(f"The most aggressive DDoS attack mitigated by Radware Attack Mitigation Service by attack bandwidth was {attack_cat} type {attack_name}.\r\n  \
# The attack occured on {attack_start}(UTC), directed at destination IP {dst_ip} , dropping cumulatively {attack_pkt} packets, {attack_bw} GB, lasting {dur}\r\n\r\n")

## Top #1 Attack summary by Max Gbps rate ####################################

device = data_month.sort_values(by=['maxAttackRateBps'], ascending=False).iloc[0]['deviceName']
policy = data_month.sort_values(by=['maxAttackRateBps'], ascending=False).iloc[0]['ruleName']
attack_cat = data_month.sort_values(by=['maxAttackRateBps'], ascending=False).iloc[0]['category']
attack_name = data_month.sort_values(by=['maxAttackRateBps'], ascending=False).iloc[0]['name']
src_ip = data_month.sort_values(by=['maxAttackRateBps'], ascending=False).iloc[0]['sourceAddress']
dst_ip = data_month.sort_values(by=['maxAttackRateBps'], ascending=False).iloc[0]['destAddress']
attack_bw = ((data_month.sort_values(by=['maxAttackRateBps'], ascending=False).iloc[0]['packetBandwidth'])/8000000)
attack_pkt = format((data_month.sort_values(by=['maxAttackRateBps'], ascending=False).iloc[0]['packetCount']), ',d')
duration = (data_month.sort_values(by=['maxAttackRateBps'], ascending=False).iloc[0]['endTime'])-(data_month.sort_values(by=['maxAttackRateBps'], ascending=False).iloc[0]['startTime'])
dur = str('{:.1f}'.format(float(duration/60000))) + ' min /' + str(int(duration/1000)) + ' sec'
attack_start = data_month.sort_values(by=['maxAttackRateBps'], ascending=False).iloc[0]['startDate']
attack_id = data_month.sort_values(by=['maxAttackRateBps'], ascending=False).iloc[0]['attackIpsId']
attack_maxpps = data_month.sort_values(by=['maxAttackRateBps'], ascending=False).iloc[0]['maxAttackPacketRatePps']
attack_maxbps = data_month.sort_values(by=['maxAttackRateBps'], ascending=False).iloc[0]['maxAttackRateBps']


print(f"Top #1 attack by max Gbps rate:\r\n")
print(f"Threat Category: {attack_cat} ")
print(f"Attack Name: {attack_name}")
print(f"Attack source: {src_ip}")
print(f"Attack destination: {dst_ip}")
print(f"Attack date(UTC): {attack_start}")
print(f"Attack total packets: {attack_pkt}")
print(f"Attack total data: {'{:.2f}'.format(float(attack_bw))} GB")
print(f"Attack rate(PPS): {format(int(attack_maxpps), ',d')}")
print(f"Attack rate(Gbps): {'{:.2f}'.format(float(attack_maxbps/1000000000))} Gbps")
print(f"Attacked device: {device}")
print(f"Attacked policy: {policy}")
print(f"Attack duration: {dur}\r\n\r\n")


print(f'The most aggressive DDoS attack mitigated by Radware on-premise equipment was a {attack_cat} type {attack_name}. The attack occurred on {attack_start}(UTC) lasting {dur.split()[0].split("/")[0]} min, directed at destination IP {dst_ip} at peak rate of {"{:.2f}".format(float(attack_maxbps/1000000000))} Gbps. The mitigation equipment dropped cumulatively {attack_pkt} packets for a total of {"{:.2f}".format(float(attack_bw))} GB data during this attack.')


# print(f"The most aggressive DDoS attack mitigated by Radware Attack Mitigation Service by max Gbps rate was {attack_cat} type {attack_name}.\r\n  \
# The attack occured on {attack_start}(UTC), directed at destination IP {dst_ip} , dropping cumulatively {attack_pkt} packets, {attack_bw} GB, lasting {dur}\r\n\r\n")


## Top #1 Attack summary by Max PPS rate rate ####################################

device = data_month.sort_values(by=['maxAttackPacketRatePps'], ascending=False).iloc[0]['deviceName']
policy = data_month.sort_values(by=['maxAttackPacketRatePps'], ascending=False).iloc[0]['ruleName']
attack_cat = data_month.sort_values(by=['maxAttackPacketRatePps'], ascending=False).iloc[0]['category']
attack_name = data_month.sort_values(by=['maxAttackPacketRatePps'], ascending=False).iloc[0]['name']
src_ip = data_month.sort_values(by=['maxAttackPacketRatePps'], ascending=False).iloc[0]['sourceAddress']
dst_ip = data_month.sort_values(by=['maxAttackPacketRatePps'], ascending=False).iloc[0]['destAddress']
attack_bw = (data_month.sort_values(by=['maxAttackPacketRatePps'], ascending=False).iloc[0]['packetBandwidth'])/8000000
attack_pkt = format((data_month.sort_values(by=['maxAttackPacketRatePps'], ascending=False).iloc[0]['packetCount']), ',d')
duration = (data_month.sort_values(by=['maxAttackPacketRatePps'], ascending=False).iloc[0]['endTime'])-(data_month.sort_values(by=['maxAttackPacketRatePps'], ascending=False).iloc[0]['startTime'])
dur = str('{:.1f}'.format(float(duration/60000))) + ' min /' + str(int(duration/1000)) + ' sec'
attack_start = data_month.sort_values(by=['maxAttackPacketRatePps'], ascending=False).iloc[0]['startDate']
attack_id = data_month.sort_values(by=['maxAttackPacketRatePps'], ascending=False).iloc[0]['attackIpsId']
attack_maxpps = data_month.sort_values(by=['maxAttackPacketRatePps'], ascending=False).iloc[0]['maxAttackPacketRatePps']
attack_maxbps = data_month.sort_values(by=['maxAttackPacketRatePps'], ascending=False).iloc[0]['maxAttackRateBps']


print(f"Top #1 attack by max PPS rate:\r\n")
print(f"Threat Category: {attack_cat} ")
print(f"Attack Name: {attack_name}")
print(f"Attack source: {src_ip}")
print(f"Attack destination: {dst_ip}")
print(f"Attack date(UTC): {attack_start}")
print(f"Attack total packets: {attack_pkt}")
print(f"Attack total data: {'{:.2f}'.format(float(attack_bw))} GB")
print(f"Attack rate(PPS): {format(int(attack_maxpps), ',d')}")
print(f"Attack rate(Gbps): {'{:.2f}'.format(float(attack_maxbps/1000000000))} Gbps")
print(f"Attacked device: {device}")
print(f"Attacked policy: {policy}")
print(f"Attack duration: {dur}\r\n\r\n")


# print(f'The most aggressive DDoS attack mitigated by Radware on-premise equipment by total attack packet count was a {attack_cat} type {attack_name}. The attack occurred on {attack_start} lasting {dur} minutes, directed at destination IP {dst_ip}. The mitigation equipment dropped cumulatively {attack_pkt} packets for a total of {attack_bw} GB data during this attack.')


print("--- %s seconds ---" % (time.time() - start_time))
