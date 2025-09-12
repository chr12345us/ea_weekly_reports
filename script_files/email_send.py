import smtplib
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email import encoders
from datetime import datetime
import sqlite3
import pandas as pd
import os
import sys
import tarfile

# sys.path.insert(0, './script_files')
# from epm_bar_chart import df as epm_bar_chart

cust_id = sys.argv[1]
#print(f'argv1 {cust_id}')

currentmonth = int(sys.argv[2]) #actual it will work on the previous month from today

#create 

currentyear = int(sys.argv[3])

smtp_auth = sys.argv[4]
if smtp_auth == "true":
        smtp_auth = True
else:
        smtp_auth = False

#print(smtp_auth)

smtp_server = sys.argv[5] # SMTP server name
#print(smtp_server)

smtp_server_port= sys.argv[6] # SMTP server port
#print(smtp_server_port)

smtp_sender = sys.argv[7] # Email sender address setting
#print(smtp_sender)

smtp_password = sys.argv[8] # Email password (optional)
#print(smtp_password)

smtp_list = sys.argv[10:] # Email address/address list recepient/s(comma separated)

smtp_subject_prefix = sys.argv[9] # Email Subject


path_r = f'./report_files/{cust_id}/'
path_d = f'./database_files/{cust_id}/'

if currentmonth != 1:
        #if under 10 then add a 0 to the front
        
        prevmonth = int(currentmonth) - 1


        if currentmonth < 10:
                currentmonth = f'0{currentmonth}'
        else:
                currentmonth = currentmonth

        if prevmonth < 10:
                prevmonth = f'0{prevmonth}'
        else:
                prevmonth = prevmonth
        
if currentmonth == 1:

    currentmonth = f'0{currentmonth}'
    prevmonth = 12

prevyear = int(currentyear) - 1






def email_body(cust_id):

        prevmon_exists = False

        if currentmonth != 1: # if the report is not for the first month of the year.
                con1 = sqlite3.connect(path_d + 'database_'+cust_id+'_'+str(currentmonth)+ '_' + str(currentyear)+ '.sqlite')
                data_month =      pd.read_sql_query(f"SELECT deviceName,packetBandwidth,name,packetCount,ruleName,category,sourceAddress,destAddress,startTime,endTime,startDate,attackIpsId,maxAttackPacketRatePps,maxAttackRateBps from attacks", con1)
                con1.close()

                #if file exists
                if os.path.isfile(path_d + 'database_'+cust_id+'_'+str(prevmonth)+ '_' + str(currentyear)+ '.sqlite'):
                        prevmon_exists = True
                        con2 = sqlite3.connect(path_d + 'database_'+cust_id+'_'+str(prevmonth)+ '_' + str(currentyear)+ '.sqlite')
                        data_month_prev = pd.read_sql_query(f"SELECT deviceName,packetBandwidth,name,packetCount,ruleName,category,sourceAddress,destAddress,startTime,endTime,startDate,attackIpsId,maxAttackPacketRatePps,maxAttackRateBps from attacks", con2)
                        con2.close()


        else: 

                con1 = sqlite3.connect(path_d + 'database_'+cust_id+'_'+str(currentmonth)+ '_' + str(currentyear)+ '.sqlite')
                data_month = pd.read_sql_query(f"SELECT deviceName,packetBandwidth,name,packetCount,ruleName,category,sourceAddress,destAddress,startTime,endTime,startDate,attackIpsId,maxAttackPacketRatePps,maxAttackRateBps from attacks", con1)
                con1.close()

                if os.path.isfile(path_d + 'database_'+cust_id+'_'+str(12)+ '_' + str(prevyear)+ '.sqlite'):
                        prevmon_exists=True
                        con2 = sqlite3.connect(path_d + 'database_'+cust_id+'_'+str(12)+ '_' + str(prevyear)+ '.sqlite')
                        data_month_prev = pd.read_sql_query(f"SELECT deviceName,packetBandwidth,name,packetCount,ruleName,category,sourceAddress,destAddress,startTime,endTime,startDate,attackIpsId,maxAttackPacketRatePps,maxAttackRateBps from attacks", con2)
                        con2.close()


        ############# High Level Management summary#######################

        email_body = f'\r\n\r\nHigh Level Management summary:'

        if cust_id == 'EA':
                total_mal_bw = '{:.2f}'.format(float(data_month['packetBandwidth'].sum()/8000000))

                #print(f'total ma bw is {total_mal_bw}')
                total_mal_bw_iad1 = '{:.2f}'.format(float(data_month[(data_month.deviceName == "10.76.4.241")]['packetBandwidth'].sum()/8000000))
                        
                total_mal_bw_catchall = '{:.2f}'.format(float(data_month[(data_month.name == "catchall-PPS")]['packetBandwidth'].sum()/8000000))
                #print(total_mal_bw_catchall)
                #print(f'total mal bw iad is {total_mal_bw_iad1}')
                total_mal_bw_no_iad1 = float(total_mal_bw) - float(total_mal_bw_iad1) - float(total_mal_bw_catchall)
                total_mal_bw_no_iad1_tb = '{:.2f}'.format(total_mal_bw_no_iad1/1000)
                #print(f'total mal bw no iad is {total_mal_bw_no_iad1}')
                        
                html_summary = f"EA’s on-premise Radware appliances scrubbed {total_mal_bw_no_iad1_tb}TB of attack traffic to protect titles and services. This left {total_mal_bw_iad1}GB of detected attack traffic unmitigated and was absorbed by the infrastructure."
             
        else:
                total_mal_bw = '{:.2f}'.format(float(data_month['packetBandwidth'].sum()/8000000000))

                html_summary = f"{cust_id}’s on-premises Radware appliances scrubbed {total_mal_bw}TB of attack traffic to protect titles and services."

        ###########Setting variables for Top #1 by max Gbps#################
        device_maxAttackRateBps = data_month.sort_values(by=['maxAttackRateBps'], ascending=False).iloc[0]['deviceName']
        policy_maxAttackRateBps = data_month.sort_values(by=['maxAttackRateBps'], ascending=False).iloc[0]['ruleName']
        attack_cat_maxAttackRateBps = data_month.sort_values(by=['maxAttackRateBps'], ascending=False).iloc[0]['category']
        attack_name_maxAttackRateBps = data_month.sort_values(by=['maxAttackRateBps'], ascending=False).iloc[0]['name']
        src_ip_maxAttackRateBps = data_month.sort_values(by=['maxAttackRateBps'], ascending=False).iloc[0]['sourceAddress']
        dst_ip_maxAttackRateBps = data_month.sort_values(by=['maxAttackRateBps'], ascending=False).iloc[0]['destAddress']
        attack_bw_maxAttackRateBps = ((data_month.sort_values(by=['maxAttackRateBps'], ascending=False).iloc[0]['packetBandwidth'])/8000000)
        attack_bw_maxAttackRateBps_formatted = "{:.2f}".format(float(attack_bw_maxAttackRateBps))
        attack_pkt_maxAttackRateBps = format((data_month.sort_values(by=['maxAttackRateBps'], ascending=False).iloc[0]['packetCount']), ',d')
        duration_maxAttackRateBps = (data_month.sort_values(by=['maxAttackRateBps'], ascending=False).iloc[0]['endTime'])-(data_month.sort_values(by=['maxAttackRateBps'], ascending=False).iloc[0]['startTime'])
        dur_maxAttackRateBps = str('{:.1f}'.format(float(duration_maxAttackRateBps/60000))) + ' min /' + str(int(duration_maxAttackRateBps/1000)) + ' sec'
        dur_maxAttackRateBps_min = dur_maxAttackRateBps.split()[0].split("/")[0]
        attack_start_maxAttackRateBps = data_month.sort_values(by=['maxAttackRateBps'], ascending=False).iloc[0]['startDate']
        attack_id_maxAttackRateBps = data_month.sort_values(by=['maxAttackRateBps'], ascending=False).iloc[0]['attackIpsId']
        attack_maxpps_maxAttackRateBps = data_month.sort_values(by=['maxAttackRateBps'], ascending=False).iloc[0]['maxAttackPacketRatePps']
        attack_maxbps_maxAttackRateBps = data_month.sort_values(by=['maxAttackRateBps'], ascending=False).iloc[0]['maxAttackRateBps']
        attack_maxbps_maxAttackRateBps_formatted = "{:.2f}".format(float(attack_maxbps_maxAttackRateBps/1000000000))
        

       ## Events count count this month with previous month ##############################

        if prevmon_exists:

                total_events = data_month.name.count()
                total_events_prev = data_month_prev.name.count()
                

                events_delta = int(total_events) - int(total_events_prev)

                if events_delta > 0:
                        events_text = f'This month, the number of events has increased from {total_events_prev} to {total_events} by a total of {events_delta} events compared to the previous month.'


                if events_delta < 0:
                        events_delta = abs(events_delta)
                        events_text = f'This month, the number of events has decreased from {total_events_prev} to {total_events} by a total of {events_delta} events compared to the previous month.'

                if events_delta == 0:
                        events_text = f'This month, the number of events remained the same as a previous month - {total_events} events in total.'

        else:
                events_text = f'No data collected for the previous month.'

        ## Maplicious packets count this month with previous month ##############################

        if prevmon_exists:

                total_mal_pkts = float(data_month['packetCount'].sum()/1000000)
                total_mal_pkts_prev = float(data_month_prev['packetCount'].sum()/1000000)

                pkts_delta = float(total_mal_pkts) - float(total_mal_pkts_prev)

                if pkts_delta > 0:
                        pkts_text = f'This month, the number of malicious packets has increased from {format(int(total_mal_pkts_prev), ",d")} Mil to {format(int(total_mal_pkts), ",d")} Mil by a total of {format(abs(int(pkts_delta)), ",d")} Mil, compared to the previous month.'

                if pkts_delta < 0:
                        pkts_text = f'This month, the number of malicious packets has decreased from {format(int(total_mal_pkts_prev), ",d")} Mil to {format(int(total_mal_pkts), ",d")} Mil by a total of {format(abs(int(pkts_delta)), ",d")} Mil, compared to the previous month.'

                if pkts_delta == 0:
                        pkts_text = f'This month, the number of malicious packets remained the same as a previous month - {format(int(total_mal_pkts), ",d")} Mil malicious packets in total.'

        else:
                pkts_text = f'No data collected for the previous month.'

        ## Maplicious bandwidth count this month with previous month ##############################

        if prevmon_exists:
    
                total_mal_bw = float(data_month['packetBandwidth'].sum()/8000000000)
                total_mal_bw_prev = float(data_month_prev['packetBandwidth'].sum()/8000000000)

                bw_delta = float(total_mal_bw) - float(total_mal_bw_prev)

                if bw_delta > 0:
                        bw_text = f'This month, the amount of malicious bandwidth has increased from {"{:.2f}".format(abs(total_mal_bw_prev))} TB to {"{:.2f}".format(abs(total_mal_bw))} TB by a total of {"{:.2f}".format(abs(bw_delta))} TB, compared to the previous month.'

                if bw_delta < 0:
                        bw_text = f'This month, the amount of malicious bandwidth has decreased from {"{:.2f}".format(abs(total_mal_bw_prev))} TB to {"{:.2f}".format(abs(total_mal_bw))} TB by a total of {"{:.2f}".format(abs(bw_delta))} TB, compared to the previous month.'

                if bw_delta == 0:
                        bw_text = f'This month, the amount of malicious bandwidth remained the same as a previous month - {"{:.2f}".format(abs(total_mal_bw))} TB of malicious bandwidth in total.'

        else:
                bw_text = f'No data collected for the previous month.'


        ######### Top #1 Attack summary by packet count ####################################

        email_body = email_body + f'\r\n\r\nTop attacks of the month\r\n\r\n'

        device_packetCount = data_month.sort_values(by=['packetCount'], ascending=False).iloc[0]['deviceName']
        policy_packetCount = data_month.sort_values(by=['packetCount'], ascending=False).iloc[0]['ruleName']
        attack_cat_packetCount = data_month.sort_values(by=['packetCount'], ascending=False).iloc[0]['category']
        attack_name_packetCount = data_month.sort_values(by=['packetCount'], ascending=False).iloc[0]['name']
        src_ip_packetCount = data_month.sort_values(by=['packetCount'], ascending=False).iloc[0]['sourceAddress']
        dst_ip_packetCount = data_month.sort_values(by=['packetCount'], ascending=False).iloc[0]['destAddress']
        attack_bw_packetCount = ((data_month.sort_values(by=['packetCount'], ascending=False).iloc[0]['packetBandwidth'])/8000000)
        attack_pkt_packetCount = format((data_month.sort_values(by=['packetCount'], ascending=False).iloc[0]['packetCount']), ',d')
        duration_packetCount = (data_month.sort_values(by=['packetCount'], ascending=False).iloc[0]['endTime'])-(data_month.sort_values(by=['packetCount'], ascending=False).iloc[0]['startTime'])
        dur_packetCount = str('{:.1f}'.format(float(duration_packetCount/60000))) + ' min /' + str(int(duration_packetCount/1000)) + ' sec'
        attack_start_packetCount = data_month.sort_values(by=['packetCount'], ascending=False).iloc[0]['startDate']
        attack_id_packetCount = data_month.sort_values(by=['packetCount'], ascending=False).iloc[0]['attackIpsId']
        attack_maxpps_packetCount = data_month.sort_values(by=['packetCount'], ascending=False).iloc[0]['maxAttackPacketRatePps']
        attack_maxbps_packetCount = data_month.sort_values(by=['packetCount'], ascending=False).iloc[0]['maxAttackRateBps']

        html_attack_cat_packetCount = f"Threat Category: {attack_cat_packetCount}"
        html_attack_name_packetCount = f"Attack Name: {attack_name_packetCount}"
        html_src_ip_packetCount = f"Attack source: {src_ip_packetCount}"
        html_dst_ip_packetCount = f"Attack destination: {dst_ip_packetCount}"
        html_attack_start_packetCount = f"Attack date(UTC): {attack_start_packetCount}"
        html_attack_pkt_packetCount = f"Attack total packets: {attack_pkt_packetCount}"
        html_attack_bw_packetCount = f"Attack total data: {'{:.2f}'.format(float(attack_bw_packetCount))} GB"
        html_attack_maxpps_packetCount = f"Attack rate(PPS): {format(int(attack_maxpps_packetCount), ',d')}"
        html_attack_maxbps_packetCount = f"Attack rate(Gbps): {'{:.2f}'.format(float(attack_maxbps_packetCount/1000000000))} Gbps"
        html_device_packetCount = f"Attacked device: {device_packetCount}"
        html_policy_packetCount = f"Attacked policy: {policy_packetCount}"
        html_dur_packetCount = f"Attack duration: {dur_packetCount}"
        html_attack_id_packetCount = f"Attack ID: {attack_id_packetCount}"

        email_body = email_body + f"#1 attack by packet count:\r\n\r\n"
        email_body = email_body + f"Threat Category: {attack_cat_packetCount}\r\n"
        email_body = email_body + f"Attack Name: {attack_name_packetCount}\r\n"
        email_body = email_body + f"Attack source: {src_ip_packetCount}\r\n"
        email_body = email_body + f"Attack destination: {dst_ip_packetCount}\r\n"
        email_body = email_body + f"Attack date(UTC): {attack_start_packetCount}\r\n"
        email_body = email_body + f"Attack total packets: {attack_pkt_packetCount}\r\n"
        email_body = email_body + f"Attack total data: {'{:.2f}'.format(float(attack_bw_packetCount))} GB\r\n"
        email_body = email_body + f"Attack rate(PPS): {format(int(attack_maxpps_packetCount), ',d')}\r\n"
        email_body = email_body + f"Attack rate(Gbps): {'{:.2f}'.format(float(attack_maxbps_packetCount/1000000000))} Gbps\r\n"
        email_body = email_body + f"Attacked device: {device_packetCount}\r\n"
        email_body = email_body + f"Attacked policy: {policy_packetCount}\r\n"
        email_body = email_body + f"Attack duration: {dur_packetCount}\r\n\r\n"
        email_body = email_body + f"Attack ID: {attack_id_packetCount}\r\n\r\n"

        ## Top #1 Attack summary by bandwidth ####################################

        device_packetBandwidth = data_month.sort_values(by=['packetBandwidth'], ascending=False).iloc[0]['deviceName']
        policy_packetBandwidth = data_month.sort_values(by=['packetBandwidth'], ascending=False).iloc[0]['ruleName']
        attack_cat_packetBandwidth = data_month.sort_values(by=['packetBandwidth'], ascending=False).iloc[0]['category']
        attack_name_packetBandwidth = data_month.sort_values(by=['packetBandwidth'], ascending=False).iloc[0]['name']
        src_ip_packetBandwidth = data_month.sort_values(by=['packetBandwidth'], ascending=False).iloc[0]['sourceAddress']
        dst_ip_packetBandwidth = data_month.sort_values(by=['packetBandwidth'], ascending=False).iloc[0]['destAddress']
        attack_bw_packetBandwidth = ((data_month.sort_values(by=['packetBandwidth'], ascending=False).iloc[0]['packetBandwidth'])/8000000)
        attack_pkt_packetBandwidth = format((data_month.sort_values(by=['packetBandwidth'], ascending=False).iloc[0]['packetCount']), ',d')
        duration_packetBandwidth = (data_month.sort_values(by=['packetBandwidth'], ascending=False).iloc[0]['endTime'])-(data_month.sort_values(by=['packetBandwidth'], ascending=False).iloc[0]['startTime'])
        dur_packetBandwidth = str('{:.1f}'.format(float(duration_packetBandwidth/60000))) + ' min /' + str(int(duration_packetBandwidth/1000)) + ' sec'
        attack_start_packetBandwidth = data_month.sort_values(by=['packetBandwidth'], ascending=False).iloc[0]['startDate']
        attack_id_packetBandwidth = data_month.sort_values(by=['packetBandwidth'], ascending=False).iloc[0]['attackIpsId']
        attack_maxpps_packetBandwidth = data_month.sort_values(by=['packetBandwidth'], ascending=False).iloc[0]['maxAttackPacketRatePps']
        attack_maxbps_packetBandwidth = data_month.sort_values(by=['packetBandwidth'], ascending=False).iloc[0]['maxAttackRateBps']

        html_attack_cat_packetBandwidth = f"Threat Category: {attack_cat_packetBandwidth}"
        html_attack_name_packetBandwidth = f"Attack Name: {attack_name_packetBandwidth}"
        html_src_ip_packetBandwidth = f"Attack source: {src_ip_packetBandwidth}"
        html_dst_ip_packetBandwidth = f"Attack destination: {dst_ip_packetBandwidth}"
        html_attack_start_packetBandwidth = f"Attack date(UTC): {attack_start_packetBandwidth}"
        html_attack_pkt_packetBandwidth = f"Attack total packets: {attack_pkt_packetBandwidth}"
        html_attack_bw_packetBandwidth = f"Attack total data: {'{:.2f}'.format(float(attack_bw_packetBandwidth))} GB"
        html_attack_maxpps_packetBandwidth = f"Attack rate(PPS): {format(int(attack_maxpps_packetBandwidth), ',d')}"
        html_attack_maxbps_packetBandwidth = f"Attack rate(Gbps): {'{:.2f}'.format(float(attack_maxbps_packetBandwidth/1000000000))} Gbps"
        html_device_packetBandwidth = f"Attacked device: {device_packetBandwidth}"
        html_policy_packetBandwidth = f"Attacked policy: {policy_packetBandwidth}"
        html_dur_packetBandwidth = f"Attack duration: {dur_packetBandwidth}"
        html_attack_id_packetBandwidth = f"Attack ID: {attack_id_packetBandwidth}"

        email_body = email_body + f"Top #1 attack by total attack traffic in GB:\r\n\r\n"
        email_body = email_body + f"Threat Category: {attack_cat_packetBandwidth}\r\n"
        email_body = email_body + f"Attack Name: {attack_name_packetBandwidth}\r\n"
        email_body = email_body + f"Attack source: {src_ip_packetBandwidth}\r\n"
        email_body = email_body + f"Attack destination: {dst_ip_packetBandwidth}\r\n"
        email_body = email_body + f"Attack date(UTC): {attack_start_packetBandwidth}\r\n"
        email_body = email_body + f"Attack total packets: {attack_pkt_packetBandwidth}\r\n"
        email_body = email_body + f"Attack total data: {'{:.2f}'.format(float(attack_bw_packetBandwidth))} GB\r\n"
        email_body = email_body + f"Attack rate(PPS): {format(int(attack_maxpps_packetBandwidth), ',d')}\r\n"
        email_body = email_body + f"Attack rate(Gbps): {'{:.2f}'.format(float(attack_maxbps_packetBandwidth/1000000000))} Gbps\r\n"
        email_body = email_body + f"Attacked device: {device_packetBandwidth}\r\n"
        email_body = email_body + f"Attacked policy: {policy_packetBandwidth}\r\n"
        email_body = email_body + f"Attack duration: {dur_packetBandwidth}\r\n\r\n"
        email_body = email_body + f"Attack ID: {attack_id_packetBandwidth}\r\n\r\n"


        ## Top #1 Attack summary by Max Gbps rate ####################################

            #Variables set earlier

        html_attack_cat_maxAttackRateBps = f"Threat Category: {attack_cat_maxAttackRateBps}"
        html_attack_name_maxAttackRateBps = f"Attack Name: {attack_name_maxAttackRateBps}"
        html_dst_ip_maxAttackRateBps = f"Attack destination: {dst_ip_maxAttackRateBps}"
        html_src_ip_maxAttackRateBps = f"Attack source: {src_ip_maxAttackRateBps}"
        html_attack_start_maxAttackRateBps = f"Attack date(UTC): {attack_start_maxAttackRateBps}"
        html_attack_pkt_maxAttackRateBps = f"Attack total packets: {attack_pkt_maxAttackRateBps}"
        html_attack_bw_maxAttackRateBps_formatted = f"Attack total data: {attack_bw_maxAttackRateBps_formatted} GB"
        html_attack_maxpps_maxAttackRateBps = f"Attack rate(PPS): {format(int(attack_maxpps_maxAttackRateBps), ',d')}"
        html_attack_maxbps_maxAttackRateBps_formatted = f"Attack rate(Gbps): {attack_maxbps_maxAttackRateBps_formatted} Gbps"
        html_device_maxAttackRateBps = f"Attacked device: {device_maxAttackRateBps}"
        html_policy_maxAttackRateBps = f"Attacked policy: {policy_maxAttackRateBps}"
        html_dur_maxAttackRateBps = f"Attack duration: {dur_maxAttackRateBps}"
        html_attack_id_maxAttackRateBps = f"Attack ID: {attack_id_maxAttackRateBps}"


        email_body = email_body + f"Top #1 attack by max Gbps rate:\r\n\r\n"
        email_body = email_body + f"Threat Category: {attack_cat_maxAttackRateBps}\r\n"
        email_body = email_body + f"Attack Name: {attack_name_maxAttackRateBps}\r\n"
        email_body = email_body + f"Attack source: {src_ip_maxAttackRateBps}\r\n"
        email_body = email_body + f"Attack destination: {dst_ip_maxAttackRateBps}\r\n"
        email_body = email_body + f"Attack date(UTC): {attack_start_maxAttackRateBps}\r\n"
        email_body = email_body + f"Attack total packets: {attack_pkt_maxAttackRateBps}\r\n"
        email_body = email_body + f"Attack total data: {attack_bw_maxAttackRateBps_formatted} GB\r\n"
        email_body = email_body + f"Attack rate(PPS): {format(int(attack_maxpps_maxAttackRateBps), ',d')}\r\n"
        email_body = email_body + f"Attack rate(Gbps): {attack_maxbps_maxAttackRateBps_formatted} Gbps\r\n"
        email_body = email_body + f"Attacked device: {device_maxAttackRateBps}\r\n"
        email_body = email_body + f"Attacked policy: {policy_maxAttackRateBps}\r\n"
        email_body = email_body + f"Attack duration: {dur_maxAttackRateBps}\r\n\r\n"
        email_body = email_body + f"Attack ID: {attack_id_maxAttackRateBps}\r\n\r\n"
        

        ## Top #1 Attack summary by Max PPS rate rate ####################################

        device_maxAttackPacketRatePps = data_month.sort_values(by=['maxAttackPacketRatePps'], ascending=False).iloc[0]['deviceName']
        policy_maxAttackPacketRatePps = data_month.sort_values(by=['maxAttackPacketRatePps'], ascending=False).iloc[0]['ruleName']
        attack_cat_maxAttackPacketRatePps = data_month.sort_values(by=['maxAttackPacketRatePps'], ascending=False).iloc[0]['category']
        attack_name_maxAttackPacketRatePps = data_month.sort_values(by=['maxAttackPacketRatePps'], ascending=False).iloc[0]['name']
        src_ip_maxAttackPacketRatePps = data_month.sort_values(by=['maxAttackPacketRatePps'], ascending=False).iloc[0]['sourceAddress']
        dst_ip_maxAttackPacketRatePps = data_month.sort_values(by=['maxAttackPacketRatePps'], ascending=False).iloc[0]['destAddress']
        attack_bw_maxAttackPacketRatePps = (data_month.sort_values(by=['maxAttackPacketRatePps'], ascending=False).iloc[0]['packetBandwidth'])/8000000
        attack_pkt_maxAttackPacketRatePps = format((data_month.sort_values(by=['maxAttackPacketRatePps'], ascending=False).iloc[0]['packetCount']), ',d')
        duration_maxAttackPacketRatePps = (data_month.sort_values(by=['maxAttackPacketRatePps'], ascending=False).iloc[0]['endTime'])-(data_month.sort_values(by=['maxAttackPacketRatePps'], ascending=False).iloc[0]['startTime'])
        dur_maxAttackPacketRatePps = str('{:.1f}'.format(float(duration_maxAttackPacketRatePps/60000))) + ' min /' + str(int(duration_maxAttackPacketRatePps/1000)) + ' sec'
        attack_start_maxAttackPacketRatePps = data_month.sort_values(by=['maxAttackPacketRatePps'], ascending=False).iloc[0]['startDate']
        attack_id_maxAttackPacketRatePps = data_month.sort_values(by=['maxAttackPacketRatePps'], ascending=False).iloc[0]['attackIpsId']
        attack_maxpps_maxAttackPacketRatePps = data_month.sort_values(by=['maxAttackPacketRatePps'], ascending=False).iloc[0]['maxAttackPacketRatePps']
        attack_maxbps_maxAttackPacketRatePps = data_month.sort_values(by=['maxAttackPacketRatePps'], ascending=False).iloc[0]['maxAttackRateBps']


        html_attack_cat_maxAttackPacketRatePps = f"Threat Category: {attack_cat_maxAttackPacketRatePps}"
        html_attack_name_maxAttackPacketRatePps = f"Attack Name: {attack_name_maxAttackPacketRatePps}"
        html_src_ip_maxAttackPacketRatePps = f"Attack source: {src_ip_maxAttackPacketRatePps}"
        html_dst_ip_maxAttackPacketRatePps = f"Attack destination: {dst_ip_maxAttackPacketRatePps}"
        html_attack_start_maxAttackPacketRatePps = f"Attack date(UTC): {attack_start_maxAttackPacketRatePps}"
        html_attack_pkt_maxAttackPacketRatePps = f"Attack total packets: {attack_pkt_maxAttackPacketRatePps}"
        html_attack_bw_maxAttackPacketRatePps = f"Attack total data: {'{:.2f}'.format(float(attack_bw_maxAttackPacketRatePps))} GB"
        html_attack_maxpps_maxAttackPacketRatePps = f"Attack rate(PPS): {format(int(attack_maxpps_maxAttackPacketRatePps), ',d')}"
        html_attack_maxbps_maxAttackPacketRatePps = f"Attack rate(Gbps): {'{:.2f}'.format(float(attack_maxbps_maxAttackPacketRatePps/1000000000))} Gbps"
        html_device_maxAttackPacketRatePps = f"Attacked device: {device_maxAttackPacketRatePps}"
        html_policy_maxAttackPacketRatePps = f"Attacked policy: {policy_maxAttackPacketRatePps}"
        html_dur_maxAttackPacketRatePps = f"Attack duration: {dur_maxAttackPacketRatePps}"
        html_attack_id_maxAttackPacketRatePps = f"Attack ID: {attack_id_maxAttackPacketRatePps}"


        email_body = email_body + f"Top #1 attack by max PPS rate:\r\n\r\n"
        email_body = email_body + f"Threat Category: {attack_cat_maxAttackPacketRatePps}\r\n"
        email_body = email_body + f"Attack Name: {attack_name_maxAttackPacketRatePps}\r\n"
        email_body = email_body + f"Attack source: {src_ip_maxAttackPacketRatePps}\r\n"
        email_body = email_body + f"Attack destination: {dst_ip_maxAttackPacketRatePps}\r\n"
        email_body = email_body + f"Attack date(UTC): {attack_start_maxAttackPacketRatePps}\r\n"
        email_body = email_body + f"Attack total packets: {attack_pkt_maxAttackPacketRatePps}\r\n"
        email_body = email_body + f"Attack total data: {'{:.2f}'.format(float(attack_bw_maxAttackPacketRatePps))} GB\r\n"
        email_body = email_body + f"Attack rate(PPS): {format(int(attack_maxpps_maxAttackPacketRatePps), ',d')}\r\n"
        email_body = email_body + f"Attack rate(Gbps): {'{:.2f}'.format(float(attack_maxbps_maxAttackPacketRatePps/1000000000))} Gbps\r\n"
        email_body = email_body + f"Attacked device: {device_maxAttackPacketRatePps}\r\n"
        email_body = email_body + f"Attacked policy: {policy_maxAttackPacketRatePps}\r\n"
        email_body = email_body + f"Attack duration: {dur_maxAttackPacketRatePps}\r\n\r\n"
        email_body = email_body + f"Attack ID: {attack_id_maxAttackPacketRatePps}\r\n\r\n"

        html = """\
        <!doctype html>
        <html>
        <head>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title>Simple Transactional Email</title>
        <style>
        @media only screen and (max-width: 620px) {{
        table.body h1 {{
        font-size: 28px !important;
        margin-bottom: 10px !important;
        }}

        table.body p,
        table.body ul,
        table.body ol,
        table.body td,
        table.body span,
        table.body a {{
        font-size: 16px !important;
        }}

        table.body .wrapper,
        table.body .article {{
        padding: 10px !important;
        }}

        table.body .content {{
        padding: 0 !important;
        }}

        table.body .container {{
        padding: 0 !important;
        width: 100% !important;
        }}

        table.body .main {{
        border-left-width: 0 !important;
        border-radius: 0 !important;
        border-right-width: 0 !important;
        }}

        table.body .btn table {{
        width: 100% !important;
        }}

        table.body .btn a {{
        width: 100% !important;
        }}

        table.body .img-responsive {{
        height: auto !important;
        max-width: 100% !important;
        width: auto !important;
        }}
        }}
        @media all {{
        .ExternalClass {{
        width: 100%;
        }}

        .ExternalClass,
        .ExternalClass p,
        .ExternalClass span,
        .ExternalClass font,
        .ExternalClass td,
        .ExternalClass div {{
        line-height: 100%;
        }}

        .apple-link a {{
        color: inherit !important;
        font-family: inherit !important;
        font-size: inherit !important;
        font-weight: inherit !important;
        line-height: inherit !important;
        text-decoration: none !important;
        }}

        #MessageViewBody a {{
        color: inherit;
        text-decoration: none;
        font-size: inherit;
        font-family: inherit;
        font-weight: inherit;
        line-height: inherit;
        }}

        .btn-primary table td:hover {{
        background-color: #34495e !important;
        }}

        .btn-primary a:hover {{
        background-color: #34495e !important;
        border-color: #34495e !important;
        }}
        }}
        </style>
        </head>
        <body style="background-color: #f6f6f6; font-family: sans-serif; -webkit-font-smoothing: antialiased; font-size: 14px; line-height: 1.4; margin: 0; padding: 0; -ms-text-size-adjust: 100%; -webkit-text-size-adjust: 100%;">
        <span class="preheader" style="color: transparent; display: none; height: 0; max-height: 0; max-width: 0; opacity: 0; overflow: hidden; mso-hide: all; visibility: hidden; width: 0;"></span>
        <table role="presentation" border="0" cellpadding="0" cellspacing="0" class="body" style="border-collapse: separate; mso-table-lspace: 0pt; mso-table-rspace: 0pt; background-color: #f6f6f6; width: 100%;" width="100%" bgcolor="#f6f6f6">
        <tr>
                <td style="font-family: sans-serif; font-size: 14px; vertical-align: top;" valign="top">&nbsp;</td>
                <td class="container" style="font-family: sans-serif; font-size: 14px; vertical-align: top; display: block; max-width: 580px; padding: 10px; width: 580px; margin: 0 auto;" width="580" valign="top">
                <div class="content" style="box-sizing: border-box; display: block; margin: 0 auto; max-width: 580px; padding: 10px;">

                <!-- START CENTERED WHITE CONTAINER -->
                <table role="presentation" class="main" style="border-collapse: separate; mso-table-lspace: 0pt; mso-table-rspace: 0pt; background: #ffffff; border-radius: 3px; width: 100%;" width="100%">

                <!-- START MAIN CONTENT AREA -->
                <tr>
                        <td class="wrapper" style="font-family: sans-serif; font-size: 14px; vertical-align: top; box-sizing: border-box; padding: 20px;" valign="top">
                        <table role="presentation" border="0" cellpadding="0" cellspacing="0" style="border-collapse: separate; mso-table-lspace: 0pt; mso-table-rspace: 0pt; width: 100%;" width="100%">
                        <tr>
                        <td style="font-family: sans-serif; font-size: 14px; vertical-align: top;" valign="top">
                                <p style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 0; margin-bottom: 15px;">Dear {cust_id} Team,</p>
                                <p style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 0; margin-bottom: 15px;">This email is an automated recurring monthly report.</p>
                                                        <p style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 0; margin-bottom: 15px;"><h4>High-Level summary:</h4></p>    
                                <p style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 0; margin-bottom: 15px;">{html_summary}</p>
                                <p style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 0; margin-bottom: 15px;">The most aggressive DDoS attack mitigated by Radware on-premises equipment was a {attack_cat_maxAttackRateBps} type {attack_name_maxAttackRateBps}. The attack occurred on {attack_start_maxAttackRateBps}(UTC) lasting {dur_maxAttackRateBps_min} min, directed at destination IP {dst_ip_maxAttackRateBps} at a peak rate of {attack_maxbps_maxAttackRateBps_formatted} Gbps. The mitigation equipment dropped cumulatively {attack_pkt_maxAttackRateBps} packets for a total of {attack_bw_maxAttackRateBps_formatted} GB data during this attack.</p>
                                                        <p style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 0; margin-bottom: 15px;"><h4>Month to month trends</h4></p>    
                                <p style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 0; margin-bottom: 15px;">{events_text}</p>
                                <p style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 0; margin-bottom: 15px;">{pkts_text}</p>
                                <p style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 0; margin-bottom: 15px;">{bw_text}</p>
   
                                

                                <p style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 0; margin-bottom: 15px;"><h4>Top #1 attack by max Gbps rate:</h4></p>
                                <p style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 0; margin-bottom: 15px;">{html_attack_cat_maxAttackRateBps}<br>
                                                                                                                                          {html_attack_name_maxAttackRateBps}<br>
                                                                                                                                          {html_src_ip_maxAttackRateBps}<br>
                                                                                                                                          {html_dst_ip_maxAttackRateBps}<br>
                                                                                                                                          {html_attack_start_maxAttackRateBps}<br>
                                                                                                                                          {html_attack_pkt_maxAttackRateBps}<br>
                                                                                                                                          {html_attack_bw_maxAttackRateBps_formatted}<br>
                                                                                                                                          {html_attack_maxpps_maxAttackRateBps}<br>
                                                                                                                                          {html_attack_maxbps_maxAttackRateBps_formatted}<br>
                                                                                                                                          {html_device_maxAttackRateBps}<br>
                                                                                                                                          {html_policy_maxAttackRateBps}<br>
                                                                                                                                          {html_dur_maxAttackRateBps}<br>
                                                                                                                                          {html_attack_id_maxAttackRateBps}</p>

                                <p style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 0; margin-bottom: 15px;"><h4>Top #1 attack by max PPS rate:</h4></p>
                                <p style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 0; margin-bottom: 15px;">{html_attack_cat_maxAttackPacketRatePps}<br>
                                                                                                                                          {html_attack_name_maxAttackPacketRatePps}<br>
                                                                                                                                          {html_src_ip_maxAttackPacketRatePps}<br>
                                                                                                                                          {html_dst_ip_maxAttackPacketRatePps}<br>
                                                                                                                                          {html_attack_start_maxAttackPacketRatePps}<br>
                                                                                                                                          {html_attack_pkt_maxAttackPacketRatePps}<br>
                                                                                                                                          {html_attack_bw_maxAttackPacketRatePps}<br>
                                                                                                                                          {html_attack_maxpps_maxAttackPacketRatePps}<br>
                                                                                                                                          {html_attack_maxbps_maxAttackPacketRatePps}<br>
                                                                                                                                          {html_device_maxAttackPacketRatePps}<br>
                                                                                                                                          {html_policy_maxAttackPacketRatePps}<br>
                                                                                                                                          {html_dur_maxAttackPacketRatePps}<br>
                                                                                                                                          {html_attack_id_maxAttackPacketRatePps}</p>
                        </td>
                        </tr>
                        </table>
                        </td>
                </tr>

                <!-- END MAIN CONTENT AREA -->
                </table>
                <!-- END CENTERED WHITE CONTAINER -->

                <!-- START FOOTER -->
                <div class="footer" style="clear: both; margin-top: 10px; text-align: center; width: 100%;">
                <table role="presentation" border="0" cellpadding="0" cellspacing="0" style="border-collapse: separate; mso-table-lspace: 0pt; mso-table-rspace: 0pt; width: 100%;" width="100%">
                        <tr>
                        <td class="content-block" style="font-family: sans-serif; vertical-align: top; padding-bottom: 10px; padding-top: 10px; color: #999999; font-size: 12px; text-align: center;" valign="top" align="center">
                        <span class="apple-link" style="color: #999999; font-size: 12px; text-align: center;">To unsubscribe, please contact Radware Resident Engineers Team at northamericare@radware.com</span>
                        <br> 
                        </td>
                        </tr>
                        <tr>
                        <td class="content-block powered-by" style="font-family: sans-serif; vertical-align: top; padding-bottom: 10px; padding-top: 10px; color: #999999; font-size: 12px; text-align: center;" valign="top" align="center">
                        
                        </td>
                        </tr>
                </table>
                </div>
                <!-- END FOOTER -->

                </div>
                </td>
                <td style="font-family: sans-serif; font-size: 14px; vertical-align: top;" valign="top">&nbsp;</td>
        </tr>
        </table>
        </body>
        </html>
        """.format(**locals())

        # print(email_body)
        # return email_body

        # print(html)
        return html

def archive_files(currentmonth):

        for root, dirs, files in os.walk(path_r):
                if root.split("/")[2] == cust_id:
                        for filename in files:
                                #attempt to split the file
                                try:
                                        if int(filename.split("_")[2]) == int(currentmonth) and int(filename.split("_")[3].split(".")[0]) == int(currentyear):
                                                if os.stat(os.path.join(root, filename)).st_size > 5000000: #if filesize > 5MB
                                                        if not filename.endswith(".tar.gz"):
                                                                # print(f'archiving {os.path.join(root, filename)}')
                                                                arcfile = os.path.join(root, filename) + '.tar.gz'
                                                                with tarfile.open(arcfile, "w:gz") as tar:
                                                                        tar.add(os.path.join(root, filename), arcname=os.path.basename(os.path.join(root, filename)))
                                except:
                                        print(f"Skipping file {filename} for archiving - not in the correct format")
                                        continue


def send_files(currentmonth,msg):
      for root, dirs, files in os.walk(path_r):
                if root.split("/")[2] == cust_id:
                        for filename in files:
                                try:
                                        if int(filename.split("_")[2]) == int(currentmonth) and int(filename.split("_")[3].split(".")[0]) == int(currentyear):
                                                if os.stat(os.path.join(root, filename)).st_size < 5000000:

                                                        #add condition if filename is not report_USCC_08_2023.htm
                                                        if filename !=f"report_{cust_id}_{currentmonth}_{currentyear}.htm" and filename !=f"report_{cust_id}_{currentmonth}_{currentyear}.txt":
                                                                
                                                                print(f'sending {os.path.join(root, filename)}')
                                                                attachment = open(os.path.join(root, filename), "rb")
                                                                p = MIMEBase('application', 'octet-stream')
                                                                p.set_payload((attachment).read())
                                                                encoders.encode_base64(p)
                                                                p.add_header('Content-Disposition', "attachment; filename= %s" % filename)
                                                                msg.attach(p)
                                                                attachment.close()
                                except:
                                        print(f"Skipping file {filename} from attaching to the email- not in the correct format")
                                        continue

def send_report(SMTP_AUTH,SMTP_SERVER,SMTP_SERVER_PORT,SMTP_SENDER,SMTP_PASSWORD,SMTP_LIST,SMTP_SUBJECT_PREFIX):

        msg = MIMEMultipart()
        msg["From"] = SMTP_SENDER
        msg["To"] = ', '.join(SMTP_LIST)

        #################################################### Attach files to the email ########################################################

        if currentmonth != 1:
                msg["Subject"] = SMTP_SUBJECT_PREFIX + f" Monthly report  - {currentmonth}, {currentyear}"
        else:
                msg["Subject"] = SMTP_SUBJECT_PREFIX + f" Monthly report  - 12, {prevyear}"

        archive_files(currentmonth)
        send_files(currentmonth,msg)

        #######################################################################################################################################
 
        body = email_body(cust_id)
        msg.attach(MIMEText(body, 'html'))
        mailserver = smtplib.SMTP(host=SMTP_SERVER,port=SMTP_SERVER_PORT)
        mailserver.ehlo()
        if SMTP_AUTH:
                mailserver.starttls()
                mailserver.ehlo()
                mailserver.login(SMTP_SENDER, SMTP_PASSWORD)
        mailserver.sendmail(from_addr=SMTP_SENDER,to_addrs=SMTP_LIST, msg=msg.as_string())
        mailserver.quit()

send_report(smtp_auth,smtp_server,smtp_server_port,smtp_sender,smtp_password,smtp_list,smtp_subject_prefix)
