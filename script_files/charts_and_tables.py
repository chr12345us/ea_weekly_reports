#!/usr/bin/python3

import pandas as pd
import sqlite3
from sqlite3 import Error
import sys
from pandas.core import series
import time
import os
import abuseipdb as aidb
import json
import urllib.request
import json
import csv
from datetime import datetime

print(f'Start time {datetime.today()}')

start_time = time.time()
cust_id = sys.argv[1]
last_month = sys.argv[2]
year = sys.argv[3]

db_path = f'./database_files/'+cust_id+'/'
tmp_path = f'./tmp_files/'+cust_id+'/'
reports_path = f'./report_files/'+cust_id+'/'
run_file = 'run.sh'

with open (run_file) as f:
	for line in f:
	#find line starting with top_n
		if line.startswith('top_n'):
			#print value after = sign
			top_n = int(line.split('=')[1].replace('\n',''))
			continue
		if line.startswith('abuseipdb='):
			abuseipdb = line.split('=')[1].replace('\n','').capitalize()

			if abuseipdb.lower() == 'true':
				abuseipdb = True
				print(f'abuseipdb = {abuseipdb}')
				continue
			if abuseipdb.lower() == 'false':
				abuseipdb = False
				print(f'abuseipdb = {abuseipdb}')
				continue


			

########DefensePro IP to Name translation########

customers_json = json.loads(open("./config_files/customers.json", "r").read())

for cust_config_block in customers_json:
	if cust_config_block['id'] == cust_id:
		defensepros = cust_config_block['defensepros']

######## Get Monthly Units ###############################
		bw_units = cust_config_block['variables']['bwUnit']
		#Can be configured "Gigabytes", "Terabytes" or "Megabytes"
		
		pkt_units = cust_config_block['variables']['pktUnit']
		#Can be configured "Millions" or "Billions" or "Thousands"

		if bw_units.lower() == 'megabytes':	
			bw_units_sum = 'ROUND(SUM(packetBandwidth)/8000.0, 2)'
		

		if bw_units.lower() == 'gigabytes':	
			bw_units_sum = 'ROUND(SUM(packetBandwidth)/8000000.0, 2)'
		
		if bw_units.lower() == 'terabytes':	
			bw_units_sum = 'ROUND(SUM(packetBandwidth)/8000000000.0, 2)'

######## Get Daily Units ###############################

		bw_units_daily = cust_config_block['variables']['bwUnitDaily']
		#Can be configured "Gigabytes", "Terabytes" or "Megabytes"
		
		pkt_units_daily = cust_config_block['variables']['pktUnitDaily']
		#Can be configured "Millions" or "Billions" or "Thousands"

		if bw_units_daily.lower() == 'megabytes':	
			bps_units = 'ROUND(MAX(maxAttackRateBps)/1000000.0, 2)'
			bps_units_desc = 'Mbps'	

		if bw_units_daily.lower() == 'gigabytes':	
			bps_units = 'ROUND(MAX(maxAttackRateBps)/1000000000.0, 2)'
			bps_units_desc = 'Gbps'

		if bw_units_daily.lower() == 'terabytes':	
			bps_units = 'ROUND(MAX(maxAttackRateBps)/1000000000.0, 2)'
			bps_units_desc = 'Gbps'




#################################################

# check if tmp_files directory exists and create it if it doesn't
if not os.path.exists('./tmp_files'):
	os.mkdir('./tmp_files')

if not os.path.exists(tmp_path):
	os.mkdir(tmp_path)

# check if report_files directory exists and create it if it doesn't

if not os.path.exists('./report_files'):
	os.mkdir('./report_files')
	
if not os.path.exists(reports_path):
	os.mkdir(reports_path)

# #delete files inside tmp_files directory
# for file in os.listdir(tmp_path):
# 	os.remove(tmp_path+file)


def AbuseIPDBGEO(ip):
	with open(tmp_path + 'AbuseIPDB.json') as abuseipdb_file:
		abuseipdb_dic = json.load(abuseipdb_file)

	for data_dic in abuseipdb_dic['Src IP details']:
		for data,data_val in data_dic.items():
			# print(ip)
			if ip == data_val['ipAddress']:
				return data_val['countryCode']
				

def AbuseIPDBScore(ip):
	with open(tmp_path + 'AbuseIPDB.json') as abuseipdb_file:
		abuseipdb_dic = json.load(abuseipdb_file)

	for data_dic in abuseipdb_dic['Src IP details']:
		for data,data_val in data_dic.items():
			if ip == data_val['ipAddress']:
				return data_val['abuseConfidenceScore']

def AbuseIPDBISP(ip):
	with open(tmp_path + 'AbuseIPDB.json') as abuseipdb_file:
		abuseipdb_dic = json.load(abuseipdb_file)

	for data_dic in abuseipdb_dic['Src IP details']:
		for data,data_val in data_dic.items():
			if ip == data_val['ipAddress']:
				return data_val['isp']


def gen_charts_data(db_path):

	events_count_list =[]
	packets_count_list = []
	bandwidth_sum_list = []

	device_events_count_list =[]
	device_packets_count_list = []
	device_bandwidth_sum_list = []

	policy_events_count_list =[]
	policy_packets_count_list = []
	policy_bandwidth_sum_list = []

	srcip_events_count_list = []
	srcip_packets_count_list = []
	srcip_bandwidth_sum_list = []

	#create events per month csv file

	with open(tmp_path + 'epm_total_bar.csv', 'w') as f:
		f.write('Month, Total Events')

	with open(tmp_path + 'ppm_total_bar.csv', 'w') as f:
		f.write('Month, Total Attack Packets')

	with open(tmp_path + 'bpm_total_bar.csv', 'w') as f:
		f.write('Month, Total Attack Volume')

	with open(tmp_path + 'total_attack_time_bar.csv', 'w') as f:
		f.write('Month, Total attack time(days)')



	# loop through files by file creation date oldest first order
	for file in sorted(os.listdir(db_path), key=lambda x: os.path.getmtime(db_path+x)):#,reverse=True): # december corner case
		if file.endswith('.sqlite'):
			con = None
			try:
				con = sqlite3.connect(db_path + file)
			except Error as e:
				print(e)

			cur = con.cursor()
			cur.execute("SELECT DISTINCT month FROM attacks")
			month_num = cur.fetchall()[0][0]

			# convert numeric month to month name
			month_name = time.strftime('%B', time.strptime(str(month_num), '%m'))







			# ########Get traffic utilization from the last month and write to csv######### ---> This is replaced by separate collect.py file
			
			if int(last_month) == int(month_num):
				
				####Get security events count by day from the last month and write to csv########

				cur.execute("SELECT startDayOfMonth, COUNT(*) FROM attacks GROUP BY startDayOfMonth")
				
				new_column_names = ['Day of the month', 'Security Events count']

				data = cur.fetchall()
	
				# Write to CSV with renamed columns
				with open(tmp_path + 'events_per_day_last_month.csv', 'w', newline='') as csv_file:
					csv_writer = csv.writer(csv_file)

					# Write the new header
					csv_writer.writerow(new_column_names)

					# Write data
					csv_writer.writerows(data)

				csv_file.close
				###################################################################



				####Get Attack Volume by day from the last month and write to csv########
					
				cur.execute(f"SELECT startDayOfMonth, {bw_units_sum} FROM attacks GROUP BY startDayOfMonth")
							
				new_column_names = ['Day of the month', 'Attack Volume']

				data = cur.fetchall()
	
				# Write to CSV with renamed columns
				with open(tmp_path + 'bandwidth_per_day_last_month.csv', 'w', newline='') as csv_file:
					csv_writer = csv.writer(csv_file)

					# Write the new header
					csv_writer.writerow(new_column_names)

					# Write data
					csv_writer.writerows(data)

				csv_file.close
				###################################################################

				####Get attack Max PPS by day from the last month and write to csv########

				cur.execute("SELECT startDayOfMonth, MAX(maxAttackPacketRatePps) as 'Max Attack rate PPS' FROM attacks GROUP BY startDayOfMonth ORDER BY startDayOfMonth")


				new_column_names = ['Day of the month', 'Attack rate Max PPS']

				data = cur.fetchall()

				# Write to CSV with renamed columns
				with open(tmp_path + 'maxpps_per_day_last_month.csv', 'w', newline='') as csv_file:
					csv_writer = csv.writer(csv_file)

					# Write the new header
					csv_writer.writerow(new_column_names)

					# Write data
					csv_writer.writerows(data)

				csv_file.close
				###################################################################



				####Get attack Max Gbps by day from the last month and write to csv########

				cur.execute(f"SELECT startDayOfMonth, {bps_units} as 'Max Attack rate BPS' FROM attacks GROUP BY startDayOfMonth ORDER BY startDayOfMonth")


				new_column_names = ['Day of the month', 'Attack rate Max BPS']

				data = cur.fetchall()

				# Write to CSV with renamed columns
				with open(tmp_path + 'maxbps_per_day_last_month.csv', 'w', newline='') as csv_file:
					csv_writer = csv.writer(csv_file)

					# Write the new header
					csv_writer.writerow(new_column_names)

					# Write data
					csv_writer.writerows(data)

				csv_file.close
				###################################################################


				####Get Attack Packets by day from the last month and write to csv########

				if pkt_units.lower() == 'thousands':					
					cur.execute("SELECT startDayOfMonth, SUM(packetCount)/1000 FROM attacks GROUP BY startDayOfMonth")

				if pkt_units.lower() == 'millions':
					cur.execute("SELECT startDayOfMonth, SUM(packetCount)/1000000 FROM attacks GROUP BY startDayOfMonth")

				if pkt_units.lower() == 'billions':
					cur.execute("SELECT startDayOfMonth, SUM(packetCount)/1000000000 FROM attacks GROUP BY startDayOfMonth")
							
				new_column_names = ['Day of the month', 'Attack Packets']

				data = cur.fetchall()
	
				# Write to CSV with renamed columns
				with open(tmp_path + 'packets_per_day_last_month.csv', 'w', newline='') as csv_file:
					csv_writer = csv.writer(csv_file)

					# Write the new header
					csv_writer.writerow(new_column_names)

					# Write data
					csv_writer.writerows(data)

				csv_file.close
				###################################################################


				########Get total events by device this month and write to csv#########
				cur.execute("select deviceName as 'Device Name', count(1) as 'Total Events' from attacks group by deviceName order by count(*) desc")

				device_epm_this_month = cur.fetchall()[:top_n]
				with open(tmp_path + 'device_epm_chart_this_month.csv', 'w', newline='') as f:
					writer = csv.writer(f)
					writer.writerow(['Device', 'Number of Events'])
					writer.writerows(device_epm_this_month)

				########Get Attack Packets by device this month and write to csv#########
				cur.execute("select deviceName as 'Device Name', sum(packetCount) as 'Total Events' from attacks group by deviceName order by sum(packetCount) desc")

				device_ppm_this_month = cur.fetchall()[:top_n]
				with open(tmp_path + 'device_ppm_chart_this_month.csv', 'w', newline='') as f:
					writer = csv.writer(f)
					writer.writerow(['Device', 'Attack Packets'])
					writer.writerows(device_ppm_this_month)

				########Get Attack Volume by device this month and write to csv#########
				cur.execute("select deviceName as 'Device Name', sum(packetBandwidth) as 'Total Events' from attacks group by deviceName order by sum(packetBandwidth) desc")

				device_bpm_this_month = cur.fetchall()[:top_n]
				with open(tmp_path + 'device_bpm_chart_this_month.csv', 'w', newline='') as f:
					writer = csv.writer(f)
					writer.writerow(['Device', 'Attack Volume'])
					writer.writerows(device_bpm_this_month)

			########Get total events count this month and write to csv#########
			cur.execute("select month as Month,count(1) as \'Total Events\' from attacks")
			total_events_this_month = cur.fetchall()[0][1]

			with open(tmp_path + 'epm_total_bar.csv', 'a') as f:
				f.write(f'\n{month_name},{total_events_this_month}')
			###################################################################

			########Get total Attack Packets this month and write to csv#########
			cur.execute(f"select month as Month,sum(packetCount) as \'Attack Packets\' from attacks")
			total_packets_this_month = cur.fetchall()[0][1]


			with open(tmp_path + 'ppm_total_bar.csv', 'a') as f:
				f.write(f'\n{month_name},{total_packets_this_month}')
			###################################################################


			########Get total Attack Volume this month and write to csv#########
			cur.execute(f"select month as Month,sum(packetBandwidth) as \'Attack Volume\' from attacks")
			total_bw_this_month = cur.fetchall()[0][1]


			with open(tmp_path + 'bpm_total_bar.csv', 'a') as f:
				f.write(f'\n{month_name},{total_bw_this_month}')
			###################################################################

			########Get total attack time month and write to csv#########
			cur.execute(f"select month as Month,sum(endTime-startTime) as \'Total attack time in days\' from attacks")
			total_attack_time_milisec = cur.fetchall()[0][1]
			total_attack_time_days = total_attack_time_milisec/1000/60/60/24
			total_attack_time_days = "{:.2f}".format(total_attack_time_days)

			with open(tmp_path + 'total_attack_time_bar.csv', 'a') as f:
				f.write(f'\n{month_name},{total_attack_time_days}')
			###################################################################

			#Create dataframe from sql query 

			df_events_count_this_month = pd.DataFrame(pd.read_sql_query(f"select name as 'Attack Name',count(*) as {month_name} from attacks group by name order by count(*) desc", con)).set_index('Attack Name')
			df_packets_count_this_month = pd.DataFrame(pd.read_sql_query(f"select name as 'Attack Name',sum(packetCount) as {month_name} from attacks group by name order by sum(packetCount) desc", con)).set_index('Attack Name')
			df_bandwidth_sum_this_month = pd.DataFrame(pd.read_sql_query(f"select name as 'Attack Name',sum(packetBandwidth) as {month_name} from attacks group by name order by sum(packetBandwidth) desc", con)).set_index('Attack Name')

			df_device_events_count_this_month = pd.DataFrame(pd.read_sql_query(f"select deviceName as 'Device Name',count(*) as {month_name} from attacks group by deviceName order by count(*) desc", con)).set_index('Device Name')
			df_device_packets_count_this_month = pd.DataFrame(pd.read_sql_query(f"select deviceName as 'Device Name',sum(packetCount) as {month_name} from attacks group by deviceName order by sum(packetCount) desc", con)).set_index('Device Name')
			df_device_bandwidth_sum_this_month = pd.DataFrame(pd.read_sql_query(f"select deviceName as 'Device Name',sum(packetBandwidth) as {month_name} from attacks group by deviceName order by sum(packetBandwidth) desc", con)).set_index('Device Name')

			df_policy_packets_count_this_month = pd.DataFrame(pd.read_sql_query(f"select ruleName as 'Policy Name',sum(packetCount) as {month_name} from attacks group by ruleName order by sum(packetCount) desc", con)).set_index('Policy Name')
			df_policy_events_count_this_month = pd.DataFrame(pd.read_sql_query(f"select ruleName as 'Policy Name',count(*) as {month_name} from attacks group by ruleName order by count(*) desc", con)).set_index('Policy Name')
			df_policy_bandwidth_sum_this_month = pd.DataFrame(pd.read_sql_query(f"select ruleName as 'Policy Name',sum(packetBandwidth) as {month_name} from attacks group by ruleName order by sum(packetBandwidth) desc", con)).set_index('Policy Name')
					
			df_srcip_events_count_this_month = pd.DataFrame(pd.read_sql_query(f"select sourceAddress as 'Source IP',count(*) as {month_name} from attacks group by sourceAddress order by count(*) desc", con)).set_index('Source IP')
			df_srcip_packets_count_this_month = pd.DataFrame(pd.read_sql_query(f"select sourceAddress as 'Source IP',sum(packetCount) as {month_name} from attacks group by sourceAddress order by sum(packetCount) desc", con)).set_index('Source IP')
			df_srcip_bandwidth_sum_this_month = pd.DataFrame(pd.read_sql_query(f"select sourceAddress as 'Source IP',sum(packetBandwidth)/8000 as {month_name} from attacks group by sourceAddress order by sum(packetBandwidth) desc", con)).set_index('Source IP')

			events_count_list.append(df_events_count_this_month)		
			packets_count_list.append(df_packets_count_this_month)
			bandwidth_sum_list.append(df_bandwidth_sum_this_month)

			device_events_count_list.append(df_device_events_count_this_month)		
			device_packets_count_list.append(df_device_packets_count_this_month)
			device_bandwidth_sum_list.append(df_device_bandwidth_sum_this_month)

			policy_events_count_list.append(df_policy_events_count_this_month)		
			policy_packets_count_list.append(df_policy_packets_count_this_month)
			policy_bandwidth_sum_list.append(df_policy_bandwidth_sum_this_month)

			srcip_events_count_list.append(df_srcip_events_count_this_month)
			srcip_packets_count_list.append(df_srcip_packets_count_this_month)
			srcip_bandwidth_sum_list.append(df_srcip_bandwidth_sum_this_month)


	con.close()
	f.close()
	###############Attack Name Events Count trends by last month################
	events_count_trend_chart_by_last_month = pd.concat(events_count_list,axis=1).fillna(0).sort_values(by=[month_name], ascending=False)
	events_count_trend_chart_by_last_month.T.iloc[: , :top_n].to_csv(tmp_path + 'epm_chart_lm.csv')
	events_count_trend_chart_by_last_month.head(top_n).to_csv(tmp_path + 'epm_table_lm.csv') #save events count trend table (sorted by last month highest to lowest) to csv file

	###############Attack Name Events Count trends all time high################
	events_count_trend_chart_all_times = pd.concat(events_count_list,axis=1).fillna(0)
	events_count_trend_chart_all_times.T.iloc[: , :top_n].to_csv(tmp_path + 'epm_chart_alltimehigh.csv') #save events count chart (all time high sum) to csv file
	events_count_trend_chart_all_times.head(top_n)       .to_csv(tmp_path + 'epm_table_alltimehigh.csv') #save events count table (all time high sum) to csv file


	###############Device Name Events Count trends by last month################

	device_events_count_trend_chart_by_last_month = pd.concat(device_events_count_list,axis=1).fillna(0).sort_values(by=[month_name], ascending=False)

	#Translate DP IP to DP Name
	for df_dp_ip in device_events_count_trend_chart_by_last_month.index:
		for dp_ip, dp_name in defensepros.items():
			if df_dp_ip == dp_ip:
				device_events_count_trend_chart_by_last_month.rename(index={df_dp_ip:dp_name}, inplace=True)

	device_events_count_trend_chart_by_last_month.T.iloc[: , :top_n].to_csv(tmp_path + 'device_epm_chart_lm.csv')
	device_events_count_trend_chart_by_last_month.head(top_n).to_csv(tmp_path + 'device_epm_table_lm.csv') #save events count trend table (sorted by last month highest to lowest) to csv file


	###############Policy Name Events Count trends by last month################

	policy_events_count_trend_chart_by_last_month = pd.concat(policy_events_count_list,axis=1).fillna(0).sort_values(by=[month_name], ascending=False)
	policy_events_count_trend_chart_by_last_month.T.iloc[: , :top_n].to_csv(tmp_path + 'policy_epm_chart_lm.csv')
	policy_events_count_trend_chart_by_last_month.head(top_n)       .to_csv(tmp_path + 'policy_epm_table_lm.csv') #save events count trend table (sorted by last month highest to lowest) to csv file
	

	###############Attack Name Packets Count trends by last month################

	packets_count_trend_chart_by_last_month = pd.concat(packets_count_list,axis=1).fillna(0).sort_values(by=[month_name], ascending=False)
	packets_count_trend_chart_by_last_month.T.iloc[: , :top_n].to_csv(tmp_path + 'ppm_chart_lm.csv') #save packets count chart (sorted by last month highest to lowest) to csv file
	packets_count_trend_chart_by_last_month.head(top_n)       .to_csv(tmp_path + 'ppm_table_lm.csv') #save packets count table (sorted by last month highest to lowest) to csv file

	###############Attack Name Packets Count trends all time high################

	packets_count_trend_chart_all_times = pd.concat(packets_count_list,axis=1).fillna(0)
	packets_count_trend_chart_all_times.T.iloc[: , :top_n].to_csv(tmp_path + 'ppm_chart_alltimehigh.csv') #save events count chart (all time high sum) to csv file
	packets_count_trend_chart_all_times.head(top_n)       .to_csv(tmp_path + 'ppm_table_alltimehigh.csv') #save events count table (all time high sum) to csv file

	###############Device Name Packets Count trends by last month################

	device_packets_count_trend_chart_by_last_month = pd.concat(device_packets_count_list,axis=1).fillna(0).sort_values(by=[month_name], ascending=False)

	#Translate DP IP to DP Name
	for df_dp_ip in device_packets_count_trend_chart_by_last_month.index:
		for dp_ip, dp_name in defensepros.items():
			if df_dp_ip == dp_ip:
				device_packets_count_trend_chart_by_last_month.rename(index={df_dp_ip:dp_name}, inplace=True)

	device_packets_count_trend_chart_by_last_month.T.iloc[: , :top_n].to_csv(tmp_path + 'device_ppm_chart_lm.csv') #save packets count chart (sorted by last month highest to lowest) to csv file
	device_packets_count_trend_chart_by_last_month.head(top_n)       .to_csv(tmp_path + 'device_ppm_table_lm.csv') #save packets count table (sorted by last month highest to lowest) to csv file

	###############Policy Name Packets Count trends by last month################

	policy_packets_count_trend_chart_by_last_month = pd.concat(policy_packets_count_list,axis=1).fillna(0).sort_values(by=[month_name], ascending=False)
	policy_packets_count_trend_chart_by_last_month.T.iloc[: , :top_n].to_csv(tmp_path + 'policy_ppm_chart_lm.csv') #save packets count chart (sorted by last month highest to lowest) to csv file
	policy_packets_count_trend_chart_by_last_month.head(top_n)       .to_csv(tmp_path + 'policy_ppm_table_lm.csv') #save packets count table (sorted by last month highest to lowest) to csv file


	###############Attack Name Packets Count trends by last month################

	bandwidth_sum_trend_chart_by_last_month = pd.concat(bandwidth_sum_list,axis=1).fillna(0).sort_values(by=[month_name], ascending=False)
	bandwidth_sum_trend_chart_by_last_month.T.iloc[: , :top_n].to_csv(tmp_path + 'bpm_chart_lm.csv') #save packets count chart (sorted by last month highest to lowest) to csv file
	bandwidth_sum_trend_chart_by_last_month.head(top_n)       .to_csv(tmp_path + 'bpm_table_lm.csv') #save packets count table (sorted by last month highest to lowest) to csv file


	###############Attack Name Attack Volume trends all time high################

	bandwidth_sum_trend_chart_all_times = pd.concat(bandwidth_sum_list,axis=1).fillna(0)
	bandwidth_sum_trend_chart_all_times.T.iloc[: , :top_n].to_csv(tmp_path + 'bpm_chart_alltimehigh.csv') #save events count chart (all time high sum) to csv file
	bandwidth_sum_trend_chart_all_times.head(top_n)       .to_csv(tmp_path + 'bpm_table_alltimehigh.csv') #save events count table (all time high sum) to csv file


	###############Device Name Packets Count trends by last month################

	device_bandwidth_sum_trend_chart_by_last_month = pd.concat(device_bandwidth_sum_list,axis=1).fillna(0).sort_values(by=[month_name], ascending=False)

	#Translate DP IP to DP Name
	for df_dp_ip in device_bandwidth_sum_trend_chart_by_last_month.index:
		for dp_ip, dp_name in defensepros.items():
			if df_dp_ip == dp_ip:
				device_bandwidth_sum_trend_chart_by_last_month.rename(index={df_dp_ip:dp_name}, inplace=True)

	device_bandwidth_sum_trend_chart_by_last_month.T.iloc[: , :top_n].to_csv(tmp_path + 'device_bpm_chart_lm.csv') #save packets count chart (sorted by last month highest to lowest) to csv file
	device_bandwidth_sum_trend_chart_by_last_month.head(top_n)       .to_csv(tmp_path + 'device_bpm_table_lm.csv') #save packets count table (sorted by last month highest to lowest) to csv file

	###############Policy Name Packets Count trends by last month################

	policy_bandwidth_sum_trend_chart_by_last_month = pd.concat(policy_bandwidth_sum_list,axis=1).fillna(0).sort_values(by=[month_name], ascending=False)
	policy_bandwidth_sum_trend_chart_by_last_month.T.iloc[: , :top_n].to_csv(tmp_path + 'policy_bpm_chart_lm.csv') #save packets count chart (sorted by last month highest to lowest) to csv file
	policy_bandwidth_sum_trend_chart_by_last_month.head(top_n)       .to_csv(tmp_path + 'policy_bpm_table_lm.csv') #save packets count table (sorted by last month highest to lowest) to csv file


	###############Top 10 source IP by events count by last month################

	srcip_events_trend_chart_by_last_month = pd.concat(srcip_events_count_list,axis=1).fillna(0).sort_values(by=[month_name], ascending=False)
	
	if 'Multiple' in srcip_events_trend_chart_by_last_month.index:
		srcip_events_trend_chart_by_last_month = srcip_events_trend_chart_by_last_month.drop(['Multiple'])
	if '0.0.0.0' in srcip_events_trend_chart_by_last_month.index:
		srcip_events_trend_chart_by_last_month = srcip_events_trend_chart_by_last_month.drop(['0.0.0.0'])
	

	srcip_events_trend_chart_by_last_month = srcip_events_trend_chart_by_last_month.iloc[:10]

	srcip_events_list = srcip_events_trend_chart_by_last_month.index[0:top_n].tolist()

	srcip_events_trend_chart_by_last_month.T.iloc[: , :top_n].to_csv(tmp_path + 'sip_epm_chart_lm.csv') #save packets count chart (sorted by last month highest to lowest) to csv file

	if abuseipdb:
		if aidb.internet_conn():
			
			for ip in srcip_events_list:
				aidb.abuseipdb_call(ip, cust_id)

			srcip_events_trend_chart_by_last_month['srcip'] = srcip_events_trend_chart_by_last_month.index
			srcip_events_trend_chart_by_last_month['GEO'] = srcip_events_trend_chart_by_last_month['srcip'].apply(AbuseIPDBGEO)
			srcip_events_trend_chart_by_last_month['Abuse Confidence'] = srcip_events_trend_chart_by_last_month['srcip'].apply(AbuseIPDBScore)
			srcip_events_trend_chart_by_last_month['ISP'] = srcip_events_trend_chart_by_last_month['srcip'].apply(AbuseIPDBISP)

			srcip_events_trend_chart_by_last_month = srcip_events_trend_chart_by_last_month.drop(['srcip'], axis=1)

			cols = srcip_events_trend_chart_by_last_month.columns.tolist()
			cols = cols[-1:] + cols[:-1]
			cols = cols[-1:] + cols[:-1]
			cols = cols[-1:] + cols[:-1]
			srcip_events_trend_chart_by_last_month = srcip_events_trend_chart_by_last_month[cols]

			srcip_events_trend_chart_by_last_month.head(top_n).to_csv(tmp_path + 'sip_epm_table_lm.csv') #save packets count table (sorted by last month highest to lowest) to csv file
		
		else:

			srcip_events_trend_chart_by_last_month.insert(0, "GEO", "N/A", True)
			srcip_events_trend_chart_by_last_month.insert(1, "Abuse Confidence", 0, True)
			srcip_events_trend_chart_by_last_month.insert(2, "ISP", "N/A", True)
			srcip_events_trend_chart_by_last_month.head(top_n).to_csv(tmp_path + 'sip_epm_table_lm.csv') #save packets count table (sorted by last month highest to lowest) to csv file

	else:

		srcip_events_trend_chart_by_last_month.insert(0, "GEO", "N/A", True)
		srcip_events_trend_chart_by_last_month.insert(1, "Abuse Confidence", 0, True)
		srcip_events_trend_chart_by_last_month.insert(2, "ISP", "N/A", True)
		srcip_events_trend_chart_by_last_month.head(top_n).to_csv(tmp_path + 'sip_epm_table_lm.csv') #save packets count table (sorted by last month highest to lowest) to csv file


	###############Top 10 source IP by packets count by last month################

	srcip_packets_trend_chart_by_last_month = pd.concat(srcip_packets_count_list,axis=1).fillna(0).sort_values(by=[month_name], ascending=False)
	
	if 'Multiple' in srcip_packets_trend_chart_by_last_month.index:
		srcip_packets_trend_chart_by_last_month = srcip_packets_trend_chart_by_last_month.drop(['Multiple'])
	if '0.0.0.0' in srcip_packets_trend_chart_by_last_month.index:
		srcip_packets_trend_chart_by_last_month = srcip_packets_trend_chart_by_last_month.drop(['0.0.0.0'])
	
	srcip_packets_trend_chart_by_last_month = srcip_packets_trend_chart_by_last_month.iloc[:top_n] #get top 10 source ip by packets count
	srcip_packets_trend_chart_by_last_month.T.to_csv(tmp_path + 'sip_ppm_chart_lm.csv') #save packets count chart (sorted by last month highest to lowest) to csv file
	
	srcip_packets_list = srcip_packets_trend_chart_by_last_month.index[0:top_n].tolist()
	
	if abuseipdb:
		if aidb.internet_conn():

			for ip in srcip_packets_list:
				aidb.abuseipdb_call(ip, cust_id)

			srcip_packets_trend_chart_by_last_month['srcip'] = srcip_packets_trend_chart_by_last_month.index
			srcip_packets_trend_chart_by_last_month['GEO'] = srcip_packets_trend_chart_by_last_month['srcip'].apply(AbuseIPDBGEO)
			srcip_packets_trend_chart_by_last_month['Abuse Confidence'] = srcip_packets_trend_chart_by_last_month['srcip'].apply(AbuseIPDBScore)
			srcip_packets_trend_chart_by_last_month['ISP'] = srcip_packets_trend_chart_by_last_month['srcip'].apply(AbuseIPDBISP)


			srcip_packets_trend_chart_by_last_month = srcip_packets_trend_chart_by_last_month.drop(['srcip'], axis=1)

			cols = srcip_packets_trend_chart_by_last_month.columns.tolist()
			cols = cols[-1:] + cols[:-1]
			cols = cols[-1:] + cols[:-1]
			cols = cols[-1:] + cols[:-1]
			srcip_packets_trend_chart_by_last_month = srcip_packets_trend_chart_by_last_month[cols]

			srcip_packets_trend_chart_by_last_month.head(top_n).to_csv(tmp_path + 'sip_ppm_table_lm.csv')
		else:

			srcip_packets_trend_chart_by_last_month.insert(0, "GEO", "N/A", True)
			srcip_packets_trend_chart_by_last_month.insert(1, "Abuse Confidence", 0 , True)
			srcip_packets_trend_chart_by_last_month.insert(2, "ISP", "N/A", True)
			srcip_packets_trend_chart_by_last_month.head(top_n).to_csv(tmp_path + 'sip_ppm_table_lm.csv') #save packets count table (sorted by last month highest to lowest) to csv file

	else:

		srcip_packets_trend_chart_by_last_month.insert(0, "GEO", "N/A", True)
		srcip_packets_trend_chart_by_last_month.insert(1, "Abuse Confidence", 0 , True)
		srcip_packets_trend_chart_by_last_month.insert(2, "ISP", "N/A", True)
		srcip_packets_trend_chart_by_last_month.head(top_n).to_csv(tmp_path + 'sip_ppm_table_lm.csv') #save packets count table (sorted by last month highest to lowest) to csv file

	###############Top 10 source IP by bandwidth sum by last month################

	srcip_bandwidth_trend_chart_by_last_month = pd.concat(srcip_bandwidth_sum_list,axis=1).fillna(0).sort_values(by=[month_name], ascending=False)
	
	if 'Multiple' in srcip_bandwidth_trend_chart_by_last_month.index:
		srcip_bandwidth_trend_chart_by_last_month = srcip_bandwidth_trend_chart_by_last_month.drop(['Multiple'])
	if '0.0.0.0' in srcip_bandwidth_trend_chart_by_last_month.index:
		srcip_bandwidth_trend_chart_by_last_month = srcip_bandwidth_trend_chart_by_last_month.drop(['0.0.0.0'])
	
	srcip_bandwidth_trend_chart_by_last_month.T.iloc[: , :top_n].to_csv(tmp_path + 'sip_bpm_chart_lm.csv') #save src ip bandwidth chart (sorted by last month highest to lowest) to csv file

	srcip_bandwidth_list = srcip_bandwidth_trend_chart_by_last_month.index[0:top_n].tolist()

	if abuseipdb:
		if aidb.internet_conn():

			for ip in srcip_bandwidth_list:
				aidb.abuseipdb_call(ip, cust_id)

			srcip_bandwidth_trend_chart_by_last_month['srcip'] = srcip_bandwidth_trend_chart_by_last_month.index
			srcip_bandwidth_trend_chart_by_last_month['GEO'] = srcip_bandwidth_trend_chart_by_last_month['srcip'].apply(AbuseIPDBGEO)
			srcip_bandwidth_trend_chart_by_last_month['Abuse Confidence'] = srcip_bandwidth_trend_chart_by_last_month['srcip'].apply(AbuseIPDBScore)
			srcip_bandwidth_trend_chart_by_last_month['ISP'] = srcip_bandwidth_trend_chart_by_last_month['srcip'].apply(AbuseIPDBISP)


			srcip_bandwidth_trend_chart_by_last_month = srcip_bandwidth_trend_chart_by_last_month.drop(['srcip'], axis=1)

			cols = srcip_bandwidth_trend_chart_by_last_month.columns.tolist()
			cols = cols[-1:] + cols[:-1]
			cols = cols[-1:] + cols[:-1]
			cols = cols[-1:] + cols[:-1]
			srcip_bandwidth_trend_chart_by_last_month = srcip_bandwidth_trend_chart_by_last_month[cols]

			srcip_bandwidth_trend_chart_by_last_month.head(top_n).to_csv(tmp_path + 'sip_bpm_table_lm.csv')
			
		else:

			srcip_bandwidth_trend_chart_by_last_month.insert(0, "GEO", "N/A", True)
			srcip_bandwidth_trend_chart_by_last_month.insert(1, "Abuse Confidence", 0 , True)
			srcip_bandwidth_trend_chart_by_last_month.insert(2, "ISP", "N/A", True)
			srcip_bandwidth_trend_chart_by_last_month.head(top_n).to_csv(tmp_path + 'sip_bpm_table_lm.csv') #save packets count table (sorted by last month highest to lowest) to csv file

	else:

		srcip_bandwidth_trend_chart_by_last_month.insert(0, "GEO", "N/A", True)
		srcip_bandwidth_trend_chart_by_last_month.insert(1, "Abuse Confidence", 0 , True)
		srcip_bandwidth_trend_chart_by_last_month.insert(2, "ISP", "N/A", True)
		srcip_bandwidth_trend_chart_by_last_month.head(top_n).to_csv(tmp_path + 'sip_bpm_table_lm.csv') #save packets count table (sorted by last month highest to lowest) to csv file


	return events_count_trend_chart_by_last_month.T.iloc[: , :top_n].to_csv()


gen_charts_data(db_path)

print(f'End time {datetime.today()}')
print("--- %s seconds ---" % (time.time() - start_time))