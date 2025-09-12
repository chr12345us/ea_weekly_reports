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

start_time = time.time()
cust_id = sys.argv[1]
last_month = sys.argv[2] #if day is 1st this will be this month, if it is 1st day of the month, the month is previous month.
year = sys.argv[3]

db_path = f'./database_files/'+cust_id+'/'
tmp_path = f'./tmp_files/'+cust_id+'/'
reports_path = f'./report_files/'+cust_id+'/'
run_file = 'run_daily.sh'

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

######## Get Units ###############################
		bw_units = cust_config_block['variables']['bwUnitDaily']
		#Can be configured "Gigabytes", "Terabytes" or "Megabytes"
		
		pkt_units = cust_config_block['variables']['pktUnitDaily']
		#Can be configured "Millions" or "Billions" or "Thousands"

######## Set units sum Units ###############################

		if bw_units.lower() == 'megabytes':	
			bw_units_sum = 'ROUND(SUM(packetBandwidth)/8000.0, 2)'
			bps_units = 'ROUND(MAX(maxAttackRateBps)/1000000.0, 2)'
			bps_units_desc = 'Mbps'

		if bw_units.lower() == 'gigabytes':	
			bw_units_sum = 'ROUND(SUM(packetBandwidth)/8000000.0, 2)'
			bps_units = 'ROUND(MAX(maxAttackRateBps)/1000000000.0, 2)'
			bps_units_desc = 'Gbps'

		if bw_units.lower() == 'terabytes':	
			bw_units_sum = 'ROUND(SUM(packetBandwidth)/8000000000.0, 2)'
			bps_units = 'ROUND(MAX(maxAttackRateBps)/1000000000.0, 2)'
			bps_units_desc = 'Gbps'


		if pkt_units.lower() == 'as is':	
			pkt_units_sum = 'SUM(packetCount)'

		if pkt_units.lower() == 'thousands':	
			pkt_units_sum = 'SUM(packetCount)/1000'
		
		if pkt_units.lower() == 'millions':	
			pkt_units_sum = 'SUM(packetCount)/1000000'
		
		if pkt_units.lower() == 'billions':	
			pkt_units_sum = 'SUM(packetCount)/1000000000'


#################################################

# check if tmp_files directory exists and create it if it doesn't
if not os.path.exists('./tmp_files'):
	os.mkdir('./tmp_files')

if not os.path.exists(tmp_path):
	os.mkdir(tmp_path)


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



	############## Connect to the sqlite database ##############################
	
	
	file = f'database_{cust_id}_{last_month}_{year}.sqlite'
	con = None
	try:
		con = sqlite3.connect(db_path + file)
	except Error as e:
		print(e)

	cur = con.cursor()



	###################Get the month number and month name #####################
	cur.execute("SELECT DISTINCT month FROM attacks")
	month_num = cur.fetchall()[0][0]
	# convert numeric month to month name
	month_name = time.strftime('%B', time.strptime(str(month_num), '%m'))

	###################Get days  #####################

	cur.execute("SELECT DISTINCT startDayOfMonth FROM attacks")
	days_list_tuple = cur.fetchall() #this returns tuples list [(24,), (25,), (26,), (27,), (28,), (29,), (30,), (31,)]]
	days_list = sorted([day[0] for day in days_list_tuple]) # convert days to a list [24, 25, 26, 27, 28, 29, 30, 31]
	

	####Get security events count by day from the last month and write to csv########

	cur.execute("SELECT startDayOfMonth, COUNT(*) FROM attacks GROUP BY startDayOfMonth")
	
	new_column_names = ['Day of the month', 'Attack Events']

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


	####Get malicious packets by day from the last month and write to csv########

	cur.execute(f"SELECT startDayOfMonth, {pkt_units_sum} FROM attacks GROUP BY startDayOfMonth")

	new_column_names = ['Day of the month', 'Malicious Packets']

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


	new_column_names = ['Day of the month', 'MAX Attack rate PPS']

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


	new_column_names = ['Day of the month', 'MAX attack rate']

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



	#Create dataframe from sql query 

	for day in days_list:
		df_events_count_this_day =  pd.DataFrame(pd.read_sql_query(f"select name as 'Attack Name', count(*) as '{day}' from attacks where startDayOfMonth = {day} group by name order by count(*) desc", con)).set_index('Attack Name')
		df_packets_count_this_day = pd.DataFrame(pd.read_sql_query(f"select name as 'Attack Name',sum(packetCount) as '{day}' from attacks where startDayOfMonth = {day} group by name order by sum(packetCount) desc", con)).set_index('Attack Name')
		df_bandwidth_sum_this_day = pd.DataFrame(pd.read_sql_query(f"select name as 'Attack Name',sum(packetBandwidth) as '{day}' from attacks where startDayOfMonth = {day} group by name order by sum(packetBandwidth) desc", con)).set_index('Attack Name')

		df_device_events_count_this_day =  pd.DataFrame(pd.read_sql_query(f"select deviceName as 'Device Name',count(*) as '{day}' from attacks where startDayOfMonth = {day} group by deviceName order by count(*) desc", con)).set_index('Device Name')
		df_device_packets_count_this_day = pd.DataFrame(pd.read_sql_query(f"select deviceName as 'Device Name',sum(packetCount) as '{day}' from attacks where startDayOfMonth = {day} group by deviceName order by sum(packetCount) desc", con)).set_index('Device Name')
		df_device_bandwidth_sum_this_day = pd.DataFrame(pd.read_sql_query(f"select deviceName as 'Device Name',sum(packetBandwidth) as '{day}' from attacks where startDayOfMonth = {day} group by deviceName order by sum(packetBandwidth) desc", con)).set_index('Device Name')

		df_policy_events_count_this_day =  pd.DataFrame(pd.read_sql_query(f"select ruleName as 'Policy Name',count(*) as '{day}' from attacks where startDayOfMonth = {day} group by ruleName order by count(*) desc", con)).set_index('Policy Name')
		df_policy_packets_count_this_day = pd.DataFrame(pd.read_sql_query(f"select ruleName as 'Policy Name',sum(packetCount) as '{day}' from attacks where startDayOfMonth = {day} group by ruleName order by sum(packetCount) desc", con)).set_index('Policy Name')
		df_policy_bandwidth_sum_this_day = pd.DataFrame(pd.read_sql_query(f"select ruleName as 'Policy Name',sum(packetBandwidth) as '{day}' from attacks where startDayOfMonth = {day} group by ruleName order by sum(packetBandwidth) desc", con)).set_index('Policy Name')
			
		df_srcip_events_count_this_day =  pd.DataFrame(pd.read_sql_query(f"select sourceAddress as 'Source IP',count(*) as '{day}' from attacks where startDayOfMonth = {day} group by sourceAddress order by count(*) desc", con)).set_index('Source IP')
		df_srcip_packets_count_this_day = pd.DataFrame(pd.read_sql_query(f"select sourceAddress as 'Source IP',sum(packetCount) as '{day}' from attacks where startDayOfMonth = {day} group by sourceAddress order by sum(packetCount) desc", con)).set_index('Source IP')
		df_srcip_bandwidth_sum_this_day = pd.DataFrame(pd.read_sql_query(f"select sourceAddress as 'Source IP',sum(packetBandwidth)/8000 as '{day}' from attacks where startDayOfMonth = {day} group by sourceAddress order by sum(packetBandwidth) desc", con)).set_index('Source IP')

		events_count_list.append(df_events_count_this_day)		
		packets_count_list.append(df_packets_count_this_day)
		bandwidth_sum_list.append(df_bandwidth_sum_this_day)

		device_events_count_list.append(df_device_events_count_this_day)		
		device_packets_count_list.append(df_device_packets_count_this_day)
		device_bandwidth_sum_list.append(df_device_bandwidth_sum_this_day)

		policy_events_count_list.append(df_policy_events_count_this_day)		
		policy_packets_count_list.append(df_policy_packets_count_this_day)
		policy_bandwidth_sum_list.append(df_policy_bandwidth_sum_this_day)

		srcip_events_count_list.append(df_srcip_events_count_this_day)
		srcip_packets_count_list.append(df_srcip_packets_count_this_day)
		srcip_bandwidth_sum_list.append(df_srcip_bandwidth_sum_this_day)

	

	con.close()	
	f.close()


	# ###############Attack Name Events Count trends by last month################
	# events_count_trend_chart_by_last_day = pd.concat(events_count_list,axis=1).fillna(0).sort_values(by=str(day), ascending=False)
	# events_count_trend_chart_by_last_day.T.iloc[: , :top_n].to_csv(tmp_path + 'events_per_day_chart_lm.csv')
	# events_count_trend_chart_by_last_day.head(top_n).to_csv(tmp_path + 'events_per_day_table_lm.csv') #save events count trend table (sorted by last month highest to lowest) to csv file





	##############################################################################
	# 1 ###############Attack Name Events Count trends all time high################
	events_count_trend_chart_all_times = pd.concat(events_count_list,axis=1).fillna(0)#.sort_values(by=day, ascending=False)

	# Create a new column with the absolute sum of values across columns
	# events_count_trend_chart_all_times['Total'] = events_count_trend_chart_all_times.iloc[:, 1:].abs().sum(axis=1)

	events_count_trend_chart_all_times['Total'] = events_count_trend_chart_all_times.abs().sum(axis=1)

	# Sort the DataFrame by the absolute sum column in descending order
	events_count_trend_chart_all_times_alltimehigh = events_count_trend_chart_all_times.sort_values(by='Total', ascending=False)

	events_count_trend_chart_all_times_alltimehigh.head(top_n)       .to_csv(tmp_path + 'events_per_day_table_alltimehigh.csv') #save events count table (all time high sum) to csv file

	# Drop the temporary column used for sorting
	events_count_trend_chart_all_times_alltimehigh = events_count_trend_chart_all_times_alltimehigh.drop(columns='Total')
	events_count_trend_chart_all_times_alltimehigh.T.iloc[: , :top_n].to_csv(tmp_path + 'events_per_day_chart_alltimehigh.csv') #save events count chart (all time high sum) to csv file



	# ###############Attack Name Packets Count trends by last day ################

	# packets_count_trend_chart_by_last_day = pd.concat(packets_count_list,axis=1).fillna(0).sort_values(by=[str(day)], ascending=False)
	# packets_count_trend_chart_by_last_day.T.iloc[: , :top_n].to_csv(tmp_path + 'packets_per_day_chart_lm.csv') #save packets count chart (sorted by last month highest to lowest) to csv file
	# packets_count_trend_chart_by_last_day.head(top_n)       .to_csv(tmp_path + 'packets_per_day_table_lm.csv') #save packets count table (sorted by last month highest to lowest) to csv file




	# 2 ###############Attack Name Packets Count trends all time high################

	packets_count_trend_chart_all_times = pd.concat(packets_count_list,axis=1).fillna(0)
	# Create a new column with the absolute sum of values across columns
	packets_count_trend_chart_all_times['Total'] = packets_count_trend_chart_all_times.abs().sum(axis=1)

	# Sort the DataFrame by the absolute sum column in descending order
	packets_count_trend_chart_all_times_sorted = packets_count_trend_chart_all_times.sort_values(by='Total', ascending=False)

	# Save the table to a CSV file
	packets_count_trend_chart_all_times_sorted.head(top_n).to_csv(tmp_path + 'packets_per_day_table_alltimehigh.csv')

	# Drop the temporary column used for sorting
	packets_count_trend_chart_all_times_sorted = packets_count_trend_chart_all_times_sorted.drop(columns='Total')

	# Save the chart to a CSV file
	packets_count_trend_chart_all_times_sorted.T.iloc[:, :top_n].to_csv(tmp_path + 'packets_per_day_chart_alltimehigh.csv')


	# ###############Attack Name Bandwidth sum trends by last month################

	# bandwidth_sum_trend_chart_by_last_day = pd.concat(bandwidth_sum_list,axis=1).fillna(0).sort_values(by=[str(day)], ascending=False)
	# bandwidth_sum_trend_chart_by_last_day.T.iloc[: , :top_n].to_csv(tmp_path + 'bandwidth_per_day_chart_lm.csv') #save packets count chart (sorted by last month highest to lowest) to csv file
	# bandwidth_sum_trend_chart_by_last_day.head(top_n)       .to_csv(tmp_path + 'bandwidth_per_day_table_lm.csv') #save packets count table (sorted by last month highest to lowest) to csv file


	# 3 ###############Attack Name Malicious badwidth trends all time high################

	bandwidth_sum_trend_chart_all_times = pd.concat(bandwidth_sum_list,axis=1).fillna(0)

	# Create a new column with the absolute sum of values across columns
	bandwidth_sum_trend_chart_all_times['Total'] = bandwidth_sum_trend_chart_all_times.abs().sum(axis=1)

	# Sort the DataFrame by the absolute sum column in descending order
	bandwidth_sum_trend_chart_all_times_sorted = bandwidth_sum_trend_chart_all_times.sort_values(by='Total', ascending=False)

	# Save the table to a CSV file
	bandwidth_sum_trend_chart_all_times_sorted.head(top_n).to_csv(tmp_path + 'bandwidth_per_day_table_alltimehigh.csv')


	# Drop the temporary column used for sorting
	bandwidth_sum_trend_chart_all_times_sorted = bandwidth_sum_trend_chart_all_times_sorted.drop(columns='Total')

	# Save the chart to a CSV file
	bandwidth_sum_trend_chart_all_times_sorted.T.iloc[:, :top_n].to_csv(tmp_path + 'bandwidth_per_day_chart_alltimehigh.csv')



	# ###############Device Name Events Count trends ################

	device_events_count_trend_chart_all_times = pd.concat(device_events_count_list,axis=1).fillna(0)#.sort_values(by=[str(day)], ascending=False)

	device_events_count_trend_chart_all_times['Total'] = device_events_count_trend_chart_all_times.abs().sum(axis=1)

	# Sort the DataFrame by the absolute sum column in descending order
	device_events_count_trend_chart_all_times = device_events_count_trend_chart_all_times.sort_values(by='Total', ascending=False)


	#Translate DP IP to DP Name
	for df_dp_ip in device_events_count_trend_chart_all_times.index:
		for dp_ip, dp_name in defensepros.items():
			if df_dp_ip == dp_ip:
				device_events_count_trend_chart_all_times.rename(index={df_dp_ip:dp_name}, inplace=True)

	device_events_count_trend_chart_all_times.head(top_n).to_csv(tmp_path + 'device_events_per_day_table_alltimehigh.csv') #save events count trend table (sorted by last month highest to lowest) to csv file
	device_events_count_trend_chart_all_times = device_events_count_trend_chart_all_times.drop(columns='Total')
	device_events_count_trend_chart_all_times.T.iloc[: , :top_n].to_csv(tmp_path + 'device_events_per_day_chart_alltimehigh.csv')


	# ###############Device Name Packets Count trends ################

	device_packets_count_trend_chart = pd.concat(device_packets_count_list,axis=1).fillna(0)#.sort_values(by=[str(day)], ascending=False)

	# Create a new column with the absolute sum of values across columns
	device_packets_count_trend_chart['Total'] = device_packets_count_trend_chart.abs().sum(axis=1)

	# Sort the DataFrame by the absolute sum column in descending order
	device_packets_count_trend_chart_alltimehigh = device_packets_count_trend_chart.sort_values(by='Total', ascending=False)


	#Translate DP IP to DP Name
	for df_dp_ip in device_packets_count_trend_chart_alltimehigh.index:
		for dp_ip, dp_name in defensepros.items():
			if df_dp_ip == dp_ip:
				device_packets_count_trend_chart_alltimehigh.rename(index={df_dp_ip:dp_name}, inplace=True)

	device_packets_count_trend_chart_alltimehigh.head(top_n)       .to_csv(tmp_path + 'device_packets_per_day_table_alltimehigh.csv') #save packets count table (sorted by last month highest to lowest) to csv file
	# Drop the temporary column used for sorting
	device_packets_count_trend_chart_alltimehigh = device_packets_count_trend_chart_alltimehigh.drop(columns='Total')

	device_packets_count_trend_chart_alltimehigh.T.iloc[: , :top_n].to_csv(tmp_path + 'device_packets_per_day_chart_alltimehigh.csv') #save packets count chart (sorted by last month highest to lowest) to csv file

	# ###############Device Name Bandwidh trends ################

	device_bandwidth_sum_trend_chart = pd.concat(device_bandwidth_sum_list,axis=1).fillna(0)#.sort_values(by=[str(day)], ascending=False)
	# Create a new column with the absolute sum of values across columns
	device_bandwidth_sum_trend_chart['Total'] = device_bandwidth_sum_trend_chart.abs().sum(axis=1)

	# Sort the DataFrame by the absolute sum column in descending order
	device_bandwidth_sum_trend_chart_alltimehigh = device_bandwidth_sum_trend_chart.sort_values(by='Total', ascending=False)

	#Translate DP IP to DP Name
	for df_dp_ip in device_bandwidth_sum_trend_chart_alltimehigh.index:
		for dp_ip, dp_name in defensepros.items():
			if df_dp_ip == dp_ip:
				device_bandwidth_sum_trend_chart_alltimehigh.rename(index={df_dp_ip:dp_name}, inplace=True)

	device_bandwidth_sum_trend_chart_alltimehigh.head(top_n)       .to_csv(tmp_path + 'device_bandwidth_per_day_table_alltimehigh.csv') #save packets count table (sorted by last month highest to lowest) to csv file

	# Drop the temporary column used for sorting
	device_bandwidth_sum_trend_chart_alltimehigh = device_bandwidth_sum_trend_chart_alltimehigh.drop(columns='Total')

	device_bandwidth_sum_trend_chart_alltimehigh.T.iloc[: , :top_n].to_csv(tmp_path + 'device_bandwidth_per_day_chart_alltimehigh.csv') #save packets count chart (sorted by last month highest to lowest) to csv file



	# ###############Policy Name Events Count trends################

	# policy_events_count_trend_chart_by_last_day = pd.concat(policy_events_count_list,axis=1).fillna(0).sort_values(by=[str(day)], ascending=False)
	# policy_events_count_trend_chart_by_last_day.T.iloc[: , :top_n].to_csv(tmp_path + 'policy_events_per_day_chart_lm.csv')
	# policy_events_count_trend_chart_by_last_day.head(top_n)       .to_csv(tmp_path + 'policy_events_per_day_table_lm.csv') #save events count trend table (sorted by last month highest to lowest) to csv file
	
	df_policy_events_count_trend_chart_all_times = pd.concat(policy_events_count_list,axis=1).fillna(0)

	df_policy_events_count_trend_chart_all_times['Total'] = df_policy_events_count_trend_chart_all_times.abs().sum(axis=1)

	# Sort the DataFrame by the absolute sum column in descending order
	df_policy_events_count_trend_chart_all_times = df_policy_events_count_trend_chart_all_times.sort_values(by='Total', ascending=False)

	df_policy_events_count_trend_chart_all_times.head(top_n).to_csv(tmp_path + 'policy_events_per_day_table_alltimehigh.csv') #save events count trend table (sorted by last month highest to lowest) to csvpolicy

	df_policy_events_count_trend_chart_all_times = df_policy_events_count_trend_chart_all_times.drop(columns='Total')

	df_policy_events_count_trend_chart_all_times.T.iloc[: , :top_n].to_csv(tmp_path + 'policy_events_per_day_chart_alltimehigh.csv')




	# ###############Policy Name Packets Count trends################

	# policy_packets_count_trend_chart_by_last_day = pd.concat(policy_packets_count_list,axis=1).fillna(0).sort_values(by=[str(day)], ascending=False)
	# policy_packets_count_trend_chart_by_last_day.T.iloc[: , :top_n].to_csv(tmp_path + 'policy_packets_per_day_chart_lm.csv') #save packets count chart (sorted by last month highest to lowest) to csv file
	# policy_packets_count_trend_chart_by_last_day.head(top_n)       .to_csv(tmp_path + 'policy_packets_per_day_table_lm.csv') #save packets count table (sorted by last month highest to lowest) to csv file


	policy_packets_count_trend_chart = pd.concat(policy_packets_count_list,axis=1).fillna(0)

	# Create a new column with the absolute sum of values across columns
	policy_packets_count_trend_chart['Total'] = policy_packets_count_trend_chart.abs().sum(axis=1)

	# Sort the DataFrame by the absolute sum column in descending order
	policy_packets_count_trend_chart_alltimehigh = policy_packets_count_trend_chart.sort_values(by='Total', ascending=False)

	policy_packets_count_trend_chart_alltimehigh.head(top_n)       .to_csv(tmp_path + 'policy_packets_per_day_table_alltimehigh.csv') #save packets count table (sorted by last month highest to lowest) to csv file
	# Drop the temporary column used for sorting
	policy_packets_count_trend_chart_alltimehigh = policy_packets_count_trend_chart_alltimehigh.drop(columns='Total')

	policy_packets_count_trend_chart_alltimehigh.T.iloc[: , :top_n].to_csv(tmp_path + 'policy_packets_per_day_chart_alltimehigh.csv') #save packets count chart (sorted by last month highest to lowest) to csv file



	# ###############Policy Name Packets Count trends by last month################

	# policy_bandwidth_sum_trend_chart_by_last_day = pd.concat(policy_bandwidth_sum_list,axis=1).fillna(0).sort_values(by=[str(day)], ascending=False)
	# policy_bandwidth_sum_trend_chart_by_last_day.T.iloc[: , :top_n].to_csv(tmp_path + 'policy_bandwidth_per_day_chart_lm.csv') #save packets count chart (sorted by last month highest to lowest) to csv file
	# policy_bandwidth_sum_trend_chart_by_last_day.head(top_n)       .to_csv(tmp_path + 'policy_bandwidth_per_day_table_lm.csv') #save packets count table (sorted by last month highest to lowest) to csv file

	policy_bandwidth_sum_trend_chart = pd.concat(policy_bandwidth_sum_list,axis=1).fillna(0)
	# Create a new column with the absolute sum of values across columns
	policy_bandwidth_sum_trend_chart['Total'] = policy_bandwidth_sum_trend_chart.abs().sum(axis=1)

	# Sort the DataFrame by the absolute sum column in descending order
	policy_bandwidth_sum_trend_chart_alltimehigh = policy_bandwidth_sum_trend_chart.sort_values(by='Total', ascending=False)

	policy_bandwidth_sum_trend_chart_alltimehigh.head(top_n)       .to_csv(tmp_path + 'policy_bandwidth_per_day_table_alltimehigh.csv') #save packets count table (sorted by last month highest to lowest) to csv file

	# Drop the temporary column used for sorting
	policy_bandwidth_sum_trend_chart_alltimehigh = policy_bandwidth_sum_trend_chart_alltimehigh.drop(columns='Total')

	policy_bandwidth_sum_trend_chart_alltimehigh.T.iloc[: , :top_n].to_csv(tmp_path + 'policy_bandwidth_per_day_chart_alltimehigh.csv') #save packets count chart (sorted by last month highest to lowest) to csv file



	# # ###############Top 10 source IP by events count by last day ################

	# srcip_events_trend_chart_by_last_day = pd.concat(srcip_events_count_list,axis=1).fillna(0)#.sort_values(by=[str(day)], ascending=False)

	# if 'Multiple' in srcip_events_trend_chart_by_last_day.index:
	# 	srcip_events_trend_chart_by_last_day = srcip_events_trend_chart_by_last_day.drop(['Multiple'])
	# if '0.0.0.0' in srcip_events_trend_chart_by_last_day.index:
	# 	srcip_events_trend_chart_by_last_day = srcip_events_trend_chart_by_last_day.drop(['0.0.0.0'])
	

	# srcip_events_trend_chart_by_last_day = srcip_events_trend_chart_by_last_day.iloc[:top_n]

	# srcip_events_list = srcip_events_trend_chart_by_last_day.index[0:top_n].tolist()

	# srcip_events_trend_chart_by_last_day.T.iloc[: , :top_n].to_csv(tmp_path + 'sip_events_per_day_chart_lm.csv') #save packets count chart (sorted by last month highest to lowest) to csv file
	
	
	# if internet_conn and aidb.internet_conn():
		
	# 	for ip in srcip_events_list:
	# 		aidb.abuseipdb_call(ip, cust_id)

	# 	srcip_events_trend_chart_by_last_day['srcip'] = srcip_events_trend_chart_by_last_day.index
	# 	srcip_events_trend_chart_by_last_day['GEO'] = srcip_events_trend_chart_by_last_day['srcip'].apply(AbuseIPDBGEO)
	# 	srcip_events_trend_chart_by_last_day['Abuse Confidence'] = srcip_events_trend_chart_by_last_day['srcip'].apply(AbuseIPDBScore)
	# 	srcip_events_trend_chart_by_last_day['ISP'] = srcip_events_trend_chart_by_last_day['srcip'].apply(AbuseIPDBISP)

	# 	srcip_events_trend_chart_by_last_day = srcip_events_trend_chart_by_last_day.drop(['srcip'], axis=1)

	# 	cols = srcip_events_trend_chart_by_last_day.columns.tolist()
	# 	cols = cols[-1:] + cols[:-1]
	# 	cols = cols[-1:] + cols[:-1]
	# 	cols = cols[-1:] + cols[:-1]
	# 	srcip_events_trend_chart_by_last_day = srcip_events_trend_chart_by_last_day[cols]

	# 	srcip_events_trend_chart_by_last_day.head(top_n).to_csv(tmp_path + 'sip_events_per_day_table_lm.csv') #save packets count table (sorted by last month highest to lowest) to csv file

	# else:

	# 	srcip_events_trend_chart_by_last_day.insert(0, "GEO", "N/A", True)
	# 	srcip_events_trend_chart_by_last_day.insert(1, "Abuse Confidence", 0, True)
	# 	srcip_events_trend_chart_by_last_day.insert(2, "ISP", "N/A", True)
	# 	srcip_events_trend_chart_by_last_day.head(top_n).to_csv(tmp_path + 'sip_events_per_day_table_lm.csv') #save packets count table (sorted by last month highest to lowest) to csv file




	# ###############Top 10 source IP by events count by last month################

	srcip_events_trend_chart_alltimehigh = pd.concat(srcip_events_count_list,axis=1).fillna(0)#.sort_values(by=[str(day)], ascending=False)
	srcip_events_trend_chart_alltimehigh['Total'] = srcip_events_trend_chart_alltimehigh.abs().sum(axis=1)
	srcip_events_trend_chart_alltimehigh = srcip_events_trend_chart_alltimehigh.sort_values(by='Total', ascending=False)


	if 'Multiple' in srcip_events_trend_chart_alltimehigh.index:
		srcip_events_trend_chart_alltimehigh = srcip_events_trend_chart_alltimehigh.drop(['Multiple'])
	if '0.0.0.0' in srcip_events_trend_chart_alltimehigh.index:
		srcip_events_trend_chart_alltimehigh = srcip_events_trend_chart_alltimehigh.drop(['0.0.0.0'])


	srcip_events_trend_chart_alltimehigh = srcip_events_trend_chart_alltimehigh.iloc[:top_n]

	srcip_events_list = srcip_events_trend_chart_alltimehigh.index[0:top_n].tolist()

	srcip_events_trend_chart_alltimehigh.T.iloc[: , :top_n].to_csv(tmp_path + 'sip_events_per_day_chart_alltimehigh.csv') #save packets count chart (sorted by last month highest to lowest) to csv file


	if abuseipdb and aidb.internet_conn():
		
		for ip in srcip_events_list:
			aidb.abuseipdb_call(ip, cust_id)

		srcip_events_trend_chart_alltimehigh['srcip'] = srcip_events_trend_chart_alltimehigh.index
		srcip_events_trend_chart_alltimehigh['GEO'] = srcip_events_trend_chart_alltimehigh['srcip'].apply(AbuseIPDBGEO)
		srcip_events_trend_chart_alltimehigh['Abuse Confidence'] = srcip_events_trend_chart_alltimehigh['srcip'].apply(AbuseIPDBScore)
		srcip_events_trend_chart_alltimehigh['ISP'] = srcip_events_trend_chart_alltimehigh['srcip'].apply(AbuseIPDBISP)

		srcip_events_trend_chart_alltimehigh = srcip_events_trend_chart_alltimehigh.drop(['srcip'], axis=1)

		cols = srcip_events_trend_chart_alltimehigh.columns.tolist()
		cols = cols[-1:] + cols[:-1]
		cols = cols[-1:] + cols[:-1]
		cols = cols[-1:] + cols[:-1]
		srcip_events_trend_chart_alltimehigh = srcip_events_trend_chart_alltimehigh[cols]

		srcip_events_trend_chart_alltimehigh.head(top_n).to_csv(tmp_path + 'sip_events_per_day_table_alltimehigh.csv') #save packets count table (sorted by last month highest to lowest) to csv file

	else:

		srcip_events_trend_chart_alltimehigh.insert(0, "GEO", "N/A", True)
		srcip_events_trend_chart_alltimehigh.insert(1, "Abuse Confidence", 0, True)
		srcip_events_trend_chart_alltimehigh.insert(2, "ISP", "N/A", True)
		srcip_events_trend_chart_alltimehigh.head(top_n).to_csv(tmp_path + 'sip_events_per_day_table_alltimehigh.csv') #save packets count table (sorted by last month highest to lowest) to csv file




	# ###############Top 10 source IP by packets count by last day################

	# srcip_packets_trend_chart_by_last_day = pd.concat(srcip_packets_count_list,axis=1).fillna(0).sort_values(by=[str(day)], ascending=False)
	
	# if 'Multiple' in srcip_packets_trend_chart_by_last_day.index:
	# 	srcip_packets_trend_chart_by_last_day = srcip_packets_trend_chart_by_last_day.drop(['Multiple'])
	# if '0.0.0.0' in srcip_packets_trend_chart_by_last_day.index:
	# 	srcip_packets_trend_chart_by_last_day = srcip_packets_trend_chart_by_last_day.drop(['0.0.0.0'])
	

	# srcip_packets_trend_chart_by_last_day = srcip_packets_trend_chart_by_last_day.iloc[:top_n] #get top 10 source ip by packets count
	# srcip_packets_trend_chart_by_last_day.T.to_csv(tmp_path + 'sip_packets_per_day_chart_lm.csv') #save packets count chart (sorted by last month highest to lowest) to csv file
	
	# srcip_packets_list = srcip_packets_trend_chart_by_last_day.index[0:top_n].tolist()
	
	# if internet_conn and aidb.internet_conn():

	# 	for ip in srcip_packets_list:
	# 		aidb.abuseipdb_call(ip, cust_id)

	# 	srcip_packets_trend_chart_by_last_day['srcip'] = srcip_packets_trend_chart_by_last_day.index
	# 	srcip_packets_trend_chart_by_last_day['GEO'] = srcip_packets_trend_chart_by_last_day['srcip'].apply(AbuseIPDBGEO)
	# 	srcip_packets_trend_chart_by_last_day['Abuse Confidence'] = srcip_packets_trend_chart_by_last_day['srcip'].apply(AbuseIPDBScore)
	# 	srcip_packets_trend_chart_by_last_day['ISP'] = srcip_packets_trend_chart_by_last_day['srcip'].apply(AbuseIPDBISP)


	# 	srcip_packets_trend_chart_by_last_day = srcip_packets_trend_chart_by_last_day.drop(['srcip'], axis=1)

	# 	cols = srcip_packets_trend_chart_by_last_day.columns.tolist()
	# 	cols = cols[-1:] + cols[:-1]
	# 	cols = cols[-1:] + cols[:-1]
	# 	cols = cols[-1:] + cols[:-1]
	# 	srcip_packets_trend_chart_by_last_day = srcip_packets_trend_chart_by_last_day[cols]

	# 	srcip_packets_trend_chart_by_last_day.head(top_n).to_csv(tmp_path + 'sip_packets_per_day_table_lm.csv')
	# else:

	# 	srcip_packets_trend_chart_by_last_day.insert(0, "GEO", "N/A", True)
	# 	srcip_packets_trend_chart_by_last_day.insert(1, "Abuse Confidence", 0 , True)
	# 	srcip_packets_trend_chart_by_last_day.insert(2, "ISP", "N/A", True)
	# 	srcip_packets_trend_chart_by_last_day.head(top_n).to_csv(tmp_path + 'sip_packets_per_day_table_lm.csv') #save packets count table (sorted by last month highest to lowest) to csv file


	# ###############Top 10 source IP by packets count alltimehigh################

	srcip_packets_trend_chart_alltimehigh = pd.concat(srcip_packets_count_list,axis=1).fillna(0)
	srcip_packets_trend_chart_alltimehigh['Total'] = srcip_packets_trend_chart_alltimehigh.abs().sum(axis=1)
	srcip_packets_trend_chart_alltimehigh = srcip_packets_trend_chart_alltimehigh.sort_values(by='Total', ascending=False)


	if 'Multiple' in srcip_packets_trend_chart_alltimehigh.index:
		srcip_packets_trend_chart_alltimehigh = srcip_packets_trend_chart_alltimehigh.drop(['Multiple'])
	if '0.0.0.0' in srcip_packets_trend_chart_alltimehigh.index:
		srcip_packets_trend_chart_alltimehigh = srcip_packets_trend_chart_alltimehigh.drop(['0.0.0.0'])


	srcip_packets_trend_chart_alltimehigh = srcip_packets_trend_chart_alltimehigh.iloc[:top_n] #get top 10 source ip by packets count
	srcip_packets_trend_chart_alltimehigh.T.to_csv(tmp_path + 'sip_packets_per_day_chart_alltimehigh.csv') #save packets count chart (sorted by last month highest to lowest) to csv file

	srcip_packets_list = srcip_packets_trend_chart_alltimehigh.index[0:top_n].tolist()

	if abuseipdb and aidb.internet_conn():

		for ip in srcip_packets_list:
			aidb.abuseipdb_call(ip, cust_id)

		srcip_packets_trend_chart_alltimehigh['srcip'] = srcip_packets_trend_chart_alltimehigh.index
		srcip_packets_trend_chart_alltimehigh['GEO'] = srcip_packets_trend_chart_alltimehigh['srcip'].apply(AbuseIPDBGEO)
		srcip_packets_trend_chart_alltimehigh['Abuse Confidence'] = srcip_packets_trend_chart_alltimehigh['srcip'].apply(AbuseIPDBScore)
		srcip_packets_trend_chart_alltimehigh['ISP'] = srcip_packets_trend_chart_alltimehigh['srcip'].apply(AbuseIPDBISP)


		srcip_packets_trend_chart_alltimehigh = srcip_packets_trend_chart_alltimehigh.drop(['srcip'], axis=1)

		cols = srcip_packets_trend_chart_alltimehigh.columns.tolist()
		cols = cols[-1:] + cols[:-1]
		cols = cols[-1:] + cols[:-1]
		cols = cols[-1:] + cols[:-1]
		srcip_packets_trend_chart_alltimehigh = srcip_packets_trend_chart_alltimehigh[cols]

		srcip_packets_trend_chart_alltimehigh.head(top_n).to_csv(tmp_path + 'sip_packets_per_day_table_alltimehigh.csv')
	else:

		srcip_packets_trend_chart_alltimehigh.insert(0, "GEO", "N/A", True)
		srcip_packets_trend_chart_alltimehigh.insert(1, "Abuse Confidence", 0 , True)
		srcip_packets_trend_chart_alltimehigh.insert(2, "ISP", "N/A", True)
		srcip_packets_trend_chart_alltimehigh.head(top_n).to_csv(tmp_path + 'sip_packets_per_day_table_alltimehigh.csv') #save packets count table (sorted by last month highest to lowest) to csv file


	# ###############Top 10 source IP by bandwidth sum by last day ################

	# srcip_bandwidth_trend_chart_by_last_day = pd.concat(srcip_bandwidth_sum_list,axis=1).fillna(0).sort_values(by=[str(day)], ascending=False)

	# if 'Multiple' in srcip_bandwidth_trend_chart_by_last_day.index:
	# 	srcip_bandwidth_trend_chart_by_last_day = srcip_bandwidth_trend_chart_by_last_day.drop(['Multiple'])
	# if '0.0.0.0' in srcip_bandwidth_trend_chart_by_last_day.index:
	# 	srcip_bandwidth_trend_chart_by_last_day = srcip_bandwidth_trend_chart_by_last_day.drop(['0.0.0.0'])
	
	# srcip_bandwidth_trend_chart_by_last_day.T.iloc[: , :top_n].to_csv(tmp_path + 'sip_bandwidth_per_day_chart_lm.csv') #save src ip bandwidth chart (sorted by last month highest to lowest) to csv file

	# srcip_bandwidth_list = srcip_bandwidth_trend_chart_by_last_day.index[0:top_n].tolist()

	# if internet_conn and aidb.internet_conn():

	# 	for ip in srcip_bandwidth_list:
	# 		aidb.abuseipdb_call(ip, cust_id)

	# 	srcip_bandwidth_trend_chart_by_last_day['srcip'] = srcip_bandwidth_trend_chart_by_last_day.index
	# 	srcip_bandwidth_trend_chart_by_last_day['GEO'] = srcip_bandwidth_trend_chart_by_last_day['srcip'].apply(AbuseIPDBGEO)
	# 	srcip_bandwidth_trend_chart_by_last_day['Abuse Confidence'] = srcip_bandwidth_trend_chart_by_last_day['srcip'].apply(AbuseIPDBScore)
	# 	srcip_bandwidth_trend_chart_by_last_day['ISP'] = srcip_bandwidth_trend_chart_by_last_day['srcip'].apply(AbuseIPDBISP)


	# 	srcip_bandwidth_trend_chart_by_last_day = srcip_bandwidth_trend_chart_by_last_day.drop(['srcip'], axis=1)

	# 	cols = srcip_bandwidth_trend_chart_by_last_day.columns.tolist()
	# 	cols = cols[-1:] + cols[:-1]
	# 	cols = cols[-1:] + cols[:-1]
	# 	cols = cols[-1:] + cols[:-1]
	# 	srcip_bandwidth_trend_chart_by_last_day = srcip_bandwidth_trend_chart_by_last_day[cols]

	# 	srcip_bandwidth_trend_chart_by_last_day.head(top_n).to_csv(tmp_path + 'sip_bandwidth_per_day_table_lm.csv')
		
	# else:

	# 	srcip_bandwidth_trend_chart_by_last_day.insert(0, "GEO", "N/A", True)
	# 	srcip_bandwidth_trend_chart_by_last_day.insert(1, "Abuse Confidence", 0 , True)
	# 	srcip_bandwidth_trend_chart_by_last_day.insert(2, "ISP", "N/A", True)
	# 	srcip_bandwidth_trend_chart_by_last_day.head(top_n).to_csv(tmp_path + 'sip_bandwidth_per_day_table_lm.csv') #save packets count table (sorted by last month highest to lowest) to csv file




	# ###############Top 10 source IP by bandwidth sum - all time high ################


	srcip_bandwidth_trend_chart_alltimehigh = pd.concat(srcip_bandwidth_sum_list,axis=1).fillna(0)
	srcip_bandwidth_trend_chart_alltimehigh['Total'] = srcip_bandwidth_trend_chart_alltimehigh.abs().sum(axis=1)
	srcip_bandwidth_trend_chart_alltimehigh = srcip_bandwidth_trend_chart_alltimehigh.sort_values(by='Total', ascending=False)



	if 'Multiple' in srcip_bandwidth_trend_chart_alltimehigh.index:
		srcip_bandwidth_trend_chart_alltimehigh = srcip_bandwidth_trend_chart_alltimehigh.drop(['Multiple'])
	if '0.0.0.0' in srcip_bandwidth_trend_chart_alltimehigh.index:
		srcip_bandwidth_trend_chart_alltimehigh = srcip_bandwidth_trend_chart_alltimehigh.drop(['0.0.0.0'])

	srcip_bandwidth_trend_chart_alltimehigh.T.iloc[: , :top_n].to_csv(tmp_path + 'sip_bandwidth_per_day_chart_alltimehigh.csv') #save src ip bandwidth chart (sorted by last month highest to lowest) to csv file

	srcip_bandwidth_list = srcip_bandwidth_trend_chart_alltimehigh.index[0:top_n].tolist()

	if abuseipdb and aidb.internet_conn():

		for ip in srcip_bandwidth_list:
			aidb.abuseipdb_call(ip, cust_id)

		srcip_bandwidth_trend_chart_alltimehigh['srcip'] = srcip_bandwidth_trend_chart_alltimehigh.index
		srcip_bandwidth_trend_chart_alltimehigh['GEO'] = srcip_bandwidth_trend_chart_alltimehigh['srcip'].apply(AbuseIPDBGEO)
		srcip_bandwidth_trend_chart_alltimehigh['Abuse Confidence'] = srcip_bandwidth_trend_chart_alltimehigh['srcip'].apply(AbuseIPDBScore)
		srcip_bandwidth_trend_chart_alltimehigh['ISP'] = srcip_bandwidth_trend_chart_alltimehigh['srcip'].apply(AbuseIPDBISP)


		srcip_bandwidth_trend_chart_alltimehigh = srcip_bandwidth_trend_chart_alltimehigh.drop(['srcip'], axis=1)

		cols = srcip_bandwidth_trend_chart_alltimehigh.columns.tolist()
		cols = cols[-1:] + cols[:-1]
		cols = cols[-1:] + cols[:-1]
		cols = cols[-1:] + cols[:-1]
		srcip_bandwidth_trend_chart_alltimehigh = srcip_bandwidth_trend_chart_alltimehigh[cols]

		srcip_bandwidth_trend_chart_alltimehigh.head(top_n).to_csv(tmp_path + 'sip_bandwidth_per_day_table_alltimehigh.csv')
		
	else:

		srcip_bandwidth_trend_chart_alltimehigh.insert(0, "GEO", "N/A", True)
		srcip_bandwidth_trend_chart_alltimehigh.insert(1, "Abuse Confidence", 0 , True)
		srcip_bandwidth_trend_chart_alltimehigh.insert(2, "ISP", "N/A", True)
		srcip_bandwidth_trend_chart_alltimehigh.head(top_n).to_csv(tmp_path + 'sip_bandwidth_per_day_table_alltimehigh.csv') #save packets count table (sorted by last month highest to lowest) to csv file



gen_charts_data(db_path)

print("--- %s seconds ---" % (time.time() - start_time))
