from requests import Session
import requests
import json
import os
import time
import sys
from datetime import datetime, timedelta,timezone
import calendar
import csv
import sqlite3
import urllib3
import pandas as pd

daily = False
monthly = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

cust_id = sys.argv[1]

try:
	if sys.argv[2].lower() =="monthly":
		monthly = True
	elif sys.argv[2].lower() =="daily":
		daily = True
except:
	print('Error: Second argument is not set. Second argument must be either "daily" (data collection for the previous day) or "monthly" (data collection for the previous month). Example:\r\n\r\n collector.py CUSTOMER_NAME monthly')
	sys.exit()

cur_month = int(sys.argv[3])
cur_day = int(sys.argv[4])
cur_year = int(sys.argv[5])

raw_data_path = f"./raw_data_files/{cust_id}/"
tmp_files_path = f"./tmp_files/{cust_id}/"
db_files_path = f"./database_files/{cust_id}/"

################################# !!! Temp config for testing  ##################

offline = False # Set to True to test without connecting to Vision

######################################################################


# Check if the directory exists, and create it if it doesn't
if not os.path.exists(raw_data_path):
    os.makedirs(raw_data_path)

if not os.path.exists(tmp_files_path):
    os.makedirs(tmp_files_path)

if not os.path.exists(db_files_path):
	os.makedirs(db_files_path)
	
################################# Extract variables from customers.json #########################################

try:
	customers_json_dic = json.loads(open("./config_files/customers.json", "r").read())
	selected_entry = next((entry for entry in customers_json_dic if entry.get("id") == cust_id), None)
	
	if selected_entry:
		username = selected_entry['user']
		password = selected_entry['pass']
		vision_ip = selected_entry['visions'][0]['ip']
		excluded_attacks = selected_entry['exclude']
		dp_ips_string = selected_entry['visions'][0]['dps'] # This is all DefensePro IPs (string)
		dp_ip_to_name_dict = selected_entry['defensepros'] # This is a dictionary of DefensePro IPs and DefensePro names
		bw_units = selected_entry['variables']['bwUnitDaily']

		try:
			policies_list = selected_entry['policiesList']
		except:
			policies_list = [] # This is a list of policies to be used in the report. If empty, all policies will be used.

		try:
			traffic_window_granular = selected_entry['variables']['TrafficWindowGranular']
		except:
			traffic_window_granular = 14400 # this is in seconds (4 hours). This setting controls the period of time blocks for which the traffic volume data is pulled

		try:
			traffic_window_averaged = selected_entry['variables']['TrafficWindowAveraged']
		except:
			traffic_window_averaged = 86400 # this is in seconds (4 hours). This setting controls the period of time blocks for which the traffic volume data is pulled

		try:
			forensics_window = selected_entry['variables']['ForensicsWindow']
		except:
			forensics_window = 3600 # this is in seconds (1 hours). This setting controls the period of time blocks for which the traffic volume data is pulled


		try:
			pre_attack_extra_timestamps = selected_entry['variables']['PreAttackTimestampsToKeep']
		except:
			pre_attack_extra_timestamps = 4  # Number of granular  timestamps(each 15 sec) to keep before the attack and after the attack

		try:
			post_attack_extra_timestamps = selected_entry['variables']['PostAttackTimestampsToKeep']
		except:
			post_attack_extra_timestamps = 20  # Number of granular  timestamps(each 15 sec) to keep before the attack and after the attack. Not recommended to reduce since average timestamp may falsly present extra attack volume in addition to granular.


		try:
			bps_attack_threshold = selected_entry['variables']['BpsAttackThreshold']
		except:
			bps_attack_threshold = 10000  # Attack volume in Kbps to keep granular chart

		try:
			pps_attack_threshold = selected_entry['variables']['PpsAttackThreshold']
		except:
			pps_attack_threshold = 10000  # Attack volume in Kbps to keep granular chart



	else:
		print(f"No data found for ID: {cust_id}")

except json.JSONDecodeError as e:
	print("Error parsing JSON:", e)
except (KeyError, IndexError) as e:
	print("Error extracting data:", e)

#####################################################################################################################

class Vision:

	def __init__(self, vision_ip, username, password):
		self.ip = vision_ip
		self.login_data = {"username": username, "password": password}
		self.base_url = "https://" + vision_ip
		self.sess = Session()
		
		self.sess.headers.update({"Content-Type": "application/json"})

		if not offline: # this is for testing purposes only, remove for production
			print('Connecting to Vision')
			self.login()

			print('Collecting DefensePro device list')		
			self.device_list = self.get_device_list()
		

		# To manipulate the desired date, replace day = 1 with the desired day or month with desired month , e.g self.today_date = datetime.today().replace(month=2) )
		self.today_date = datetime.today().replace(month=cur_month,day=cur_day,year=cur_year)#,tzinfo=timezone.utc)

		print(f'Today date is {self.today_date}')

		self.today_day_number = self.today_date.day

		self.previous_day_number = (self.today_date - timedelta(days=1)).day

		# print(f'Today is {self.today_day_number} and yesterday was {self.previous_day_number}')

		self.today_month_number = self.today_date.month

		if self.today_month_number == 1:
			self.prev_month_number = 12  # Wrap around to December
		else:
			self.prev_month_number = self.today_month_number - 1

		self.today_year = self.today_date.year

		self.start_time_lower, self.end_time_upper = self.generate_report_times(self.today_date)

		self.days_in_prev_month = calendar.monthrange(self.today_year, self.prev_month_number)[1]
		

	def login(self):

		login_url = self.base_url + '/mgmt/system/user/login'
		try:
			r = self.sess.post(url=login_url, json=self.login_data, verify=False)
			r.raise_for_status()
			response = r.json()
		except (requests.exceptions.HTTPError, requests.exceptions.ConnectionError,requests.exceptions.SSLError,requests.exceptions.Timeout,requests.exceptions.ConnectTimeout,requests.exceptions.ReadTimeout) as err:
			raise SystemExit(err)

		if response['status'] == 'ok':
			self.sess.headers.update({"JSESSIONID": response['jsessionid']})
			# print("Auth Cookie is:  " + response['jsessionid'])
		else:
			exit(1)


	def _post(self, URL, requestData = ""):

		max_retries = 3  # Number of retries for 403 errors

		for attempt in range(max_retries):
			try:
				response = self.sess.post(url=URL, verify=False, data=requestData)

				# Check if session expired (403 Forbidden)
				if response.status_code == 403:
					print(f"Attempt {attempt + 1}: Received 403 Forbidden. Refreshing session...")
					self.login()  # Refresh session
					
					# Retry after logging in
					response = self.sess.post(url=URL, verify=False, data=requestData)

				# Raise an exception if the response is an error (except 403 which we handled or 200 OK)
				response.raise_for_status()

				return response  # Return the successful response

			except (requests.exceptions.HTTPError, requests.exceptions.ConnectionError, requests.exceptions.SSLError,
				requests.exceptions.Timeout, requests.exceptions.ConnectTimeout,
				requests.exceptions.ReadTimeout) as err:
				print(f"Request failed: {err}")
				time.sleep(2 ** attempt)  # Exponential backoff before retry

		print("Max retries reached. Request failed.")
		return None  # Return None if all retries fail


	def generate_report_times(self,today_date):
		# Get current time
		
	
		if daily:
			# Daily Report Time Variables
			# Yesterday's start time: 00:00:00
			yesterday_start = (today_date - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
			start_time_lower = int(yesterday_start.timestamp())*1000

			# Yesterday's end time: 23:59:59
			yesterday_end = (today_date - timedelta(days=1)).replace(hour=23, minute=59, second=59, microsecond=0)
			end_time_upper = int(yesterday_end.timestamp())*1000

		if monthly:
			# Monthly Report Time Variables
			# First day of the previous month at 00:00:00


			first_day_of_prev_month = (today_date.replace(day=1) - timedelta(days=1)).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
			start_time_lower = int(first_day_of_prev_month.timestamp())*1000

			# Last day of the previous month at 23:59:59
			last_day_of_prev_month = first_day_of_prev_month.replace(
				day=calendar.monthrange(first_day_of_prev_month.year, first_day_of_prev_month.month)[1],
				hour=23, minute=59, second=59, microsecond=0
			)
			end_time_upper = int(last_day_of_prev_month.timestamp())*1000

		# Return all variables
		return start_time_lower, end_time_upper
			
	def get_device_list(self):
		# Returns list of DP with mgmt IP, type, Name
		devices_url = self.base_url + '/mgmt/system/config/itemlist/alldevices'
		r = self.sess.get(url=devices_url, verify=False)
		json_txt = r.json()

		dev_list = {item['managementIp']: {'Type': item['type'], 'Name': item['name'],
			'Version': item['deviceVersion'], 'ormId': item['ormId']} for item in json_txt if item['type'] == "DefensePro"}
		
		with open(raw_data_path + 'full_dev_list.json', 'w') as full_dev_list_file:
			json.dump(dev_list,full_dev_list_file)

		return dev_list

################Traffic stats Bps######################
	def write_traffic_stats_to_csv(self,traffic_raw_response, filename):
		"""
		Parses the given response and writes the data to a CSV file, ensuring no overlapping timestamps.
		"""
		data = []

		type_traffic_utilization = False
		type_cps = False
		type_cec = False

		first_row = traffic_raw_response["data"][0]["row"]

		if "excluded" in first_row:
			type_traffic_utilization = True

		if "connectionPerSecond" in first_row:
			type_cps = True

		if "connectionsPerSecond" in first_row:
			type_cec = True

		# Extract new data from the JSON response
		for row in traffic_raw_response['data']:
			timestamp = int(row['row']['timeStamp'])
			if type_traffic_utilization:
				data.append({
					'Date': timestamp,
					'trafficValue': row['row']['trafficValue'],
					'discards': row['row']['discards'],
					'challengeIng': row['row']['challengeIng'],
					'excluded': row['row']['excluded']

				})
				
			elif type_cps:
				data.append({
					'Date': timestamp,
					'connectionPerSecond': row['row']['connectionPerSecond']
				})
			elif type_cec:
				data.append({
					'Date': timestamp,
					'connectionsPerSecond': row['row']['connectionsPerSecond']
				})

		# Read existing data from the CSV file
		if os.path.isfile(filename):
			with open(filename, 'r') as csvfile:
				reader = csv.DictReader(csvfile)
				existing_data = [row for row in reader]
		else:
			existing_data = []

		# Filter out rows from existing data that overlap with new data (based on year, month, day)
		existing_dates = {
			datetime.fromtimestamp(int(row['Date']) / 1000).date(): row
			for row in existing_data
		}
		new_dates = {
			datetime.fromtimestamp(item['Date'] / 1000).date(): item
			for item in data
		}

		for new_date in new_dates:
			if new_date in existing_dates:
				existing_data = [row for row in existing_data if datetime.fromtimestamp(int(row['Date']) / 1000).date() != new_date]

		# Append new data to existing data
		updated_data = existing_data + data

		################ Write to CSV #######################

		if daily:
			
			if self.today_day_number != 2:
				print('Daily clause day is not 2nd of the month')

				# Write the updated data back to the CSV file
				with open(filename, 'w', newline='') as csvfile:
					if type_traffic_utilization:
						fieldnames = ['Date', 'trafficValue','discards','challengeIng','excluded']
					elif type_cps:
						fieldnames = ['Date', 'connectionPerSecond']
					elif type_cec:
						fieldnames = ['Date', 'connectionsPerSecond']
						
					writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
					writer.writeheader()
					writer.writerows(updated_data)



			else:
				print('Daily clause day is 2nd of the month')
				# This will overwrite the data in the file
				with open(filename, 'w', newline='') as csvfile:
					if type_traffic_utilization:
						fieldnames = ['Date', 'trafficValue','discards','challengeIng','excluded']
					elif type_cps:
						fieldnames = ['Date', 'connectionPerSecond']
					elif type_cec:
						fieldnames = ['Date', 'connectionsPerSecond']

					writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

					writer.writeheader()
					writer.writerows(data)
					print (f'Created {filename}')

		else: # if monthly
			print('Monthly condition')
			# This will overwrite the data
			with open(filename, 'w', newline='') as csvfile:
				if type_traffic_utilization:
					fieldnames = ['Date', 'trafficValue','discards','challengeIng','excluded']
				elif type_cps:
					fieldnames = ['Date', 'connectionPerSecond']
				elif type_cec:
					fieldnames = ['Date', 'connectionsPerSecond']
				writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
				writer.writeheader()
				writer.writerows(data)
				print (f'Created {filename}')

	def extract_attack_data_only(self, data, attack_threshold, pre_attack_extra_timestamps,post_attack_extra_timestamps):
		attack_timestamps = set()
		
		for ip, details in data.items():
			timestamps = [int(entry["row"]["timeStamp"]) for entry in details["data"]]
			
			for i, entry in enumerate(details["data"]):
				row = entry["row"]
				if float(row["discards"]) > attack_threshold:
					attack_timestamps.add(timestamps[i])
					
					# Add Y timestamps before
					attack_timestamps.update(timestamps[max(0, i - pre_attack_extra_timestamps):i])
					
					# Add ExTY timestamps after
					attack_timestamps.update(timestamps[i + 1: min(len(timestamps), i + 1 + post_attack_extra_timestamps)])
		
		return sorted(attack_timestamps)  # Return sorted list of unique timestamps


	def merge_attacks_to_aggregate(self, traffic_bps_per_device_aggregate, traffic_bps_per_device_granular, attack_only_timestamps): 
		"""
		This function merges granular under attack timestamps into aggregate averaged dictionary.
		This way we will have averaged aggregate data, but during attacks we will have it granular.
		"""
		merged_data = traffic_bps_per_device_aggregate.copy()
		
		for ip, details in traffic_bps_per_device_granular.items():
			if ip not in merged_data:
				merged_data[ip] = {"data": []}
			
			existing_entries = {int(entry["row"]["timeStamp"]): entry for entry in merged_data[ip]["data"]}
			
			for entry in details["data"]:
				timestamp = int(entry["row"]["timeStamp"])
				if timestamp in attack_only_timestamps:
					existing_entries[timestamp] = entry  # Replace if exists or add new
			
			# Sort merged data by timestamp
			merged_data[ip]["data"] = sorted(existing_entries.values(), key=lambda entry: int(entry["row"]["timeStamp"]))
		
		return merged_data

################Combined Traffic stats ######################
	def write_per_device_combined_traffic_stats_to_csv(self,traffic_raw_response, filename):
		"""
		Parses the given response and writes the data to a CSV file, ensuring no overlapping timestamps.
		"""
		dps_list = dp_ips_string.split(',')
		dps_names = [dp_ip_to_name_dict.get(dp, dp) for dp in dps_list]

		header_names = ["Timestamp"] + sorted(dps_names)  # Start with timestamp
		header_ips = ["Timestamp"] + sorted(dps_list)  # Start with timestamp
		
		collected_data_dict = {}  # Dictionary to store per device aggregated data by timestamp


		for ip in dps_list:
			for entry in traffic_raw_response[ip]['data']:

				row = entry['row']  # Extract 'row' dictionary
				timestamp = row['timeStamp']
				if filename == tmp_files_path + 'traffic_per_device_bps.csv':
					row_value = round(float(row['trafficValue']) / 1000, 2)

				if filename == tmp_files_path + 'attacks_per_device_bps.csv':
					row_value = round(float(row['discards']) / 1000, 2)

				if filename == tmp_files_path + 'excluded_per_device_bps.csv':
					row_value = round(float(row['excluded']) / 1000, 2)

				if filename == tmp_files_path + 'traffic_per_device_pps.csv':
					row_value = round(float(row['trafficValue']) ,2)

				if filename == tmp_files_path + 'attacks_per_device_pps.csv':
					row_value = round(float(row['discards']) , 2)

				if filename == tmp_files_path + 'excluded_per_device_pps.csv':
					row_value = round(float(row['excluded']) ,2)

				if filename == tmp_files_path + 'cps_per_device.csv':
					row_value = float(row['connectionPerSecond'])  # Convert to number

				if filename == tmp_files_path + 'cec_per_device.csv':
					row_value = float(row['connectionsPerSecond'])  # Convert to number

				# Store stats in time_series dictionary
				if timestamp not in collected_data_dict:
					collected_data_dict[timestamp] = {}

				collected_data_dict[timestamp][ip] = row_value


		# Read existing CSV, if it exists to prevent duplicating when appending new data
		existing_data_dict = {}
		if os.path.exists(filename):
			with open(filename, "r") as csv_file:
				reader = csv.reader(csv_file)
				existing_headers = next(reader)  # Read headers
				for row in reader:
					timestamp = row[0]
					existing_data_dict[timestamp] = {existing_headers[i]: float(row[i]) for i in range(1, len(row)) if row[i]}  # Convert values to float


		# Merge new data, replacing overlapping timestamps.
		for timestamp, ip_data in collected_data_dict.items():
			existing_data_dict[timestamp] = ip_data  # Replace or add new data

		# Translating new merged DP IP data to DP Name. (At this stage previous data has DP names, new data has DP IP's. )
		existing_data_dict = {
			timestamp: {dp_ip_to_name_dict.get(key, key): value for key, value in sub_dict.items()}
			for timestamp, sub_dict in existing_data_dict.items()
		}


		# Write the updated data back to the CSV file
		if (daily and self.today_day_number == 2) or monthly:
				print('Creating new file, overwriting previous data')
				# Final data will be only the new data, existing csv will be overwritten with new data only

				final_data = [header_ips]  # Start with headers
				for timestamp in sorted(collected_data_dict.keys()):
					row = [timestamp] + [collected_data_dict[timestamp].get(ip, "") for ip in header_ips[1:]]  # Preserve order
					final_data.append(row)
				
				final_data[0] = [dp_ip_to_name_dict.get(ip, ip) for ip in final_data[0]]  # Replace DP IP with DP name

				# Remove rows if any of the devices does not have corresponding row timestampe (IRP communication issues or CC processing issue)
				loss_rate = 0
				for row in final_data:
					if '' in row:
						print(f"Removing row with empty values: {row} , {time.strftime('%d-%b-%Y %H:%M:%S', time.localtime(int(row[0])/1000))}")
						loss_rate += 1
						final_data.remove(row)
				print(f"Removed {loss_rate} rows with empty values for all devices.")

				# Overwrite the existing csv with new collected data only
				with open(filename, "w", newline="") as csv_file:
					writer = csv.writer(csv_file)
					writer.writerows(final_data)

				print(f"CSV file '{filename}' has been updated successfully.")

		else:
			print('Daily report - today is not the 2nd day of the month - merging new data with existing data in the csv')

			# Final data will be the existing data + newly collected data
			final_data = [header_names]  # Start with headers
			for timestamp in sorted(existing_data_dict.keys()):
				row = [timestamp] + [existing_data_dict[timestamp].get(dp_name, "") for dp_name in header_names[1:]]
				final_data.append(row)
			
			# Remove rows with empty values for all devices (IRP communication issues or CC processing issue)
			loss_rate = 0
			for row in final_data:
				if '' in row:
					print(f"Removing row with empty values: {row} , {time.strftime('%d-%b-%Y %H:%M:%S', time.localtime(int(row[0])/1000))}")
					loss_rate += 1
					final_data.remove(row)
			print(f"Removed {loss_rate} rows with empty values for all devices.")

			# Merging existing csv data with new collected data only
			with open(filename, "w", newline="") as csv_file:
				writer = csv.writer(csv_file)
				writer.writerows(final_data)

			print(f"CSV file '{filename}' has been updated successfully.")



	def write_traffic_stats_to_db(self,traffic_raw_response, report_type):
		"""
		This function parses the traffic data and saves the data to a SQLite database.
		"""

		# Build list of per-IP DataFrames
		all_dps_df_list = [] # This will hold DataFrames for each DP
		dp_names_list = [] # List of DP names for the report

		for dp_ip, dp_ip_traffic_stats in traffic_raw_response.items():
			
			dp_name = dp_ip_to_name_dict.get(dp_ip, dp_ip)
			dp_names_list.append(dp_name)


			rows = []
			for entry in dp_ip_traffic_stats['data']:
				row = entry['row']
				if report_type == "Traffic Volume BPS":

					db_table_name = 'traffic_bps'

					#Convert traffic volume values from string to float and set units to Mbps
					row['trafficValue'] = round(float(row['trafficValue']) / 1000, 2)
					row['discards'] = round(float(row['discards']) / 1000, 2)

					

					rows.append({
					'Timestamp': row['timeStamp'],
					f'Traffic {dp_name}': float(row['trafficValue']) - float(row['discards']),
					f'Attacks {dp_name}': float(row['discards'])
					})
					
				elif report_type == "Traffic Volume PPS":

					db_table_name = 'traffic_pps'

					#Convert traffic volume values from string to float
					row['trafficValue'] = round(float(row['trafficValue']) ,2)
					row['discards'] = round(float(row['discards']) , 2)

					rows.append({
					'Timestamp': row['timeStamp'],
					f'Traffic {dp_name}': float(row['trafficValue']) - float(row['discards']),
					f'Attacks {dp_name}': float(row['discards'])
					})


				if report_type == "Traffic Volume BPS Excluded":

					db_table_name = 'traffic_bps_excluded'

					#Convert traffic volume values from string to float and set units to Mbps

					row['excluded'] = round(float(row['excluded']) / 1000, 2)
					
					rows.append({
					'Timestamp': row['timeStamp'],
					f'{dp_name}': float(row['excluded']),
					})
					
				if report_type == "Traffic Volume PPS Excluded":

					db_table_name = 'traffic_pps_excluded'

					#Convert traffic volume values from string to float and set units to Mbps

					row['excluded'] = round(float(row['excluded']) ,2)
					
					rows.append({
					'Timestamp': row['timeStamp'],
					f'{dp_name}': float(row['excluded']),
					})

				elif report_type == "Traffic CPS":

					db_table_name = 'traffic_cps'

					#Convert traffic volume values from string to float
					row['connectionPerSecond'] = float(row['connectionPerSecond'])  # Convert to number

					rows.append({
					'Timestamp': row['timeStamp'],
					f'{dp_name}': float(row['connectionPerSecond']),
					})

				elif report_type == "Traffic CEC":

					db_table_name = 'traffic_cec'

					#Convert traffic volume values from string to float
					row['connectionsPerSecond'] = float(row['connectionsPerSecond'])  # Convert to number

					rows.append({
					'Timestamp': row['timeStamp'],
					f'{dp_name}': float(row['connectionsPerSecond']),
					})


			df_single_dp = pd.DataFrame(rows)
			if not df_single_dp.empty:
				all_dps_df_list.append(df_single_dp)
			
		# Merge all DP DataFrames on 'timestamp'
		df_final = all_dps_df_list[0]
		for df in all_dps_df_list[1:]:
			df_final = pd.merge(df_final, df, on='Timestamp', how='outer')

		# Sort timestamps by timestamp
		df_final = df_final.sort_values(by='Timestamp')
		df_final['DateTime'] = pd.to_datetime(df_final['Timestamp'].astype('int64'), unit='ms').dt.strftime('%Y-%m-%d %H:%M:%S')

		# Rearrange columns: timestamp, all traffic_<ip>, all attacks_<ip>
		if report_type == "Traffic Volume BPS" or report_type == "Traffic Volume PPS":
			traffic_cols = [f'Traffic {dp_name}' for dp_name in dp_names_list]
			attack_cols = [f'Attacks {dp_name}' for dp_name in dp_names_list]
			ordered_cols = ['Timestamp'] + ['DateTime'] + traffic_cols + attack_cols
			df_final = df_final[ordered_cols]
		
		# Drop rows with NaN values in 'Timestamp' or 'DateTime' - some data points maybe missing for some DPs due to IRP communication issues, CC processing issue etc.
		df_final = df_final.dropna().reset_index(drop=True)


		if daily:
			# Save to SQLite
			if self.today_day_number == 1 and self.today_month_number != 1: # This is a case for 1st of the month but not Jan 1st
				db_file = db_files_path + f'database_{cust_id}_{self.today_month_number -1:02}_{self.today_year}.sqlite'
				print(db_file)

			elif self.today_day_number == 1 and self.today_month_number == 1: # This is a case for  Jan 1st
				db_file = db_files_path + f'database_{cust_id}_{12}_{self.today_year -1:02}.sqlite'
				print(db_file)

			else:
				db_file = db_files_path + f'database_{cust_id}_{self.today_month_number:02}_{self.today_year}.sqlite'
				print(db_file)

		elif monthly:

			if self.today_month_number != 1: # This is a case for not Jan month
				db_file = db_files_path + f'database_{cust_id}_{self.today_month_number -1:02}_{self.today_year}.sqlite'
				print(db_file)

			else: # This is a case for  Jan month
				db_file = db_files_path + f'database_{cust_id}_{12}_{self.today_year -1}.sqlite'
				print(db_file)


		conn = sqlite3.connect(db_file)
		cursor = conn.cursor()

		# Create table if it doesn't exist
		create_cols = ", ".join([f'"{col}" REAL' for col in df_final.columns if col not in ['Timestamp', 'DateTime']])
		cursor.execute(f'''
			CREATE TABLE IF NOT EXISTS {db_table_name} (
				Timestamp TEXT,
				DateTime TEXT,
				{create_cols}
			)
		''')

		# delete all epoch timestamps entries for the previous day and append new data
		

		end_time_inclusive = ((self.end_time_upper // 1000) + 1) * 1000

		cursor.execute(f'''
			DELETE FROM {db_table_name}
			WHERE CAST(Timestamp AS INTEGER) >= ? AND CAST(Timestamp AS INTEGER) <= ?
		''', (self.start_time_lower, end_time_inclusive))

		
		# Insert new data
		df_final.to_sql(db_table_name, conn, if_exists='append', index=False)

		conn.commit()
		conn.close()


	def ams_stats_dashboards_call(self, units="bps", uri = "/mgmt/vrm/monitoring/traffic/periodic/report", report_type="AMS Dasboard"):

		api_url = f'https://{self.ip}' + uri
		data = {
			"direction": "Inbound",
			"timeInterval": {
				"from": v.start_time_lower,
				"to": v.end_time_upper
			},

		}
		if units and units != "cps" and units != "cec":
			data.update({"unit": units})
		response = self._post(api_url, json.dumps(data))
		if response.status_code == 200:
			print(
				f"Pulled {report_type} data. Time range: "
				f"{time.strftime('%d-%b-%Y %H:%M:%S', time.localtime(v.start_time_lower/1000))} - "
				f"{time.strftime('%d-%b-%Y %H:%M:%S', time.localtime(v.end_time_upper/1000))}"
			)
			
			try:
				response_json = response.json()

				# If Null in rows, filter out these rows

				filtered_response_json = {
					"metaData": response_json["metaData"],
					"data": [
						row for row in response_json["data"] 
						if not any(value is None for value in row["row"].values())
					],
					"dataMap": response_json["dataMap"]
				}

				with open(raw_data_path + f"traffic_{units}_raw.json", "w", encoding="utf-8") as json_file:
					json.dump(filtered_response_json, json_file, indent=4)  # Save JSON with indentation
				print(f"Response body saved as pretty JSON in traffic_{units}_raw.json")
				return filtered_response_json

			except json.JSONDecodeError:
				print("Response is not in JSON format, skipping JSON file save.")

			return response.json()
		
		else:
			error_message = (
				f"Error pulling attack rate data. Time range: "
				f"{time.strftime('%d-%b-%Y %H:%M:%S', time.localtime(v.start_time_lower/1000))} - "
				f"{time.strftime('%d-%b-%Y %H:%M:%S', time.localtime(v.end_time_upper/1000))}"
			)
			print(error_message)
			raise Exception(error_message)
		
	def ams_stats_dashboards_per_device_call(self, units="bps", uri = "/mgmt/vrm/monitoring/traffic/periodic/report", report_type="AMS Dasboard"):

		api_url = f'https://{self.ip}' + uri

		data = {
			"direction": "Inbound",
			"timeInterval": {
				"from": v.start_time_lower,
				"to": v.end_time_upper
			},

		}

		if units and units != "cps" and units != "cec":
			data.update({"unit": units})

		combined_response_json = {}

		if dp_ips_string:
			dps_list = dp_ips_string.split(',')
			for dp in dps_list:
				
				data.update({"selectedDevices":  [
					{
						"deviceId": dp,
						"networkPolicies": [],
						"ports": []
					}
					]
				})
	



				response = self._post(api_url, json.dumps(data))

				if response.status_code == 200:
					try:
						response_json = response.json()

						# If Null in rows, filter out these rows

						filtered_response_json = {
							"metaData": response_json["metaData"],
							"data": [
								row for row in response_json["data"] 
								if not any(value is None for value in row["row"].values())
							],
							"dataMap": response_json["dataMap"]
						}

						combined_response_json[dp] = filtered_response_json

						print(
						f"Pulled {report_type} data for {dp} DefensePro. Time range: "
						f"{time.strftime('%d-%b-%Y %H:%M:%S', time.localtime(v.start_time_lower/1000))} - "
						f"{time.strftime('%d-%b-%Y %H:%M:%S', time.localtime(v.end_time_upper/1000))}"
						)





					except json.JSONDecodeError:
						print("Response is not in JSON format, skipping JSON file save.")

					# return response.json()
				
				else:
					error_message = (
						f"Error pulling attack rate data. Time range: "
						f"{time.strftime('%d-%b-%Y %H:%M:%S', time.localtime(v.start_time_lower/1000))} - "
						f"{time.strftime('%d-%b-%Y %H:%M:%S', time.localtime(v.end_time_upper/1000))}"
					)
					print(error_message)
					raise Exception(error_message)


		with open(raw_data_path + f"traffic_per_device_{units}_raw.json", "w", encoding="utf-8") as json_file:
			json.dump(combined_response_json, json_file, indent=4)  # Save JSON with indentation
		print(f"Response body saved as pretty JSON in traffic_{units}_raw.json")

		return combined_response_json
	
	def ams_stats_dashboards_per_device_window_calls(self, start_time_lower, end_time_upper, traffic_window, units, uri = "/mgmt/vrm/monitoring/traffic/periodic/report", report_type="AMS Dasboard"):

		initial_start_time_lower = start_time_lower

		api_url = f'https://{self.ip}' + uri

		query = {
			"direction": "Inbound",
			"timeInterval": {
				"from": start_time_lower,
				"to": end_time_upper
			},

		}

		if units == "bps" or units=="pps":
			query.update({"unit": units})

		combined_response_json = {}

		if dp_ips_string:
			dps_list = dp_ips_string.split(',')
			for dp in dps_list:
				
				query.update({"selectedDevices":  [
					{
						"deviceId": dp,
						"networkPolicies": policies_list,
						"ports": []
					}
					]
				})


				while start_time_lower < end_time_upper:
					d1 = start_time_lower # This is the start time of the window
					d2 = start_time_lower + (traffic_window *1000) # This is the end time of the window
					# print(d1,d2)
					# print(datetime.fromtimestamp(d1/1000, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S'))
					# print(datetime.fromtimestamp(d2/1000, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S'))


					query.update({"timeInterval": {
						"from": d1,
						"to": d2
					},
					})

					response = self._post(api_url, json.dumps(query))

					if response.status_code == 200:
						try:
							response_json = response.json()

							filtered_data = []

							# If Null in rows, filter out these rows

							for row in response_json["data"]:
								if any(value is None for value in row["row"].values()):
									print(f"Skipping row due to None values: {row}")
								else:
									filtered_data.append(row)

							# Construct filtered response JSON
							filtered_response_json = {
								"metaData": response_json["metaData"],
								"data": filtered_data,
								"dataMap": response_json["dataMap"]
							}


							# Ensure dp exists in combined_response_json
							if dp not in combined_response_json:
								combined_response_json[dp] = {"data": [], "dataMap": {}}  # Initialize if missing


							combined_response_json[dp]["data"].extend(filtered_response_json["data"])
							# Update maxValue logic
							current_max_value = float(combined_response_json[dp].get("dataMap", {}).get("maxValue", {}).get("trafficValue", 0))
							
							try:
								new_max_value = float(filtered_response_json["dataMap"]["maxValue"]["trafficValue"])

								if new_max_value > current_max_value:
									combined_response_json[dp]["dataMap"]["maxValue"] = filtered_response_json["dataMap"]["maxValue"]
									# print(f"New max value found: {new_max_value}")
							except:
								pass


							print(
							f"Pulled {report_type} data for {dp} DefensePro. Time range:"
							f"{time.strftime('%d-%b-%Y %H:%M:%S', time.localtime(d1/1000))} - "
							f"{time.strftime('%d-%b-%Y %H:%M:%S', time.localtime(d2/1000))}"
							)

							start_time_lower += (traffic_window *1000)



						except json.JSONDecodeError:
							print("Response is not in JSON format, skipping JSON file save.")

						# return response.json()
					
					else:
						error_message = (
							f"Error pulling attack rate data. Time range: "
							f"{time.strftime('%d-%b-%Y %H:%M:%S', time.localtime(v.start_time_lower/1000))} - "
							f"{time.strftime('%d-%b-%Y %H:%M:%S', time.localtime(v.end_time_upper/1000))}"
						)
						print(error_message)
						raise Exception(error_message)


				# Reset start time for next DP
				start_time_lower = initial_start_time_lower

		if report_type == "Traffic Volume BPS Granular" or report_type == "Traffic Volume PPS Granular":

			with open(raw_data_path + f"traffic_per_device_{units}_raw_granular.json", "w", encoding="utf-8") as json_file:
				json.dump(combined_response_json, json_file, indent=4)  # Save JSON with indentation
			print(f"Response body saved as pretty JSON in traffic_{units}_raw_granular.json")

		if report_type == "Traffic Volume BPS Aggregate" or report_type == "Traffic Volume PPS Aggregate":

			with open(raw_data_path + f"traffic_per_device_{units}_raw_aggregate.json", "w", encoding="utf-8") as json_file:
				json.dump(combined_response_json, json_file, indent=4)  # Save JSON with indentation
			print(f"Response body saved as pretty JSON in traffic_{units}_raw_aggregate.json")

		if report_type == "CPS Granular":
			with open(raw_data_path + f"cps_per_device_raw_granular.json", "w", encoding="utf-8") as json_file:
				json.dump(combined_response_json, json_file, indent=4)  # Save JSON with indentation
			print(f"Response body saved as pretty JSON in cps_per_device_raw_granular.json")			

		if report_type == "CPS Aggregate":
			with open(raw_data_path + f"cps_per_device_raw_aggregate.json", "w", encoding="utf-8") as json_file:
				json.dump(combined_response_json, json_file, indent=4)  # Save JSON with indentation
			print(f"Response body saved as pretty JSON in cps_per_device_raw_aggregate.json")


		if report_type == "Concurrent Connections Granular":
			with open(raw_data_path + f"cec_per_device_raw_granular.json", "w", encoding="utf-8") as json_file:
				json.dump(combined_response_json, json_file, indent=4)  # Save JSON with indentation
			print(f"Response body saved as pretty JSON in cec_per_device_raw_granular.json")			

		if report_type == "Concurrent Connections Aggregate":
			with open(raw_data_path + f"cec_per_device_raw_aggregate.json", "w", encoding="utf-8") as json_file:
				json.dump(combined_response_json, json_file, indent=4)  # Save JSON with indentation
			print(f"Response body saved as pretty JSON in cec_per_device_raw_aggregate.json")

		return combined_response_json

	def get_cps(self):

		api_url = f'https://{self.ip}/mgmt/vrm/monitoring/traffic/cps'
		data = {
			"direction": "Inbound",
			"timeInterval": {
				"from": v.start_time_lower,
				"to": v.end_time_upper
			},

		}
		
		response = self._post(api_url, json.dumps(data))
		if response.status_code == 200:
			print(
				f"Pulled CPS stats. Time range: "
				f"{time.strftime('%d-%b-%Y %H:%M:%S', time.localtime(v.start_time_lower/1000))} - "
				f"{time.strftime('%d-%b-%Y %H:%M:%S', time.localtime(v.end_time_upper/1000))}"
			)
			
			try:
				response_json = response.json()
				with open(raw_data_path + "traffic_cps_raw.json", "w", encoding="utf-8") as json_file:
					json.dump(response_json, json_file, indent=4)  # Save JSON with indentation
				print("Response body saved as pretty JSON in traffic_bps_raw.json")

			except json.JSONDecodeError:
				print("Response is not in JSON format, skipping JSON file save.")

			return response.json()
		
		else:
			error_message = (
				f"Error pulling CPS stats data. Time range: "
				f"{time.strftime('%d-%b-%Y %H:%M:%S', time.localtime(v.start_time_lower/1000))} - "
				f"{time.strftime('%d-%b-%Y %H:%M:%S', time.localtime(v.end_time_upper/1000))}"
			)
			print(error_message)
			raise Exception(error_message)
		

	def create_forensics_post_payload(self,start_time_lower,end_time_upper):

		query = {
			"criteria": [],
			"pagination": {
				"page": 0,
				"size": 10000,
				"topHits": 10000
			}
		}


		# Create an "and" filter
		and_filters = {
			"type": "andFilter",
			"filters": []
		}

		# Date range filter
		time_filter = {
			"type": "timeFilter",
			"field": "endTime",
			"lower": f"{start_time_lower}",
			"upper": f"{end_time_upper}",
			"includeLower": True,
			"includeUpper": True
		}
		and_filters['filters'].append(time_filter)

		query['criteria'].append(and_filters)

		if excluded_attacks:
			exclude_array = excluded_attacks.split(',')
			for text in exclude_array:
				field, value = text.split(':')
				and_filters['filters'].append({
					"type": "termFilter",
					"field": field,
					"value": value,
					"inverseFilter": True
				})


		# Create an "or" filter for DefensePro IPs
		or_filters = {
			"type": "orFilter",
			"filters": []
		}

		if dp_ips_string:
			dps_list = dp_ips_string.split(',')
			for dp in dps_list:
				and_filter = {
					"type": "andFilter",
					"inverseFilter": False,
					"filters": [
						{
							"type": "termFilter",
							"inverseFilter": False,
							"field": "deviceIp",
							"value": dp
						},
						{
							"type": "orFilter",
							"inverseFilter": False,
							"filters": [
								{
									"type": "termFilter",
									"inverseFilter": False,
									"field": "ruleName",
									"value": policy
								} for policy in policies_list
							]
						}
					]
				}
				or_filters["filters"].append(and_filter)

				
		else:
			or_filters['filters'].append({
				"type": "termFilter",
				"field": "deviceIp",
				"value": "0.0.0.0",
				"inverseFilter": True
			})

		# Add "or" filters to query criteria
		query['criteria'].append(or_filters)
		return query

	def get_forensics(self,start_time_lower,end_time_upper,days_in_prev_month):

		print(
		f"Pulling forensics data. Time range: "
		f"{time.strftime('%d-%b-%Y %H:%M:%S', time.localtime(start_time_lower/1000))} - "
		f"{time.strftime('%d-%b-%Y %H:%M:%S', time.localtime(end_time_upper/1000))}"
			)
		
		################# Progress bar ############################
		if monthly:
			total_calls = days_in_prev_month * 24
		if daily:
			total_calls = 24
		bar_length = 50  # Length of the progress bar
		completed_calls = 0  # Track successful API calls
		###########################################################

		api_url = f'https://{self.ip}/mgmt/monitor/reporter/reports-ext/ATTACK'


		
		all_data = []
		metaData = None  # To store metaData from the first response
	

		while start_time_lower < end_time_upper:
			d1 = start_time_lower # This is the start time of the window
			d2 = start_time_lower + (forensics_window *1000) # This is the end time of the window
			# print(d1,d2)
			# print(datetime.fromtimestamp(d1/1000, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S'))
			# print(datetime.fromtimestamp(d2/1000, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S'))
		  
			post_payload = self.create_forensics_post_payload(d1,d2)

			response = self._post(api_url, json.dumps(post_payload))


			if response.status_code == 200:

				try:
					response_json = response.json()
					if "data" in response_json:
						all_data.extend(response_json["data"])  # Append the current page's data
						if not metaData:
							metaData = response_json.get("metaData", {})  # Get metaData only once

						# print("-", end="", flush=True)  # Print a dash for each call

						# Progress bar
						completed_calls += 1
						percent = (completed_calls / total_calls) * 100
						filled_length = int(bar_length * completed_calls // total_calls)
						bar = "=" * filled_length + "-" * (bar_length - filled_length)
						sys.stdout.write(f"\r[{bar}] {percent:.2f}%")
						sys.stdout.flush()
	
						start_time_lower += (forensics_window *1000)


					else:
						print(f"No data in the response")
						break

				except json.JSONDecodeError:
					print("Response is not in JSON format, skipping JSON file save.")

			
			else:
				error_message = (
					f"Error pulling forensics data. Time range: "
					f"{time.strftime('%d-%b-%Y %H:%M:%S', time.localtime(v.start_time_lower/1000))} - "
					f"{time.strftime('%d-%b-%Y %H:%M:%S', time.localtime(v.end_time_upper/1000))}"
				)
				print(error_message)
				raise Exception(error_message)

		final_response = {
			"data": all_data,
			"metaData": metaData
		}
	
		with open(raw_data_path + "forensics_raw.json", "w", encoding="utf-8") as json_file:
			json.dump(final_response, json_file, indent=4)  # Save JSON with indentation
		print("\n\nResponse body saved as pretty JSON in forensics_raw.json")
		return final_response
	
	def compile_to_sqldb(self):
		

		
		if daily:

			if self.today_day_number == 1 and self.today_month_number != 1: # This is a case for not Jan 1st
				db_file = db_files_path + f'database_{cust_id}_{self.today_month_number -1:02}_{self.today_year}.sqlite'
				print(db_file)


			elif self.today_day_number == 1 and self.today_month_number == 1: # This is a case for  Jan 1st
				db_file = db_files_path + f'database_{cust_id}_{12}_{self.today_year -1:02}.sqlite'
				print(db_file)

			else:
				db_file = db_files_path + f'database_{cust_id}_{self.today_month_number:02}_{self.today_year}.sqlite'
				print(db_file)
			
			
					
			# Connect to SQLite database (it will be created if it doesn't exist)
			conn = sqlite3.connect(db_file)
			cursor = conn.cursor()
			# Create table
			cursor.execute('''
				CREATE TABLE IF NOT EXISTS attacks (
					deviceName TEXT NOT NULL,
					startDate DATE NOT NULL,
					endDate DATE NOT NULL,
					name TEXT NOT NULL,
					actionType TEXT NOT NULL,
					ruleName TEXT NOT NULL,
					sourceAddress TEXT NOT NULL,
					destAddress TEXT NOT NULL,
					sourcePort TEXT NOT NULL,
					destPort TEXT NOT NULL,
					protocol TEXT NOT NULL,
					threatGroup TEXT NOT NULL,
					category TEXT NOT NULL,
					attackIpsId TEXT NOT NULL,
					duration INTEGER NOT NULL,
					risk TEXT NOT NULL,
					startTime INTEGER NOT NULL,
					endTime INTEGER NOT NULL,
					month INTEGER NOT NULL,
					year INTEGER NOT NULL,
					startDayOfMonth INTEGER NOT NULL,
					endDayOfMonth INTEGER NOT NULL,
					vlanTag TEXT NOT NULL,
					packetCount INTEGER NOT NULL,
					packetBandwidth INTEGER NOT NULL,
					averageAttackPacketRatePps INTEGER NOT NULL,
					averageAttackRateBps INTEGER NOT NULL,
					maxAttackRateBps INTEGER NOT NULL,
					maxAttackPacketRatePps INTEGER NOT NULL,
					lastPeriodBandwidth INTEGER NOT NULL,
					poId TEXT NOT NULL,
					radwareId TEXT NOT NULL,
					direction TEXT NOT NULL,
					geoLocation TEXT NOT NULL,
					activationId TEXT NOT NULL,
					packetType TEXT NOT NULL,
					physicalPort TEXT NOT NULL,
					lastPeriodPacketRate INTEGER NOT NULL,
				  	originalStartDate DATE NOT NULL)
				''')
			
			if self.today_day_number == 1 and self.today_month_number == 1: # This is a case for  Jan 1st
				# Clear the table content for the previous day
				cursor.execute('DELETE FROM attacks where month = ? and startDayOfMonth = ?', (12, 31))
			
			elif self.today_day_number == 1 and self.today_month_number != 1: # This is a case for 1st of the month, but not January month
				# Clear the table content for the previous day
				cursor.execute('DELETE FROM attacks where month = ? and startDayOfMonth = ?', (self.today_month_number -1, self.previous_day_number ))
			else:
				# Clear the table content for the previous day
				cursor.execute('DELETE FROM attacks where month = ? and startDayOfMonth = ?', (self.today_month_number, self.previous_day_number))


			# Insert data into the table
			for entry in forensics_raw['data']:

				# Check if duration exists before trying to insert
				if 'duration' not in entry['row']:
					print(f"Skipping record - missing 'duration' field. Device: {entry['row'].get('deviceIp', 'unknown')}, Attack name: {entry['row'].get('name', 'unknown')}")
					continue

				start_date = datetime.fromtimestamp(int(entry["row"]["startTime"])/ 1000)
				orig_start_date = start_date
				end_date = datetime.fromtimestamp(int(entry["row"]["endTime"])/ 1000)
				
				if self.today_day_number == 2:
					if start_date.day == (self.today_date - timedelta(days=2)).day: # This is a case when the attack started in the day before yesterday day and continued to yesterday
						print(f'Attack started in the day before yesterday ({start_date}) day and continued to yesterday')
						
						if self.today_month_number !=1 : # This is a case for 2nd of the month, but not January month
							start_date = start_date.replace(day= 1, hour=0, minute=0, second=0)
							# print(f'New start date: {start_date}')
						else: # This is a case for 2nd of January
							start_date = start_date.replace(day= 1, month=1,year=self.today_year, hour=0, minute=0, second=0)
							# print(f'New start date: {start_date}')
					



				cursor.execute('''
				INSERT INTO attacks (deviceName, startDate, endDate, name, actionType, ruleName, sourceAddress, destAddress, sourcePort, destPort, protocol, threatGroup, category, attackIpsId, duration, risk, startTime, endTime, month, year, startDayOfMonth, endDayOfMonth, vlanTag, packetCount, packetBandwidth, averageAttackPacketRatePps, averageAttackRateBps, maxAttackRateBps, maxAttackPacketRatePps, lastPeriodBandwidth, poId, radwareId, direction, geoLocation, activationId, packetType, physicalPort, lastPeriodPacketRate, originalStartDate)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				''', (
					entry["row"]["deviceIp"], 
					start_date.strftime('%Y-%m-%d %H:%M:%S'), 
					end_date.strftime('%Y-%m-%d %H:%M:%S'), 
					entry["row"]["name"], 
					entry["row"]["actionType"], 
					entry["row"]["ruleName"], 
					entry["row"]["sourceAddress"], 
					entry["row"]["destAddress"], 
					entry["row"]["sourcePort"], 
					entry["row"]["destPort"], 
					entry["row"]["protocol"], 
					entry["row"]["threatGroup"], 
					entry["row"]["category"], 
					entry["row"]["attackIpsId"], 
					entry["row"]["duration"], 
					entry["row"]["risk"], 
					entry["row"]["startTime"], 
					entry["row"]["endTime"], 
					end_date.month,
					end_date.year,
					start_date.day, 
					end_date.day, 
					entry["row"]["vlanTag"], 
					entry["row"]["packetCount"], 
					entry["row"]["packetBandwidth"], 
					entry["row"]["averageAttackPacketRatePps"], 
					entry["row"]["averageAttackRateBps"], 
					entry["row"]["maxAttackRateBps"], 
					entry["row"]["maxAttackPacketRatePps"], 
					entry["row"]["lastPeriodBandwidth"], 
					entry["row"]["poId"], 
					entry["row"]["radwareId"], 
					entry["row"]["direction"], 
					json.loads(entry["row"]["enrichmentContainer"]).get("geoLocation", {}).get("countryCode", None), 
					entry["row"]["activationId"], 
					entry["row"]["packetType"], 
					entry["row"]["physicalPort"], 
					entry["row"]["lastPeriodPacketRate"],
					orig_start_date.strftime('%Y-%m-%d %H:%M:%S')
					))
			# Commit changes and close the connection
			conn.commit()
			conn.close()

		if monthly:
			if self.today_month_number != 1: # This is a case for not Jan month
				db_file = db_files_path + f'database_{cust_id}_{self.today_month_number -1:02}_{self.today_year}.sqlite'
				print(db_file)


			else: # This is a case for  Jan month
				db_file = db_files_path + f'database_{cust_id}_{12}_{self.today_year -1}.sqlite'
				print(db_file)

					
			# Connect to SQLite database (it will be created if it doesn't exist)
			conn = sqlite3.connect(db_file)
			cursor = conn.cursor()
			# Create table
			cursor.execute('''
				CREATE TABLE IF NOT EXISTS attacks (
					deviceName TEXT NOT NULL,
					startDate DATE NOT NULL,
					endDate DATE NOT NULL,
					name TEXT NOT NULL,
					actionType TEXT NOT NULL,
					ruleName TEXT NOT NULL,
					sourceAddress TEXT NOT NULL,
					destAddress TEXT NOT NULL,
					sourcePort TEXT NOT NULL,
					destPort TEXT NOT NULL,
					protocol TEXT NOT NULL,
					threatGroup TEXT NOT NULL,
					category TEXT NOT NULL,
					attackIpsId TEXT NOT NULL,
					duration INTEGER NOT NULL,
					risk TEXT NOT NULL,
					startTime INTEGER NOT NULL,
					endTime INTEGER NOT NULL,
					month INTEGER NOT NULL,
					year INTEGER NOT NULL,
					startDayOfMonth INTEGER NOT NULL,
					endDayOfMonth INTEGER NOT NULL,
					vlanTag TEXT NOT NULL,
					packetCount INTEGER NOT NULL,
					packetBandwidth INTEGER NOT NULL,
					averageAttackPacketRatePps INTEGER NOT NULL,
					averageAttackRateBps INTEGER NOT NULL,
					maxAttackRateBps INTEGER NOT NULL,
					maxAttackPacketRatePps INTEGER NOT NULL,
					lastPeriodBandwidth INTEGER NOT NULL,
					poId TEXT NOT NULL,
					radwareId TEXT NOT NULL,
					direction TEXT NOT NULL,
					geoLocation TEXT NOT NULL,
					activationId TEXT NOT NULL,
					packetType TEXT NOT NULL,
					physicalPort TEXT NOT NULL,
					lastPeriodPacketRate INTEGER NOT NULL,
				  	originalStartDate DATE NOT NULL)
				''')
			
			if self.today_month_number != 1: # This is a case for not January month
				# Clear the table content for the previous month
				cursor.execute(f'DELETE FROM attacks where month = {self.today_month_number -1}')


			else: # This is a case for  Jan 1st
				# Clear the table content for the previous month (December)
				cursor.execute('DELETE FROM attacks where month = 12')

			# Insert data into the table
			for entry in forensics_raw['data']:
				
				# Check if duration exists before trying to insert
				if 'duration' not in entry['row']:
					print(f"Skipping record - missing 'duration' field. Device: {entry['row'].get('deviceIp', 'unknown')}, Attack name: {entry['row'].get('name', 'unknown')}")
					continue

				start_date = datetime.fromtimestamp(int(entry["row"]["startTime"])/ 1000)
				orig_start_date = start_date
				end_date = datetime.fromtimestamp(int(entry["row"]["endTime"])/ 1000)


				#################################################################################	
				
				if self.today_month_number > 2: #Calculate the month and year 2 months ago
					two_months_ago_month = self.today_month_number - 2
				else:
					two_months_ago_month = self.today_month_number + 10  # Wrap around (12 months in a year)
				
				if start_date.month == two_months_ago_month: # This is a case when the attack started in the last day of the month before last month and continued to the first day of the last month
					print(f'Attack started in the last day of the month before last month and continued to the first day of the last month ({start_date})')
					
					if self.today_month_number !=1 : # This is a case for 2nd of the month, but not January month
						start_date = start_date.replace(day= 1, month=self.today_month_number-1, hour=0, minute=0, second=0)
						# print(f'New start date: {start_date}')
					else: # This is a case for 2nd of January
						start_date = start_date.replace(day= 1, month=12, hour=0, minute=0, second=0)
						# print(f'New start date: {start_date}')
				##################################################################################


				cursor.execute('''
				INSERT INTO attacks (deviceName, startDate, endDate, name, actionType, ruleName, sourceAddress, destAddress, sourcePort, destPort, protocol, threatGroup, category, attackIpsId, duration, risk, startTime, endTime, month, year, startDayOfMonth, endDayOfMonth, vlanTag, packetCount, packetBandwidth, averageAttackPacketRatePps, averageAttackRateBps, maxAttackRateBps, maxAttackPacketRatePps, lastPeriodBandwidth, poId, radwareId, direction, geoLocation, activationId, packetType, physicalPort, lastPeriodPacketRate, originalStartDate)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				''', (
					entry["row"]["deviceIp"], 
					start_date.strftime('%Y-%m-%d %H:%M:%S'), 
					end_date.strftime('%Y-%m-%d %H:%M:%S'), 
					entry["row"]["name"], 
					entry["row"]["actionType"], 
					entry["row"]["ruleName"], 
					entry["row"]["sourceAddress"], 
					entry["row"]["destAddress"], 
					entry["row"]["sourcePort"], 
					entry["row"]["destPort"], 
					entry["row"]["protocol"], 
					entry["row"]["threatGroup"], 
					entry["row"]["category"], 
					entry["row"]["attackIpsId"], 
					entry["row"]["duration"], 
					entry["row"]["risk"], 
					entry["row"]["startTime"], 
					entry["row"]["endTime"], 
					end_date.month,
					end_date.year,
					start_date.day, 
					end_date.day, 
					entry["row"]["vlanTag"], 
					entry["row"]["packetCount"], 
					entry["row"]["packetBandwidth"], 
					entry["row"]["averageAttackPacketRatePps"], 
					entry["row"]["averageAttackRateBps"], 
					entry["row"]["maxAttackRateBps"], 
					entry["row"]["maxAttackPacketRatePps"], 
					entry["row"]["lastPeriodBandwidth"], 
					entry["row"]["poId"], 
					entry["row"]["radwareId"], 
					entry["row"]["direction"], 
					json.loads(entry["row"]["enrichmentContainer"]).get("geoLocation", {}).get("countryCode", None), 
					entry["row"]["activationId"], 
					entry["row"]["packetType"], 
					entry["row"]["physicalPort"], 
					entry["row"]["lastPeriodPacketRate"],
					orig_start_date.strftime('%Y-%m-%d %H:%M:%S')
					))


			# Commit changes and close the connection
			conn.commit()
			conn.close()




v = Vision(vision_ip, username, password)


# Get Forensics data
if not offline:
	forensics_raw = v.get_forensics(v.start_time_lower,v.end_time_upper,v.days_in_prev_month)
	v.compile_to_sqldb()


######################################################################
# !!!!!!!!!!! For testing - remove. Open json file and read it and set variable traffic_bps_per_device instead of getting it

if offline:
	with open(raw_data_path + "traffic_per_device_bps_raw_granular.json", "r") as json_file:
		traffic_bps_per_device_granular = json.load(json_file)

	with open(raw_data_path + "traffic_per_device_bps_raw_aggregate.json", "r") as json_file:
		traffic_bps_per_device_aggregate = json.load(json_file)



	with open(raw_data_path + "traffic_per_device_pps_raw_granular.json", "r") as json_file:
		traffic_pps_per_device_granular = json.load(json_file)

	with open(raw_data_path + "traffic_per_device_pps_raw_aggregate.json", "r") as json_file:
		traffic_pps_per_device_aggregate = json.load(json_file)


	with open(raw_data_path + "cps_per_device_raw_granular.json", "r") as json_file:
		cps_per_device_granular = json.load(json_file)

	with open(raw_data_path + "cps_per_device_raw_aggregate.json", "r") as json_file:
		cps_per_device_aggregate = json.load(json_file)

	with open(raw_data_path + "cec_per_device_raw_granular.json", "r") as json_file:
		cec_per_device_granular = json.load(json_file)

	with open(raw_data_path + "cec_per_device_raw_aggregate.json", "r") as json_file:
		cec_per_device_aggregate = json.load(json_file)
#####################################################################




###################### Traffic BPS Chart ###########################
# 1. Collect the traffic data granularly (every 15 sec)
if not offline:
	traffic_bps_per_device_granular = v.ams_stats_dashboards_per_device_window_calls(v.start_time_lower, v.end_time_upper, traffic_window_granular, units = "bps", report_type="Traffic Volume BPS Granular")

# 2. Identify the attack timestamps
bps_attack_only_timestamps_list = v.extract_attack_data_only(traffic_bps_per_device_granular, bps_attack_threshold, pre_attack_extra_timestamps, post_attack_extra_timestamps)

# 3. Collect the averaged traffic data (average depending on the traffic_window)
if not offline:
	traffic_bps_per_device_aggregate = v.ams_stats_dashboards_per_device_window_calls(v.start_time_lower, v.end_time_upper, traffic_window_averaged, units = "bps", report_type="Traffic Volume BPS Aggregate")

# 4. Merge attack only timestamps into aggregate data. This way attack timeframe will be granular and rest will be aggregated and averaged
traffic_bps_per_device_merged = v.merge_attacks_to_aggregate(traffic_bps_per_device_aggregate, traffic_bps_per_device_granular,bps_attack_only_timestamps_list)

# 5. Write Traffic BPS Stats to sqlite db
v.write_traffic_stats_to_db(traffic_bps_per_device_merged, report_type="Traffic Volume BPS")


###################### Traffic PPS Chart ###########################
# 1. Collect the traffic data granularly (every 15 sec)
if not offline:
	traffic_pps_per_device_granular = v.ams_stats_dashboards_per_device_window_calls(v.start_time_lower, v.end_time_upper, traffic_window_granular, units = "pps", report_type="Traffic Volume PPS Granular")

# 2. Identify the attack timestamps
pps_attack_only_timestamps_list = v.extract_attack_data_only(traffic_pps_per_device_granular, pps_attack_threshold, pre_attack_extra_timestamps, post_attack_extra_timestamps)

# 3. Collect the averaged traffic data (average depending on the traffic_window)
if not offline:
	traffic_pps_per_device_aggregate = v.ams_stats_dashboards_per_device_window_calls(v.start_time_lower, v.end_time_upper, traffic_window_averaged, units = "pps", report_type="Traffic Volume PPS Aggregate")

# 4. Merge attack only timestamps into aggregate data. This way attack timeframe will be granular and rest will be aggregated and averaged
traffic_pps_per_device_merged = v.merge_attacks_to_aggregate(traffic_pps_per_device_aggregate, traffic_pps_per_device_granular,pps_attack_only_timestamps_list)

# 5. Write Traffic PPS Stats to sqlite db
v.write_traffic_stats_to_db(traffic_pps_per_device_merged, report_type="Traffic Volume PPS")


# Merge PPS attacks and BPS attack stamps

merged_attack_only_timestamps_list = sorted(set(bps_attack_only_timestamps_list) | set(pps_attack_only_timestamps_list))

# print('Printing all attack timestamps BPS+PPS')
# print(merged_attack_only_timestamps_list)



# ##################### Attacks BPS Chart ############################
# # 1. Write Attacks BPS Volume to csv (reusing the same data from Traffic BPS)
# v.write_per_device_combined_traffic_stats_to_csv(traffic_bps_per_device_merged, tmp_files_path + 'attacks_per_device_bps.csv')

# ##################### Attacks PPS Chart ############################
# # 1. Write Attacks PPS Volume to csv (reusing the same data from Traffic PPS)
# v.write_per_device_combined_traffic_stats_to_csv(traffic_pps_per_device_merged, tmp_files_path + 'attacks_per_device_pps.csv')



###################### Excluded BPS ###########################

# Write Excluded BPS Volume to database
v.write_traffic_stats_to_db(traffic_bps_per_device_aggregate, report_type="Traffic Volume BPS Excluded")

###################### Excluded PPS ###########################

# Write Excluded PPS Volume to csv from already collected data
v.write_traffic_stats_to_db(traffic_pps_per_device_aggregate, report_type="Traffic Volume PPS Excluded")



##################### CPS Chart ####################################

# 1. Collect the CPS data granularly (every 15 sec)
if not offline:
	cps_per_device_granular = v.ams_stats_dashboards_per_device_window_calls(v.start_time_lower, v.end_time_upper, traffic_window_granular, units=None, uri = "/mgmt/vrm/monitoring/traffic/cps", report_type="CPS Granular")

# 2. Collect the averaged traffic data (average depending on the traffic_window)
if not offline:
	cps_per_device_aggregate = v.ams_stats_dashboards_per_device_window_calls(v.start_time_lower, v.end_time_upper, traffic_window_averaged, units=None, uri = "/mgmt/vrm/monitoring/traffic/cps", report_type="CPS Aggregate")

# 3. Merge attack only timestamps into aggregate data. This way attack timeframe will be granular and rest will be aggregated and averaged

cps_per_device_merged = v.merge_attacks_to_aggregate(cps_per_device_aggregate, cps_per_device_granular,merged_attack_only_timestamps_list)

# 4. Write CPS to database
v.write_traffic_stats_to_db(cps_per_device_merged, report_type="Traffic CPS")


##################### Concurrent Connections Chart ####################################

# 1. Collect the Concurent Connections data granularly (every 15 sec)
if not offline:
	cec_per_device_granular = v.ams_stats_dashboards_per_device_window_calls(v.start_time_lower, v.end_time_upper, traffic_window_granular, units=None, uri = "/mgmt/vrm/monitoring/traffic/concurrent-connections", report_type="Concurrent Connections Granular")

# 2. Collect the averaged traffic data (average depending on the traffic_window)
if not offline:
	cec_per_device_aggregate = v.ams_stats_dashboards_per_device_window_calls(v.start_time_lower, v.end_time_upper, traffic_window_averaged, units=None, uri = "/mgmt/vrm/monitoring/traffic/concurrent-connections", report_type="Concurrent Connections Aggregate")

# 3. Merge attack only timestamps into aggregate data. This way attack timeframe will be granular and rest will be aggregated and averaged
cec_per_device_merged = v.merge_attacks_to_aggregate(cec_per_device_aggregate, cec_per_device_granular,merged_attack_only_timestamps_list)

# 4. Write Concurrent Connections to database
v.write_traffic_stats_to_db(cec_per_device_merged, report_type="Traffic CEC")

print(f'Finished data collection at {print(datetime.today())}')