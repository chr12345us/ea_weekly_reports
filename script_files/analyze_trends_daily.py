import pandas as pd
import sqlite3
import csv
import sys
import pandas as pd
import json

cust_id = sys.argv[1]
month = sys.argv[2] #this month
year = sys.argv[3] #this year


######### Exctract variables from /config_files/customers.json
customers_json = json.loads(open("./config_files/customers.json", "r").read())
for cust_config_block in customers_json:
	if cust_config_block['id'].lower() == cust_id.lower():
		defensepros = cust_config_block['defensepros']

		bw_units = cust_config_block['variables']['bwUnitDaily']
		#Can be configured "Gigabytes", "Terabytes" or "Megabytes"
		
		pkt_units = cust_config_block['variables']['pktUnitDaily']
		#Can be configured "Millions" or "Billions" or "Thousands"
		if bw_units.lower() == 'megabytes':	
			bw_units_sum = 'ROUND(SUM(packetBandwidth)/8000.0, 2)'
			bps_unit = 1000000
			bps_units_desc = 'Mbps'

		if bw_units.lower() == 'gigabytes':	
			bw_units_sum = 'ROUND(SUM(packetBandwidth)/8000000.0, 2)'
			bps_unit = 1000000000
			bps_units_desc = 'Gbps'

		if bw_units.lower() == 'terabytes':
			bw_units_sum = 'ROUND(SUM(packetBandwidth)/8000000000.0, 2)'
			bps_unit = 1000000000
			bps_units_desc = 'Gbps'

		try:
			if cust_config_block['variables']['barChartsAnnotations'].lower() == 'false':
				bar_charts_annotations = False
			else:
				bar_charts_annotations = True
		except:
			bar_charts_annotations = True

##### Extract variables from run.sh ##############
run_file = 'run_daily.sh'
with open (run_file) as f:
	for line in f:
	#find line starting with top_n
		if line.startswith('top_n'):
			#print value after = sign
			top_n = int(line.split('=')[1].replace('\n',''))
			continue

		if line.startswith('db_from_forensics'):
			#print value after = sign
			db_from_forensics = (line.split('=')[1].replace('\n','').replace('"','')).lower()
			if db_from_forensics == 'true':
				db_from_forensics = True
			else:
				db_from_forensics = False
			continue


# Paths
charts_tables_path = f"./tmp_files/{cust_id}/"
reports_path = f"./report_files/{cust_id}/"
db_path = f'./database_files/{cust_id}/'
db_file = 'database_' + cust_id + '_' + str(month) + '_' + str(year) + '.sqlite'


def convert_csv_to_list_of_lists(filename):
	# Open csv file and convert to list of lists function
	data = []
	with open(filename, 'r') as file:
		reader = csv.reader(file)
		for row in reader:
			data.append(row)

	return convert_strings_to_numbers(data)

def convert_sqlite_to_list_of_lists(db_filename, db_table_name):

	# Connect to SQLite database
	conn = sqlite3.connect(db_filename)
	cursor = conn.cursor()

	# Fetch all column names
	cursor.execute(f"PRAGMA table_info({db_table_name})")
	columns_info = cursor.fetchall()
	column_names = [col[1] for col in columns_info if col[1] != "DateTime"]

	

	# Quote column names to handle special characters
	quoted_column_names = [f'"{col}"' for col in column_names]

	# Query all rows ordered by Timestamp, excluding DateTime
	cursor.execute(f'''
		SELECT {', '.join(quoted_column_names)} 
		FROM "{db_table_name}" 
		ORDER BY CAST(Timestamp AS INTEGER)
	''')
	

	rows = cursor.fetchall()

	# Convert each row tuple to list and make sure Timestamp is a number
	rows_as_lists = []
	for row in rows:
		row = list(row)
		# Convert the Timestamp (first column) to int
		try:
			row[0] = int(row[0])
		except ValueError:
			pass  # leave as-is if conversion fails
		rows_as_lists.append(row)

	# Prepend the column names
	result = [column_names] + rows_as_lists

	conn.close()
	return result

def convert_strings_to_numbers(data):
  # Check values float, integer or string function
	converted_data = []
	
	for sublist_index, sublist in enumerate(data):
		if sublist_index == 0: # do not convert the strings to numbers for the first headline row (policy names might be numbers corner case)
			converted_data.append(sublist)
		else:
			converted_row = []
			for value in sublist:
				#check if not ipv4 address
				if value.count('.') != 3:
					if value.replace(".", "").isdigit():  # Check if value is numeric
						if value.endswith('.0'):
							value = int(value.replace('.0', ''))
							converted_row.append(value)  # Convert ".0" to integer
						#check if value has decimal points
						elif "." in value:
							converted_row.append(float(value))
						elif value.isdigit():
							converted_row.append(int(value))  # Convert to integer
						else:
							print('The value is not defined as integer or float')
					else:
						converted_row.append(value)
				else:
					converted_row.append(value)
			converted_data.append(converted_row)
	return converted_data

def convert_packets_units(data, pkt_units):
	converted_data = []
	for row in data:
		converted_row = []
		for index, value in enumerate(row):
			# if the value is integer or float
			if index==0:
				value = value
			else:
				if isinstance(value, int) or isinstance(value, float):
					if pkt_units == "Billions":
						value = value/1000000000
					elif pkt_units == "Millions":
						value = value/1000000
					elif pkt_units == "Thousands":
						value = value/1000
					elif pkt_units.lower() == "as is":
						pass
					else:
						print(f'Packets unit variable "pkt_units" is not set.')
				
			#if value float convert to integer
					if isinstance(value, float):
						value = int(value)

			converted_row.append(value)
			
		converted_data.append(converted_row)
	return converted_data


def convert_bw_units(data, bw_units):
	converted_data = []

	for row in data:
		converted_row = []

		for index, value in enumerate(row):
			if index == 0:
				# For the first column, just append the value without conversion
				converted_row.append(value)
			elif not isinstance(value, str) and value != "":
				# Check if the value is not a string and not empty
				value = float(value)

				if bw_units.lower() == "megabytes":
					value = value / 8000
				elif bw_units.lower() == "gigabytes":
					value = value / 8000000
				elif bw_units.lower() == "terabytes":
					value = value / 8000000000

				# Leave only two decimal points
				value = round(value, 2)

				converted_row.append(value)
			else:
				# Append the original value if it's a string or empty
				converted_row.append(value)

		converted_data.append(converted_row)

	return converted_data

def trends_move(data, units="events"):

	analysis = '<ul>'
	# Extract attack names and attack counts for June and July
	attack_names = data[0][1:]
	attack_counts_previous = data[-2][1:]
	attack_counts_last = data[-1][1:]

	if isinstance(attack_counts_previous, list) and all(isinstance(item, str) for item in attack_counts_previous):
		analysis = f"Can not calculate trends - no previous month data"
		return analysis

	else:
		# Calculate and print the trends
		for name, count_previous, count_last in zip(attack_names, attack_counts_previous, attack_counts_last):
			if int(count_last) < int(count_previous):
				trend = "Decrease"
			else:
				trend = "Increase"
			
			difference = abs(int(count_last) - int(count_previous))

			if count_previous == 0:
				difference_percentage = "N/A"
			else:
				difference_percentage = (difference / count_previous) * 100

			#check if difference is float


			if isinstance(difference, float):
				difference = round(difference, 2)

			if difference_percentage == "N/A":
				change = f"by N/A %  - from {count_previous} to {count_last} {units} by a total of {difference} {units} "
			else:
				change = f"by {difference_percentage:.2f}% - from {count_previous} to {count_last} {units} by a total of {difference} {units} "
		
			analysis += f'<li><strong>{name}:</strong><ul><li> {trend} {change}</li></ul>'

		analysis += '</ul>'

		return analysis


def trends_move_total(data, units="events"):
	
	prev_total = data[-2][1]
	last_total = data[-1][1]

	if isinstance(prev_total, str):
		result = f"Can not calculate trends - no previous month data"
		return result
	
	else:
		trend = "increased" if last_total > prev_total else "decreased"
		difference = abs(last_total - prev_total)

		if isinstance(difference, float):
			difference = round(difference, 2)

		if float(prev_total) == 0:
			percentage_difference = "N/A"
			result = f"This month the total number of {units} {trend} by {percentage_difference}%- from {prev_total} to {last_total} {units} by a total of {difference} {units}"

		else:
			percentage_difference = (difference / float(prev_total)) * 100
			formatted_percentage_difference = f'{percentage_difference:.2f}%'
			result = f"This month the total number of {units} {trend} by {formatted_percentage_difference}- from {prev_total} to {last_total} {units} by a total of {difference} {units}"

		return result


def format_bw_units_value(value, bw_units=None):
	# Check if value is a number (integer or float)
	if pd.notna(value) and isinstance(value, (int, float)):
		# Apply formatting based on units
		if bw_units:
			if bw_units.lower() == 'megabytes':
				value /= 8000
			elif bw_units.lower() == 'gigabytes':
				value /= 8000000
			elif bw_units.lower() == 'terabytes':
				value /= 8000000000

			value = '{:,.2f}'.format(value)
			return value

	else:
		return value


def format_pkt_units_value(value, pkt_units=None):
	# Check if value is a number (integer or float)
	if pd.notna(value) and isinstance(value, (int, float)):
		# Apply formatting based on units
		if pkt_units:
			if pkt_units.lower() == 'millions':
				value /= 1000000
			elif pkt_units.lower() == 'billions':
				value /= 1000000000
			elif pkt_units.lower() == 'thousands':
				value /= 1000
			elif pkt_units.lower() == 'as is':
				pass
			else:
				print(f'pkt_units variable is not set - value is {value} , pkt_units is {pkt_units}')

			

			# convert float to intiger
			if isinstance(value, float):
				value = int(value)
			

			value = "{:,}".format(value)
			return value
		
			
	else:
		return value

def convert_to_int(column):
	try:
		return column.astype(int)
	except ValueError:
		return column
	
def csv_to_html_table(filename, bw_units=None, pkt_units=None):
	# Read the CSV file, if the value is integer, leave it as integer, if float, leave it as float
	
	df = pd.read_csv(filename)

	# Apply formatting to numeric columns
	if bw_units and filename!=charts_tables_path + 'sip_packets_per_day_table_alltimehigh.csv':
#		formatted_df = df.applymap(lambda x: format_bw_units_value(x, bw_units))
		formatted_df = df.apply(lambda col: col.map(lambda x: format_bw_units_value(x, bw_units)))


	elif pkt_units and filename!=charts_tables_path + 'sip_packets_per_day_table_alltimehigh.csv':
#		formatted_df = df.applymap(lambda x: format_pkt_units_value(x, pkt_units))
		formatted_df = df.apply(lambda col: col.map(lambda x: format_pkt_units_value(x, pkt_units)))

	else:
		df = df.apply(convert_to_int, axis=0)
		formatted_df = df

	# Convert the formatted DataFrame to an HTML table
	html_table = formatted_df.to_html(index=False, escape=False)
	
	return html_table


def write_html(html_page,month,year):
	# write html_page to file function

	with open(reports_path + f'trends-daily_{cust_id}_{month}_{year}.html', 'w') as f:
		f.write(html_page)


def extract_values_from_csv(csv_file):
	values = []

	with open(charts_tables_path + csv_file, 'r') as csv_file:
		csv_reader = csv.reader(csv_file)
		
		# Skip the header row
		next(csv_reader)

		# Extract values from the first column
		for row in csv_reader:
			values.append(row[0])

	return values

def bw_units_conversion(value):

	if isinstance(value, (int, float)):
		if bw_units.lower() == 'megabytes':
			return round(value / 8000, 2)
		elif bw_units.lower() == 'gigabytes':
			return round(value / 8000000, 2)
		elif bw_units.lower() == 'terabytes':
			return round(value / 8000000000, 2)

def pkt_units_conversion(value):

	if isinstance(value, (int, float)):
		if pkt_units.lower() == 'millions':
			return round(value / 1000000, 2)
		elif pkt_units.lower() == 'billions':
			return round(value / 1000000000, 2)
		if pkt_units.lower() == 'thousands':
			return round(value / 1000, 2)

	return value


def maxpps_per_day_html_table():

	maxpps_indices = data_month.groupby(['Day of the Month'])['maxAttackPacketRatePps'].idxmax()
	maxpps_rows = data_month.loc[maxpps_indices][['startDate', 'Device Name','Policy Name','Attack Name', 'maxAttackPacketRatePps']].reset_index(drop=True)
	maxpps_rows['maxAttackPacketRatePps'] = maxpps_rows['maxAttackPacketRatePps'].apply(lambda x: f"{x:,}")
	maxpps_rows= maxpps_rows.to_html(index=False)
	return maxpps_rows


def maxbps_per_day_html_table():

	maxbps_indices = data_month.groupby(['Day of the Month'])['maxAttackRateBps'].idxmax()
	maxbps_rows = data_month.loc[maxbps_indices][['startDate', 'Device Name','Policy Name','Attack Name', 'maxAttackRateBps']].reset_index(drop=True)
	maxbps_rows['maxAttackRateBps'] = maxbps_rows['maxAttackRateBps'].apply(lambda x: f"{x / bps_unit:,.2f} {bps_units_desc}")
	maxbps_rows= maxbps_rows.to_html(index=False)
	return maxbps_rows

def events_per_day_html_table():

	# Group by day_of_month, name, Device Name, Policy Name and aggregate sum of packetCount
	events_per_day = data_month.groupby(['Day of the Month', 'Attack Name', 'Device Name', 'Policy Name']).size()

	# Get the top 5 events with the highest sum of packet counts for each day
	events_per_day_top5 = events_per_day.groupby(level=['Day of the Month'], group_keys=False).nlargest(5).apply(format_with_commas).to_frame('Attack Events Count')
	events_per_day_top5 = events_per_day_top5.to_html()

	for device_ip, device_name in defensepros.items():
		events_per_day_top5=events_per_day_top5.replace(device_ip, device_name)

	return events_per_day_top5

def packets_per_day_html_table():

	# Group by day_of_month, name, Device Name, Policy Name and aggregate sum of packetCount
	packets_per_day = data_month.groupby(['Day of the Month', 'Attack Name', 'Device Name', 'Policy Name'])['packetCount'].sum()
	packets_per_day = packets_per_day.apply(pkt_units_conversion)

	# Get the top 5 events with the highest sum of packet counts for each day
	packets_per_day_top5 = packets_per_day.groupby(level=['Day of the Month'], group_keys=False).nlargest(5).apply(format_with_commas).to_frame('Attack packets sum')
	packets_per_day_top5 = packets_per_day_top5.to_html()

	for device_ip, device_name in defensepros.items():
		packets_per_day_top5=packets_per_day_top5.replace(device_ip, device_name)

	return packets_per_day_top5


def bandwidth_per_day_html_table():
	# Group by day_of_month, name, Device Name, Policy Name and aggregate sum of packetCount
	bandwidth_per_day = data_month.groupby(['Day of the Month', 'Attack Name', 'Device Name', 'Policy Name'])['packetBandwidth'].sum()
	bandwidth_per_day = bandwidth_per_day.apply(bw_units_conversion)

	# Get the top 5 events with the highest sum of packet counts for each day
	bandwidth_per_day_top5 = bandwidth_per_day.groupby(level=['Day of the Month'], group_keys=False).nlargest(5).apply(format_with_commas).to_frame('Attack Volume sum')
	bandwidth_per_day_top5 = bandwidth_per_day_top5.to_html()

	for device_ip, device_name in defensepros.items():
		bandwidth_per_day_top5=bandwidth_per_day_top5.replace(device_ip, device_name)

	return bandwidth_per_day_top5





def events_per_day_html(epm):
	data_month_epm = data_month[data_month['Attack Name'] == epm]
	series_epm = data_month_epm.groupby(['Attack Name','Device Name','Policy Name']).size().sort_values(ascending=False).apply(format_with_commas).head(10)
	events_per_day_html = series_epm.to_frame('Attack Events')
	events_per_day_html=events_per_day_html.to_html()

	for device_ip, device_name in defensepros.items():
		events_per_day_html=events_per_day_html.replace(device_ip, device_name)

	return events_per_day_html

def packets_per_day_html(ppm):
	data_month_ppm = data_month[data_month['Attack Name'] == ppm]
	series_ppm = data_month_ppm.groupby(['Attack Name','Device Name','Policy Name']).sum()['packetCount'].sort_values(ascending=False)
	# Convert units
	series_ppm = series_ppm.apply(pkt_units_conversion).apply(format_with_commas).head(10)
	packets_per_day_html = series_ppm.to_frame('Attack packets')
	packets_per_day_html=packets_per_day_html.to_html()

	for device_ip, device_name in defensepros.items():
		packets_per_day_html=packets_per_day_html.replace(device_ip, device_name)

	return packets_per_day_html

def bandwidth_per_day_html(bpm):
	data_month_bpm = data_month[data_month['Attack Name'] == bpm]
	series_bpm = data_month_bpm.groupby(['Attack Name','Device Name','Policy Name']).sum()['packetBandwidth'].sort_values(ascending=False)
	# Convert units
	series_bpm = series_bpm.apply(bw_units_conversion).apply(format_with_commas).head(10)

	df_bandwidth_per_day_html = series_bpm.to_frame('Attack Volume')
	df_bandwidth_per_day_html=df_bandwidth_per_day_html.to_html()

	for device_ip, device_name in defensepros.items():
		df_bandwidth_per_day_html=df_bandwidth_per_day_html.replace(device_ip, device_name)

	return df_bandwidth_per_day_html



def device_events_per_day_html(device_epm):

	for device_ip, device_name in defensepros.items():
		if device_name == device_epm:

			data_month_epm = data_month[data_month['Device Name'] == device_ip]
			device_series_epm = data_month_epm.groupby(['Device Name','Attack Name','Policy Name']).size().sort_values(ascending=False).apply(format_with_commas).head(10)
			device_events_per_day_html = device_series_epm.to_frame('Attack Events')
			device_events_per_day_html=device_events_per_day_html.to_html().replace(device_ip, device_name)
			
	return device_events_per_day_html

def device_packets_per_day_html(device_ppm):

	for device_ip, device_name in defensepros.items():
		
		if device_name == device_ppm:
			data_month_ppm = data_month[data_month['Device Name'] == device_ip]
			device_series_ppm = data_month_ppm.groupby(['Device Name','Attack Name','Policy Name']).sum()['packetCount'].sort_values(ascending=False)
			device_series_ppm = device_series_ppm.apply(pkt_units_conversion).apply(format_with_commas).head(10)
			device_packets_per_day_html = device_series_ppm.to_frame('Attack packets')
			device_packets_per_day_html=device_packets_per_day_html.to_html().replace(device_ip, device_name)
	return device_packets_per_day_html

def device_bandwidth_per_day_html(device_bpm):
	for device_ip, device_name in defensepros.items():
		if device_name == device_bpm:
			data_month_bpm = data_month[data_month['Device Name'] == device_ip]
			device_series_bpm = data_month_bpm.groupby(['Device Name','Attack Name','Policy Name']).sum()['packetBandwidth'].sort_values(ascending=False)
			device_series_bpm = device_series_bpm.apply(bw_units_conversion).apply(format_with_commas).head(10)
			device_df_bandwidth_per_day_html = device_series_bpm.to_frame('Attack Volume')
			device_df_bandwidth_per_day_html= device_df_bandwidth_per_day_html.to_html().replace(device_ip, device_name)


	return device_df_bandwidth_per_day_html


def policy_events_per_day_html(policy_epm):

	data_month_epm = data_month[data_month['Policy Name'] == policy_epm]
	series_epm = data_month_epm.groupby(['Policy Name','Attack Name','Device Name']).size().sort_values(ascending=False).apply(format_with_commas).head(10)
	events_per_day_html = series_epm.to_frame('Attack Events')
	events_per_day_html=events_per_day_html.to_html()

	for device_ip, device_name in defensepros.items():
		events_per_day_html=events_per_day_html.replace(device_ip, device_name)
		
	return events_per_day_html

def policy_packets_per_day_html(policy_ppm):
	data_month_ppm = data_month[data_month['Policy Name'] == policy_ppm]
	series_ppm = data_month_ppm.groupby(['Policy Name','Attack Name','Device Name']).sum()['packetCount'].sort_values(ascending=False)
	series_ppm = series_ppm.apply(pkt_units_conversion).apply(format_with_commas).head(10)
	packets_per_day_html = series_ppm.to_frame('Attack packets')
	packets_per_day_html=packets_per_day_html.to_html()
	
	for device_ip, device_name in defensepros.items():
		packets_per_day_html=packets_per_day_html.replace(device_ip, device_name)
	
	return packets_per_day_html

def policy_bandwidth_per_day_html(policy_bpm):
	data_month_bpm = data_month[data_month['Policy Name'] == policy_bpm]
	series_bpm = data_month_bpm.groupby(['Policy Name','Attack Name','Device Name']).sum()['packetBandwidth'].sort_values(ascending=False)
	series_bpm = series_bpm.apply(bw_units_conversion).apply(format_with_commas).head(10)
	df_bandwidth_per_day_html = series_bpm.to_frame('Attack Volume')
	df_bandwidth_per_day_html=df_bandwidth_per_day_html.to_html()

	for device_ip, device_name in defensepros.items():
		df_bandwidth_per_day_html=df_bandwidth_per_day_html.replace(device_ip, device_name)
	
	return df_bandwidth_per_day_html


def sip_events_per_day_html(sip_epm):

	data_month_epm = data_month[data_month['Source IP'] == sip_epm]
	series_epm = data_month_epm.groupby(['Source IP','Attack Name','Device Name','Policy Name']).size().sort_values(ascending=False).apply(format_with_commas).head(10)
	events_per_day_html = series_epm.to_frame('Attack Events')
	events_per_day_html=events_per_day_html.to_html()

	for device_ip, device_name in defensepros.items():
		events_per_day_html=events_per_day_html.replace(device_ip, device_name)
		
	return events_per_day_html


def sip_packets_per_day_html(sip_ppm):
	data_month_ppm = data_month[data_month['Source IP'] == sip_ppm]
	series_ppm = data_month_ppm.groupby(['Source IP','Attack Name','Device Name','Policy Name']).sum()['packetCount'].sort_values(ascending=False)
	series_ppm = series_ppm.apply(pkt_units_conversion).apply(format_with_commas).head(10)
	packets_per_day_html = series_ppm.to_frame('Attack packets')
	packets_per_day_html=packets_per_day_html.to_html()
	
	for device_ip, device_name in defensepros.items():
		packets_per_day_html=packets_per_day_html.replace(device_ip, device_name)
	
	return packets_per_day_html

def sip_bandwidth_per_day_html(sip_bpm):
	data_month_bpm = data_month[data_month['Source IP'] == sip_bpm]
	series_bpm = data_month_bpm.groupby(['Source IP','Attack Name','Device Name','Policy Name']).sum()['packetBandwidth'].sort_values(ascending=False)
	series_bpm = series_bpm.apply(bw_units_conversion).apply(format_with_commas).head(10)
	df_bandwidth_per_day_html = series_bpm.to_frame('Attack Volume')
	df_bandwidth_per_day_html=df_bandwidth_per_day_html.to_html()

	for device_ip, device_name in defensepros.items():
		df_bandwidth_per_day_html=df_bandwidth_per_day_html.replace(device_ip, device_name)
	
	return df_bandwidth_per_day_html



def format_with_commas(value):
	return '{:,}'.format(value)


if __name__ == '__main__':


	maxpps_per_day_trends = convert_csv_to_list_of_lists(charts_tables_path + 'maxpps_per_day_last_month.csv')

	# Attack Volume per day
	maxbps_per_day_trends = convert_csv_to_list_of_lists(charts_tables_path + 'maxbps_per_day_last_month.csv')


	# Events per day count
	events_per_day_trends = convert_csv_to_list_of_lists(charts_tables_path + 'events_per_day_last_month.csv')

	# Attack Volume per day
	packets_per_day_trends = convert_csv_to_list_of_lists(charts_tables_path + 'packets_per_day_last_month.csv')

	# Attack Volume per day
	bandwidth_per_day_trends = convert_csv_to_list_of_lists(charts_tables_path + 'bandwidth_per_day_last_month.csv')


	# Traffic volume
	if db_from_forensics:
		traffic_per_device_combined_trends_bps = [['Date,Traffic Utilization(Mbps),Blocked traffic,Excluded traffic']]
		attacks_per_device_combined_trends_bps = [['Date,Traffic Utilization(Mbps),Blocked traffic,Excluded traffic']]
		
		traffic_per_device_combined_trends_pps = [['Date,Traffic Utilization(PPS),Blocked traffic,Excluded traffic']]
		attacks_per_device_combined_trends_pps = [['Date,Traffic Utilization(PPS),Blocked traffic,Excluded traffic']]

		cps_per_device_combined_trends = [['Date,CPS']]
		cec_per_device_combined_trends = [['Date,CEC']]

		excluded_per_device_combined_trends_bps = [['Date,Excluded Traffic(Mbps)']]
		excluded_per_device_combined_trends_pps = [['Date,Excluded Traffic(PPS)']]

	else:



		traffic_per_device_combined_trends_bps = convert_sqlite_to_list_of_lists(db_path + db_file, "traffic_bps")
		number_of_devices = (len(traffic_per_device_combined_trends_bps[0]) - 1) /2

		traffic_per_device_combined_trends_pps = convert_sqlite_to_list_of_lists(db_path + db_file, "traffic_pps")

		cps_per_device_combined_trends = convert_sqlite_to_list_of_lists(db_path + db_file, "traffic_cps")
		cec_per_device_combined_trends = convert_sqlite_to_list_of_lists(db_path + db_file, "traffic_cec")

		excluded_per_device_combined_trends_bps = convert_sqlite_to_list_of_lists(db_path + db_file, "traffic_bps_excluded")
		excluded_per_device_combined_trends_pps = convert_sqlite_to_list_of_lists(db_path + db_file, "traffic_pps_excluded")


	################################################# Analyze deeper top category ##########################################################

	#1 Create a data frame
	con = sqlite3.connect(db_path + db_file)
	# data = pd.read_sql_query("SELECT * from attacks", con)
	data_month = pd.read_sql_query(f"SELECT deviceName as 'Device Name',month,year,packetBandwidth,name as 'Attack Name',packetCount,ruleName as 'Policy Name',category,sourceAddress as 'Source IP',destAddress,startTime,endTime,startDate,attackIpsId,actionType,maxAttackPacketRatePps,maxAttackRateBps,destPort,protocol,startDayOfMonth as 'Day of the Month' from attacks", con)

	#export data to csv
	data_month.to_csv(reports_path +'database_'+cust_id+'_'+str(month)+'_'+str(year)+'.csv', encoding='utf-8', index=False)

	con.close()

	#2 Extract Top Attacks list

	events_per_day_top_list=extract_values_from_csv('events_per_day_table_alltimehigh.csv')
	packets_per_day_top_list=extract_values_from_csv('packets_per_day_table_alltimehigh.csv')
	bandwidth_per_day_top_list=extract_values_from_csv('bandwidth_per_day_table_alltimehigh.csv')

	device_events_per_day_top_list=extract_values_from_csv('device_events_per_day_table_alltimehigh.csv') #list of devices
	device_packets_per_day_top_list=extract_values_from_csv('device_packets_per_day_table_alltimehigh.csv') #list of devices
	device_bandwidth_per_day_top_list=extract_values_from_csv('device_bandwidth_per_day_table_alltimehigh.csv') #list of devices

	policy_events_per_day_top_list=extract_values_from_csv('policy_events_per_day_table_alltimehigh.csv')
	policy_packets_per_day_top_list=extract_values_from_csv('policy_packets_per_day_table_alltimehigh.csv')
	policy_bandwidth_per_day_top_list=extract_values_from_csv('policy_bandwidth_per_day_table_alltimehigh.csv')

	sip_events_per_day_top_list=extract_values_from_csv('sip_events_per_day_table_alltimehigh.csv')
	sip_packets_per_day_top_list=extract_values_from_csv('sip_packets_per_day_table_alltimehigh.csv')
	sip_bandwidth_per_day_top_list=extract_values_from_csv('sip_bandwidth_per_day_table_alltimehigh.csv')

	#3 Create empty html table
	events_per_day_html_final = ''
	packets_per_day_html_final = ''
	bandwidth_per_day_html_final = ''

	device_events_per_day_html_final = ''
	device_packets_per_day_html_final = ''
	device_bandwidth_per_day_html_final = ''

	policy_events_per_day_html_final = ''
	policy_packets_per_day_html_final = ''
	policy_bandwidth_per_day_html_final = ''

	sip_events_per_day_html_final = ''
	sip_packets_per_day_html_final = ''
	sip_bandwidth_per_day_html_final = ''

	#4 Iterate through each Device and popluate the html table

	for index, value in enumerate(events_per_day_top_list):
		events_per_day_html_final+=f'<h4>Distribution of topmost Attack Events for attack "{value}" across devices and policies</h4>'
		events_per_day_html_final+= events_per_day_html(events_per_day_top_list[index])

	for index, value in enumerate(packets_per_day_top_list):
		packets_per_day_html_final+=f'<h4>Distribution of topmost Attack packets for attack "{value}" across devices and policies</h4>'
		packets_per_day_html_final+= packets_per_day_html(packets_per_day_top_list[index])
		
	for index, value in enumerate(bandwidth_per_day_top_list):
		bandwidth_per_day_html_final+=f'<h4>Distribution of topmost Attack Volume for attack "{value}" across devices and policies</h4>'
		bandwidth_per_day_html_final+= bandwidth_per_day_html(bandwidth_per_day_top_list[index])



	for index, value in enumerate(device_events_per_day_top_list):
		device_events_per_day_html_final+=f'<h4>Distribution of Attack Events for device "{value}" across policies</h4>'
		device_events_per_day_html_final+= device_events_per_day_html(device_events_per_day_top_list[index])

	for index, value in enumerate(device_packets_per_day_top_list):
		device_packets_per_day_html_final+=f'<h4>Distribution of Attack packets for device "{value}" across policies</h4>'
		device_packets_per_day_html_final+= device_packets_per_day_html(device_packets_per_day_top_list[index])

	for index, value in enumerate(device_bandwidth_per_day_top_list):
		device_bandwidth_per_day_html_final+=f'<h4>Distribution of Attack Volume for device "{value}" across policies</h4>'
		device_bandwidth_per_day_html_final+= device_bandwidth_per_day_html(device_packets_per_day_top_list[index])


	for index, value in enumerate(policy_events_per_day_top_list):
		policy_events_per_day_html_final+=f'<h4>Distribution of Attack Events for policy "{value}" across devices</h4>'
		policy_events_per_day_html_final+= policy_events_per_day_html(policy_events_per_day_top_list[index])

	for index, value in enumerate(policy_packets_per_day_top_list):
		policy_packets_per_day_html_final+=f'<h4>Distribution of  Attack packets for policy "{value}" across devices</h4>'
		policy_packets_per_day_html_final+= policy_packets_per_day_html(policy_packets_per_day_top_list[index])
		
	for index, value in enumerate(policy_bandwidth_per_day_top_list):
		policy_bandwidth_per_day_html_final+=f'<h4>Distribution of Attack Volume for policy "{value}" across devices</h4>'
		policy_bandwidth_per_day_html_final+= policy_bandwidth_per_day_html(policy_bandwidth_per_day_top_list[index])


	for index, value in enumerate(sip_events_per_day_top_list):
		sip_events_per_day_html_final+=f'<h4>Distribution of Attack Events for Source IP {value}</h4>'
		sip_events_per_day_html_final+= sip_events_per_day_html(sip_events_per_day_top_list[index])

	for index, value in enumerate(sip_packets_per_day_top_list):
		sip_packets_per_day_html_final+=f'<h4>Distribution of Attack packets for Source IP {value}</h4>'
		sip_packets_per_day_html_final+= sip_packets_per_day_html(sip_packets_per_day_top_list[index])
		
	for index, value in enumerate(sip_bandwidth_per_day_top_list):
		sip_bandwidth_per_day_html_final+=f'<h4>Distribution of Attack Volume for Source IP {value}</h4>'
		sip_bandwidth_per_day_html_final+= sip_bandwidth_per_day_html(sip_bandwidth_per_day_top_list[index])


	#5 Generate html for the last month


	maxpps_per_day_table = maxpps_per_day_html_table()
	maxbps_per_day_table = maxbps_per_day_html_table()


	events_per_day_table = events_per_day_html_table()
	packets_per_day_table = packets_per_day_html_table()
	bandwidth_per_day_table = bandwidth_per_day_html_table()


	################################################# Events, packets and bandwidth trends by Attack name sorted by the overall sum of all months together ##########################################################


	events_trends_alltimehigh = convert_csv_to_list_of_lists(charts_tables_path + 'events_per_day_chart_alltimehigh.csv')
	events_trends_move_alltimehigh = trends_move(events_trends_alltimehigh, 'events')
	events_trends_table_alltimehigh = csv_to_html_table(charts_tables_path + 'events_per_day_table_alltimehigh.csv')
	
	
	packets_trends_chart_alltimehigh = convert_csv_to_list_of_lists(charts_tables_path + 'packets_per_day_chart_alltimehigh.csv')
	packets_trends_chart_alltimehigh = convert_packets_units(packets_trends_chart_alltimehigh, pkt_units)

	if pkt_units is not None:
		packets_trends_move_text_alltimehigh = trends_move(packets_trends_chart_alltimehigh, ' packets(' + pkt_units + ')')
		packets_table_alltimehigh = csv_to_html_table(charts_tables_path + 'packets_per_day_table_alltimehigh.csv',bw_units=None, pkt_units=pkt_units)


	else:
		packets_trends_move_text_alltimehigh = trends_move(packets_trends_chart_alltimehigh, ' packets')
		packets_table_alltimehigh = csv_to_html_table(charts_tables_path + 'packets_per_day_table_alltimehigh.csv',bw_units=None, pkt_units=None)




	bw_trends_alltimehigh = convert_csv_to_list_of_lists(charts_tables_path + 'bandwidth_per_day_chart_alltimehigh.csv')
	bw_trends_alltimehigh = convert_bw_units(bw_trends_alltimehigh, bw_units)
	bw_trends_move_alltimehigh = trends_move(bw_trends_alltimehigh, bw_units)
	bw_table_alltimehigh = csv_to_html_table(charts_tables_path + 'bandwidth_per_day_table_alltimehigh.csv',bw_units)


	################################################# Events, packets and bandwidth trends by DefensePro  ##########################################################

	events_by_device_trends_chart_data = convert_csv_to_list_of_lists(charts_tables_path + 'device_events_per_day_chart_alltimehigh.csv')
	events_by_device_trends_move_text = trends_move(events_by_device_trends_chart_data, 'events')
	events_by_device_table = csv_to_html_table(charts_tables_path + 'device_events_per_day_table_alltimehigh.csv')

	packets_by_device_trends_chart_data = convert_csv_to_list_of_lists(charts_tables_path + 'device_packets_per_day_chart_alltimehigh.csv')
	packets_by_device_trends_chart_data = convert_packets_units(packets_by_device_trends_chart_data, pkt_units)
	packets_by_device_trends_move_text = trends_move(packets_by_device_trends_chart_data, ' packets(' + pkt_units + ')')
	packets_by_device_table = csv_to_html_table(charts_tables_path + 'device_packets_per_day_table_alltimehigh.csv',bw_units=None, pkt_units=pkt_units)

	bw_by_device_trends_chart_data = convert_csv_to_list_of_lists(charts_tables_path + 'device_bandwidth_per_day_chart_alltimehigh.csv')
	bw_by_device_trends_chart_data = convert_bw_units(bw_by_device_trends_chart_data, bw_units)
	bw_by_device_trends_move_text = trends_move(bw_by_device_trends_chart_data, bw_units)
	bw_by_device_table = csv_to_html_table(charts_tables_path + 'device_bandwidth_per_day_table_alltimehigh.csv',bw_units)


	################################################# Events, packets and bandwidth trends by Policy ##########################################################

	policy_events_trends_chart = convert_csv_to_list_of_lists(charts_tables_path + 'policy_events_per_day_chart_alltimehigh.csv')
	policy_events_trends_move_text = trends_move(policy_events_trends_chart, 'events')
	policy_events_trends_table = csv_to_html_table(charts_tables_path + 'policy_events_per_day_table_alltimehigh.csv')


	policy_packets_trends_chart = convert_csv_to_list_of_lists(charts_tables_path + 'policy_packets_per_day_chart_alltimehigh.csv')
	policy_packets_trends_chart = convert_packets_units(policy_packets_trends_chart, pkt_units)
	policy_packets_trends_move_text = trends_move(policy_packets_trends_chart, ' packets(' + pkt_units + ')')
	policy_packets_table = csv_to_html_table(charts_tables_path + 'policy_packets_per_day_table_alltimehigh.csv',bw_units=None, pkt_units=pkt_units)


	policy_bw_trends_chart = convert_csv_to_list_of_lists(charts_tables_path + 'policy_bandwidth_per_day_chart_alltimehigh.csv')
	policy_bw_trends_chart = convert_bw_units(policy_bw_trends_chart, bw_units)
	policy_bw_trends_move_text = trends_move(policy_bw_trends_chart, bw_units)
	policy_bw_table = csv_to_html_table(charts_tables_path + 'policy_bandwidth_per_day_table_alltimehigh.csv',bw_units)


	################################################# Top source IP(bw is Megabytes) ##########################################################		
	sip_events_trends_chart = convert_csv_to_list_of_lists(charts_tables_path + 'sip_events_per_day_chart_alltimehigh.csv')
	sip_events_trends_move_text = trends_move(sip_events_trends_chart, 'events')
	sip_events_trends_table = csv_to_html_table(charts_tables_path + 'sip_events_per_day_table_alltimehigh.csv')

	sip_packets_trends_chart = convert_csv_to_list_of_lists(charts_tables_path + 'sip_packets_per_day_chart_alltimehigh.csv')
	sip_packets_trends_chart = convert_packets_units(sip_packets_trends_chart, pkt_units)

	sip_packets_trends_move_text = trends_move(sip_packets_trends_chart, ' packets')
	sip_packets_table = csv_to_html_table(charts_tables_path + 'sip_packets_per_day_table_alltimehigh.csv',bw_units=None, pkt_units=None)



	sip_bw_trends_chart = convert_csv_to_list_of_lists(charts_tables_path + 'sip_bandwidth_per_day_chart_alltimehigh.csv')
	# sip_bw_trends_chart = convert_bw_units(sip_bw_trends_chart, sip_bw_units)
	# sip_bw_trends_move_text = trends_move(sip_bw_trends_chart, sip_bw_units)
	sip_bw_table = csv_to_html_table(charts_tables_path + 'sip_bandwidth_per_day_table_alltimehigh.csv')



	############################################### Top destination IP ##########################################################

	# Count occurrences of each destination IP
	dip_top_events_df = (
		data_month['destAddress']
		.value_counts()
		.drop(['Multiple', '0.0.0.0'], errors='ignore')
		.nlargest(top_n)
		.sort_values(ascending=False)
	)

	# Format as list of lists for Google Charts
	# The first list is the header
	dip_events_chart_data = [['Destination IP', 'Number of attack events']] + dip_top_events_df.reset_index().values.tolist()

	if bar_charts_annotations:
		dip_events_chart_data[0].append({'role': 'annotation'})
			
		# Add the third column (annotation) to each row
		for row in dip_events_chart_data[1:]:
			row.append(int(row[1]))  



	###################### Dest IP Packets #########################
	# Group by destination IP and sum the packets
	dip_top_packets_df = (
		data_month.groupby('destAddress')['packetCount']
		.sum()
		.drop(['Multiple', '0.0.0.0'], errors='ignore')
		.nlargest(top_n)
		.sort_values(ascending=False)
	)

	# Format for Google Charts
	dip_packets_chart_data = [['Destination IP', 'Packets(cumulative)']] + dip_top_packets_df.reset_index().values.tolist()


	if bar_charts_annotations:
		dip_packets_chart_data[0].append({'role': 'annotation'})
			
		# Add the third column (annotation) to each row
		for row in dip_packets_chart_data[1:]:
			row.append(int(row[1]))



	##################### Dest IP Bandwidth #########################

	# Group by destination IP and sum the bandwidth (in kilobits), convert to MB
	dip_top_bandwidth_df = (
		data_month.groupby('destAddress')['packetBandwidth']
		.sum()
		.drop(['Multiple', '0.0.0.0'], errors='ignore')
		.nlargest(top_n)
		.sort_values(ascending=False)
	)

	dip_top_bandwidth_df = (dip_top_bandwidth_df * 0.000125).round(2)  # Convert to MB

	# Prepare Google Charts data
	dip_bandwidth_chart_data = [['Destination IP', 'Volume (MB)']] + dip_top_bandwidth_df.reset_index().values.tolist()

	if bar_charts_annotations:
		dip_bandwidth_chart_data[0].append({'role': 'annotation'})
			
		# Add the third column (annotation) to each row
		for row in dip_bandwidth_chart_data[1:]:
			row.append(int(row[1]))


	# Generate the HTML page with the data
	html_page = f"""
	<!DOCTYPE html>
	<html lang="en">
	<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">

	  <script type="text/javascript" src="https://www.gstatic.com/charts/loader.js"></script>
		<script type="text/javascript">
		  google.charts.load('current', {{'packages':['corechart']}});
		  google.charts.setOnLoadCallback(drawChart);

			var default_google_colors = [
				"#3366cc", "#dc3912", "#ff9900", "#109618", "#990099", "#0099c6",
				"#dd4477", "#66aa00", "#b82e2e", "#316395", "#994499", "#22aa99",
				"#aaaa11", "#6633cc", "#e67300", "#8b0707", "#651067", "#329262",
				"#5574a6", "#3b3eac", "#b77322", "#16d620", "#b91383", "#f4359e",
				"#9c5935", "#a9c413", "#2a778d", "#668d1c", "#bea413", "#0c5922", "#743411"
			];

			var purple_colors = [
				"#990099", "#6633cc", "#994499", "#651067", "#3b3eac", 
				"#b91383", "#f4359e", "#743411", "#800080", "#6a0dad", 
				"#8b008b", "#9370db", "#ba55d3", "#9400d3", "#9932cc", 
				"#4b0082", "#7b68ee", "#8a2be2", "#dda0dd", "#ee82ee"
			];


			// Function to generate an array of the same red color for all series for attacks data
			function generateSameRedColor(numColors) {{
				return Array(numColors).fill('rgb(200, 0, 0)'); // All red
			}}

			function generateGradientBlueColors(numColors) {{
				return Array.from({{ length: numColors }}, (_, i) => {{
					let blueIntensity = Math.max(120, 200 - i * 20); // Decrease blue intensity for contrast
					let redComponent = Math.min(50 + i * 5, 80); // Slight increase in red for variety
					let greenComponent = Math.min(100 + i * 5, 130); // Slight increase in green for contrast
					return `rgb(${{redComponent}}, ${{greenComponent}}, ${{blueIntensity}})`;
				}});
			}}


			// Determine the number of series dynamically for attack data for coloring based on attack data
			var numSeries = {number_of_devices};
			var redColors = generateSameRedColor(numSeries);
			var blueColors = generateGradientBlueColors(numSeries);
			var redBlueColors = [...blueColors, ...redColors]; // Merge both color sets


		  var colorMap = {{}}; // Store colors globally

		  let debounceTimeout;
		  let chart;

		  function drawChart() {{
		  
			
			// Convert epoch timestamps to Date objects before passing to Google Charts
			var raw_traffic_per_device_combined_trends_bps_data = {traffic_per_device_combined_trends_bps}.map(row => {{
				return [new Date(row[0]), ...row.slice(1)]; // Convert first column, keep others unchanged
			}});


			
			// Convert epoch timestamps to Date objects before passing to Google Charts
			var raw_traffic_per_device_combined_trends_pps_data = {traffic_per_device_combined_trends_pps}.map(row => {{
				return [new Date(row[0]), ...row.slice(1)]; // Convert first column, keep others unchanged
			}});


			// Convert epoch timestamps to Date objects before passing to Google Charts
			var raw_cps_per_device_combined_trends_data = {cps_per_device_combined_trends}.map(row => {{
				return [new Date(row[0]), ...row.slice(1)]; // Convert first column, keep others unchanged
			}});

			// Convert epoch timestamps to Date objects before passing to Google Charts
			var raw_cec_per_device_combined_trends_data = {cec_per_device_combined_trends}.map(row => {{
				return [new Date(row[0]), ...row.slice(1)]; // Convert first column, keep others unchanged
			}});

			// Convert epoch timestamps to Date objects before passing to Google Charts
			var raw_excluded_per_device_combined_trends_bps_data = {excluded_per_device_combined_trends_bps}.map(row => {{
				return [new Date(row[0]), ...row.slice(1)]; // Convert first column, keep others unchanged
			}});

			// Convert epoch timestamps to Date objects before passing to Google Charts
			var raw_excluded_per_device_combined_trends_pps_data = {excluded_per_device_combined_trends_pps}.map(row => {{
				return [new Date(row[0]), ...row.slice(1)]; // Convert first column, keep others unchanged
			}});


			var traffic_per_device_combined_trends_bps_data = google.visualization.arrayToDataTable(raw_traffic_per_device_combined_trends_bps_data);
			var traffic_per_device_combined_trends_pps_data = google.visualization.arrayToDataTable(raw_traffic_per_device_combined_trends_pps_data);

				


			var cps_per_device_combined_trends_data = google.visualization.arrayToDataTable(raw_cps_per_device_combined_trends_data);
			var cec_per_device_combined_trends_data = google.visualization.arrayToDataTable(raw_cec_per_device_combined_trends_data);

			var excluded_per_device_combined_trends_bps_data = google.visualization.arrayToDataTable(raw_excluded_per_device_combined_trends_bps_data);
			var excluded_per_device_combined_trends_pps_data = google.visualization.arrayToDataTable(raw_excluded_per_device_combined_trends_pps_data);

			var maxpps_per_day_data = google.visualization.arrayToDataTable({maxpps_per_day_trends});
			var maxbps_per_day_data = google.visualization.arrayToDataTable({maxbps_per_day_trends});

			var events_per_day_data = google.visualization.arrayToDataTable({events_per_day_trends});
			var packets_per_day_data = google.visualization.arrayToDataTable({packets_per_day_trends});
			var bandwidth_per_day_data = google.visualization.arrayToDataTable({bandwidth_per_day_trends});

			var events_per_day_data_alltimehigh = google.visualization.arrayToDataTable({events_trends_alltimehigh});
			var packets_per_day_data_alltimehigh = google.visualization.arrayToDataTable({packets_trends_chart_alltimehigh});
			var bandwidth_per_day_data_alltimehigh = google.visualization.arrayToDataTable({bw_trends_alltimehigh});

			var events_per_day_by_device_data = google.visualization.arrayToDataTable({events_by_device_trends_chart_data});
			var packets_per_day_by_device_data = google.visualization.arrayToDataTable({packets_by_device_trends_chart_data});
			var bandwidth_per_day_by_device_data = google.visualization.arrayToDataTable({bw_by_device_trends_chart_data});

			var sip_events_per_day_data = google.visualization.arrayToDataTable({sip_events_trends_chart});
			var sip_packets_per_day_data = google.visualization.arrayToDataTable({sip_packets_trends_chart});
			var sip_bandwidth_per_day_data = google.visualization.arrayToDataTable({sip_bw_trends_chart});

			var dip_events_bar_chart_data = google.visualization.arrayToDataTable({dip_events_chart_data});
			var dip_packets_bar_chart_data = google.visualization.arrayToDataTable({dip_packets_chart_data});
			var dip_bandwidth_bar_chart_data = google.visualization.arrayToDataTable({dip_bandwidth_chart_data});

			var policy_events_per_day_data = google.visualization.arrayToDataTable({policy_events_trends_chart });
			var policy_packets_per_day_data = google.visualization.arrayToDataTable({policy_packets_trends_chart });
			var policy_bandwidth_per_day_data = google.visualization.arrayToDataTable({policy_bw_trends_chart });

			var traffic_per_device_combined_trends_bps_options = {{
				title: 'Traffic and Attack Volume for each DefensePro',
				vAxis: {{
					title: 'Traffic and Attack Volume (Mbps)',
					minValue: 0
					}},
				hAxis: {{
					title: 'Date and time'
					}},
				isStacked: false,
				colors: redBlueColors,
				focusTarget: 'category',
				legend: {{position: 'top', maxLines: 10}},
				width: '100%',
				explorer: {{
					actions: ['dragToZoom', 'rightClickToReset'],
					axis: 'horizontal',
					maxZoomIn: 0.001,
					maxZoomOut: 20
					}}
				}};


			var traffic_per_device_combined_trends_pps_options = {{
				title: 'Traffic and Atttack Rate for each DefensePro',
				vAxis: {{
					title: 'Traffic and Attack Rate (PPS)',
					minValue: 0
					}},
				hAxis: {{
					title: 'Date and time'
					}},
				isStacked: false,
				colors: redBlueColors,
				focusTarget: 'category',
				legend: {{position: 'top', maxLines: 10}},
				width: '100%',
				explorer: {{
					actions: ['dragToZoom', 'rightClickToReset'],
					axis: 'horizontal',
					maxZoomIn: 0.001,
					maxZoomOut: 20
					}}
				}};

				
			var cps_per_device_combined_trends_options = {{
				title: 'Connections Per Second per device',
				vAxis: {{
					title: 'Number of Connections Per Second(CPS)',
					minValue: 0
					}},
				hAxis: {{
					title: 'Date and time'
					}},
				isStacked: false,
				colors: blueColors,
				focusTarget: 'category',
				legend: {{position: 'top', maxLines: 5}},
				width: '100%',
				explorer: {{
					actions: ['dragToZoom', 'rightClickToReset'],
					axis: 'horizontal',
					maxZoomIn: 0.001,
					maxZoomOut: 20
					}}
				}};

			var cec_per_device_combined_trends_options = {{
				title: 'Concurrent Established Connections Per per device',
				vAxis: {{
					title: 'Number of Concurrent Established Connections',
					minValue: 0
					}},
				hAxis: {{
					title: 'Date and time'
					}},
				isStacked: false,
				colors: blueColors,
				focusTarget: 'category',
				legend: {{position: 'top', maxLines: 5}},
				width: '100%',
				explorer: {{
					actions: ['dragToZoom', 'rightClickToReset'],
					axis: 'horizontal',
					maxZoomIn: 0.001,
					maxZoomOut: 20
					}}
				}};

			var excluded_per_device_combined_trends_bps_options = {{
				title: 'Excluded Uninspected Traffic Volume by DefensePro',
				vAxis: {{
					title: 'Excluded Uninspected Traffic (Mbps)',
					minValue: 0
					}},
				hAxis: {{
					title: 'Date and time'
					}},
				isStacked: false,
				colors: purple_colors,
				focusTarget: 'category',
				legend: {{position: 'top', maxLines: 10}},
				width: '100%',
				explorer: {{
					actions: ['dragToZoom', 'rightClickToReset'],
					axis: 'horizontal',
					maxZoomIn: 0.001,
					maxZoomOut: 20
					}}
				}};

			var excluded_per_device_combined_trends_pps_options = {{
				title: 'Excluded Uninspected Traffic Rate by DefensePro',
				vAxis: {{
					title: 'Excluded Uninspected Traffic (PPS)',
					minValue: 0
					}},
				hAxis: {{
					title: 'Date and time'
					}},
				isStacked: false,
				colors: purple_colors,
				focusTarget: 'category',
				legend: {{position: 'top', maxLines: 10}},
				width: '100%',
				explorer: {{
					actions: ['dragToZoom', 'rightClickToReset'],
					axis: 'horizontal',
					maxZoomIn: 0.001,
					maxZoomOut: 20
					}}
				}};
				
			var maxpps_per_day_options = {{
			  title: 'Highest PPS rate attack of the day',
			  vAxis: {{
				minValue: 0,
				title: 'Max Attack Rate (PPS) ',
				}},
			  hAxis: {{
				ticks: maxpps_per_day_data.getDistinctValues(0),minTextSpacing:1,showTextEvery:1,
				title: 'Day of the Month'
				}},
			  isStacked: false,
			  legend: {{position: 'top', maxLines: 5}},
			  width: '100%'
			}};

			var maxbps_per_day_options = {{
			  title: 'Highest volume attack of the day',
			  vAxis: {{
				minValue: 0,
				title: 'Max Attack Rate({bps_units_desc})'
				}},
			  hAxis: {{
				ticks: maxbps_per_day_data.getDistinctValues(0),minTextSpacing:1,showTextEvery:1,
				title: 'Day of the Month'
				}},
			  isStacked: false,
			  legend: {{position: 'top', maxLines: 5}},
			  width: '100%'
			}};
			
			var events_per_day_options = {{
			  title: 'Attack Events per day',
			  vAxis: {{
				minValue: 0,
				title: 'Number of Attack Events'
				}},
			  hAxis: {{
				ticks: events_per_day_data.getDistinctValues(0),minTextSpacing:1,showTextEvery:1,
				title: 'Day of the Month'
				}},
			  isStacked: false,
			  legend: {{position: 'top', maxLines: 5}},
			  width: '100%'
			}};

			  var packets_per_day_options = {{
			  title: 'Cumulative Attack packets per day',
			  vAxis: {{
				minValue: 0,
				title: 'Packet units - {pkt_units}'
				}},
			  hAxis: {{
				ticks: packets_per_day_data.getDistinctValues(0),minTextSpacing:1,showTextEvery:1,
				title: 'Day of the Month'
				}},
			  isStacked: false,
			  legend: {{position: 'top', maxLines: 5}},
			  width: '100%'
			}};

			var bandwidth_per_day_options = {{
			  title: 'Cumulative Attack Volume per day',
			  vAxis: {{
				minValue: 0,
				title:'{bw_units}',
				}},
			  hAxis: {{
				ticks: bandwidth_per_day_data.getDistinctValues(0),minTextSpacing:1,showTextEvery:1,
				title: 'Day of the Month'
				}},
			  isStacked: false,
			  legend: {{position: 'top', maxLines: 5}},
			  width: '100%'
			}};

			var attack_events_per_day_options = {{
			  title: 'Attack Events trends - TopN by last day',
			  vAxis: {{minValue: 0}},
			  hAxis: {{ticks: events_per_day_data.getDistinctValues(0),minTextSpacing:1,showTextEvery:1}},
			  isStacked: false,
			  focusTarget: 'category',
			  legend: {{position: 'top', maxLines: 5}},
			  width: '100%'
			}};


			var attack_packets_per_day_options = {{
			  title: 'Attack packets trends (units {pkt_units}) - TopN by last day',
			  vAxis: {{minValue: 0}},
			  hAxis: {{ticks: events_per_day_data.getDistinctValues(0),minTextSpacing:1,showTextEvery:1}},
			  isStacked: false,
			  focusTarget: 'category',
			  legend: {{position: 'top', maxLines: 5}},
			  width: '100%'
			}};

			var attack_bandwidth_per_day_options = {{
			  title: 'Attack Volume trends (units {bw_units}) - TopN by last day',
			  vAxis: {{minValue: 0}},
			  hAxis: {{ticks: events_per_day_data.getDistinctValues(0),minTextSpacing:1,showTextEvery:1}},
			  isStacked: false,
			  focusTarget: 'category',
			  legend: {{position: 'top', maxLines: 5}},
			  width: '100%'
			}};



			var events_per_day_options_alltimehigh = {{
			  title: 'Attack Events trends',
			  vAxis: {{
				minValue: 0,
				title: 'Number of Attack Events'
				}},
			  hAxis: {{
				ticks: events_per_day_data.getDistinctValues(0),minTextSpacing:1,showTextEvery:1,
				title: 'Day of the Month'
				}},
			  isStacked: false,
			  colors: default_google_colors,
			  focusTarget: 'category',
			  legend: {{position: 'top', maxLines: 5}},
			  width: '100%'
			}};

			var packets_per_day_options_alltimehigh = {{
			  title: 'Cumulative Attack packets by attack vector',
			  vAxis: {{
				minValue: 0,
				title: 'Packet units - {pkt_units}'
				}},
			  hAxis: {{
				ticks: events_per_day_data.getDistinctValues(0),minTextSpacing:1,showTextEvery:1,
				title: 'Day of the Month'
				}},
			  isStacked: false,
			  focusTarget: 'category',
			  legend: {{position: 'top', maxLines: 5}},
			  width: '100%'
			}};

			var bandwidth_per_day_options_alltimehigh = {{
			  title: 'Cumulative Attack Volume by attack vector',
			  vAxis: {{
				minValue: 0,
				title:'{bw_units}'
				}},
			  isStacked: false,
			  hAxis: {{
				ticks: bandwidth_per_day_data.getDistinctValues(0),minTextSpacing:1,showTextEvery:1,
				title: 'Day of the Month'
				}},
			  focusTarget: 'category',
			  legend: {{position: 'top', maxLines: 5}},
			  width: '100%'
			}};

			var events_per_day_by_device_options = {{
			  title: 'Attack Events by DefensePro trends',
			  vAxis: {{
				minValue: 0,
				title: 'Number of Attack Events'
				}},
			  hAxis: {{
				ticks: events_per_day_data.getDistinctValues(0),minTextSpacing:1,showTextEvery:1,
				title: 'Day of the Month'
				}},			  isStacked: false,
			  focusTarget: 'category',
			  legend: {{position: 'top', maxLines: 5}},
			  width: '100%'
			}};

			var packets_per_day_by_device_options = {{
			  title: 'Cumulative Packets by DefensePro',
			  vAxis: {{
				minValue: 0,
				title: 'Packet units - {pkt_units}'
				}},
			  hAxis: {{
				ticks: events_per_day_data.getDistinctValues(0),minTextSpacing:1,showTextEvery:1,
				title: 'Day of the Month'
				}},
			  isStacked: false,
			  focusTarget: 'category',
			  legend: {{position: 'top', maxLines: 5}},
			  width: '100%'
			}};

			var bandwidth_per_day_by_device_options = {{
			  title: 'Cumulative Attack Volume by DefensePro',
			  vAxis: {{
				minValue: 0,
				title:'{bw_units}'
				}},
			  hAxis: {{
				ticks: events_per_day_data.getDistinctValues(0),minTextSpacing:1,showTextEvery:1,
				title: 'Day of the Month'
				}},
			  isStacked: false,
			  focusTarget: 'category',
			  legend: {{position: 'top', maxLines: 5}},
			  width: '100%'
			}};

			var sip_events_per_day_options = {{
			  title: 'Attack Events trends by source IP',
			  vAxis: {{
				minValue: 0,
				title: 'Number of Attack Events'
				}},
			  hAxis: {{
				ticks: events_per_day_data.getDistinctValues(0),minTextSpacing:1,showTextEvery:1,
				title: 'Day of the Month'
				}},
			  isStacked: false,
			  focusTarget: 'category',
			  legend: {{position: 'top', maxLines: 5}},
			  width: '100%'
			}};

			var sip_packets_per_day_options = {{
			  title: 'Cumulative Attack packets by Source IP',
			  vAxis: {{
				minValue: 0,
				title: 'Packet units - {pkt_units}'
				}},
			  hAxis: {{
				ticks: events_per_day_data.getDistinctValues(0),minTextSpacing:1,showTextEvery:1,
				title: 'Day of the Month'
				}},
			  isStacked: false,
			  focusTarget: 'category',
			  legend: {{position: 'top', maxLines: 5}},
			  width: '100%'
			}};

			var sip_bandwidth_per_day_options = {{
			  title: 'Cumulative Attack Volume by Source IP',
			  vAxis: {{
				minValue: 0,
				title:'Megabytes'
				}},
			  hAxis: {{
				ticks: events_per_day_data.getDistinctValues(0),minTextSpacing:1,showTextEvery:1,
				title: 'Day of the Month'
				}},
			  isStacked: false,
			  focusTarget: 'category',
			  legend: {{position: 'top', maxLines: 5}},
			  width: '100%'
			}};

			var dip_events_bar_chart_options = {{
			  title: 'Attack Events by Destination IP',
			  bar: {{
				groupWidth: "70%"
				}},
			  legend: {{
				position: 'bottom'
				}},
			  vAxis: {{
				minValue: 0,
				title:'Attacked Destination IP'
				}},
			  annotations: {{
            	alwaysOutside: true
				}},
			  width: '100%'
			}};

			var dip_packets_bar_chart_options = {{
			  title: 'Cumulative Attack packets by Destination IP',
			  bar: {{
				groupWidth: "70%"
				}},
			  legend: {{
				position: 'bottom'
				}},
			  vAxis: {{
				minValue: 0,
				title:'Attacked Destination IP'
				}},
			  annotations: {{
            	alwaysOutside: true
				}},
			  width: '100%'
			}};

			var dip_bandwidth_bar_chart_options = {{
			  title: 'Cumulative Attack Volume by Destination IP',
			  bar: {{
				groupWidth: "70%"
				}},
			  legend: {{
				position: 'bottom'
				}},
			  vAxis: {{
				minValue: 0,
				title:'Attacked Destination IP'
				}},
			  annotations: {{
            	alwaysOutside: true
				}},
			  width: '100%'
			}};


			var policy_events_per_day_options = {{
			  title: 'Attack Events trends by Policy Name',
			  vAxis: {{
				minValue: 0,
				title: 'Number of Attack Events'
				}},
			  hAxis: {{
				ticks: events_per_day_data.getDistinctValues(0),minTextSpacing:1,showTextEvery:1,
				title: 'Day of the Month'
				}},
			  isStacked: false,
			  focusTarget: 'category',
			  legend: {{position: 'top', maxLines: 5}},
			  width: '100%'
			}};

			var policy_packets_per_day_options = {{
			  title: 'Cumulative Attack packets by policy',
			  vAxis: {{
				minValue: 0,
				title: 'Packet units - {pkt_units}'
				}},
			  hAxis: {{
				ticks: events_per_day_data.getDistinctValues(0),minTextSpacing:1,showTextEvery:1,
				title: 'Day of the Month'
				}},
			  isStacked: false,
			  focusTarget: 'category',
			  legend: {{position: 'top', maxLines: 5}},
			  width: '100%'
			}};

			var policy_bandwidth_per_day_options = {{
			  title: 'Cumulative Attack Volume by policy',
			  vAxis: {{
				minValue: 0,
				title:'{bw_units}'
				}},
			  hAxis: {{
				ticks: events_per_day_data.getDistinctValues(0),minTextSpacing:1,showTextEvery:1,
				title: 'Day of the Month'
				}},
			  isStacked: false,
			  focusTarget: 'category',
			  legend: {{position: 'top', maxLines: 5}},
			  width: '100%'
			}};

			var traffic_per_device_combined_trends_bps_chart = new google.visualization.AreaChart(document.getElementById('traffic_per_device_combined_trends_bps_chart_div'));

			var traffic_per_device_combined_trends_pps_chart = new google.visualization.AreaChart(document.getElementById('traffic_per_device_combined_trends_pps_chart_div'));
					
			
			var cps_per_device_combined_trends_chart = new google.visualization.AreaChart(document.getElementById('cps_per_device_combined_trends_chart_div'));

			var cec_per_device_combined_trends_chart = new google.visualization.AreaChart(document.getElementById('cec_per_device_combined_trends_chart_div'));

			var excluded_per_device_combined_trends_bps_chart = new google.visualization.AreaChart(document.getElementById('excluded_per_device_combined_trends_bps_chart_div'));
			var excluded_per_device_combined_trends_pps_chart = new google.visualization.AreaChart(document.getElementById('excluded_per_device_combined_trends_pps_chart_div'));

			var maxpps_per_day_chart = new google.visualization.AreaChart(document.getElementById('maxpps_per_day_chart_div'));
			var maxbps_per_day_chart = new google.visualization.AreaChart(document.getElementById('maxbps_per_day_chart_div'));

			var events_per_day_chart = new google.visualization.AreaChart(document.getElementById('events_per_day_chart_div'));
			var bandwidth_per_day_chart = new google.visualization.AreaChart(document.getElementById('bandwidth_per_day_chart_div'));
			var packets_per_day_chart = new google.visualization.AreaChart(document.getElementById('packets_per_day_chart_div'));

			var events_per_day_chart_alltimehigh = new google.visualization.AreaChart(document.getElementById('events_per_day_chart_div_alltimehigh'));
			var packets_per_day_chart_alltimehigh = new google.visualization.AreaChart(document.getElementById('packets_per_day_chart_div_alltimehigh'));
			var bandwidth_per_day_chart_alltimehigh = new google.visualization.AreaChart(document.getElementById('bandwidth_per_day_chart_div_alltimehigh'));

			var events_per_day_by_device_chart = new google.visualization.AreaChart(document.getElementById('events_per_day_by_device_chart_div'));
			var packets_per_day_by_device_chart = new google.visualization.AreaChart(document.getElementById('packets_per_day_by_device_chart_div'));
			var bandwidth_per_day_by_device_chart = new google.visualization.AreaChart(document.getElementById('bandwidth_per_day_by_device_chart_div'));

			var sip_events_per_day_chart = new google.visualization.AreaChart(document.getElementById('sip_events_per_day_chart_div'));
			var sip_packets_per_day_chart = new google.visualization.AreaChart(document.getElementById('sip_packets_per_day_chart_div'));
			var sip_bandwidth_per_day_chart = new google.visualization.AreaChart(document.getElementById('sip_bandwidth_per_day_chart_div'));		

			var dip_events_bar_chart = new google.visualization.BarChart(document.getElementById('dip_events_bar_chart_div'));		
			var dip_packets_bar_chart = new google.visualization.BarChart(document.getElementById('dip_packets_bar_chart_div'));
			var dip_bandwidth_bar_chart = new google.visualization.BarChart(document.getElementById('dip_bandwidth_bar_chart_div'));

			var policy_events_per_day_chart = new google.visualization.AreaChart(document.getElementById('policy_events_per_day_chart_div'));
			var policy_packets_per_day_chart = new google.visualization.AreaChart(document.getElementById('policy_packets_per_day_chart_div'));
			var policy_bandwidth_per_day_chart = new google.visualization.AreaChart(document.getElementById('policy_bandwidth_per_day_chart_div'));

            // Create checkboxes for Traffic utilization BPS per device combined
            createCheckboxes('traffic_per_device_combined_trends_bps_chart_div', raw_traffic_per_device_combined_trends_bps_data, traffic_per_device_combined_trends_bps_options, function(selectedCategories) {{
                var filteredData = filterDataByCategories(raw_traffic_per_device_combined_trends_bps_data, selectedCategories);
                var filteredDataTable = google.visualization.arrayToDataTable(filteredData);
                traffic_per_device_combined_trends_bps_chart.draw(filteredDataTable, traffic_per_device_combined_trends_bps_options);
            }});


            // Create checkboxes for Traffic utilization PPS per device combined
            createCheckboxes('traffic_per_device_combined_trends_pps_chart_div', raw_traffic_per_device_combined_trends_pps_data, traffic_per_device_combined_trends_pps_options, function(selectedCategories) {{
                var filteredData = filterDataByCategories(raw_traffic_per_device_combined_trends_pps_data, selectedCategories);
                var filteredDataTable = google.visualization.arrayToDataTable(filteredData);
                traffic_per_device_combined_trends_pps_chart.draw(filteredDataTable, traffic_per_device_combined_trends_pps_options);
            }});


            // Create checkboxes for CPS per device combined
            createCheckboxes('cps_per_device_combined_trends_chart_div', raw_cps_per_device_combined_trends_data, cps_per_device_combined_trends_options, function(selectedCategories) {{
                var filteredData = filterDataByCategories(raw_cps_per_device_combined_trends_data, selectedCategories);
                var filteredDataTable = google.visualization.arrayToDataTable(filteredData);
                cps_per_device_combined_trends_chart.draw(filteredDataTable, cps_per_device_combined_trends_options);
            }});

            // Create checkboxes for Concurrent Established Connections (CEC) per device combined
            createCheckboxes('cec_per_device_combined_trends_chart_div', raw_cec_per_device_combined_trends_data, cec_per_device_combined_trends_options, function(selectedCategories) {{
                var filteredData = filterDataByCategories(raw_cec_per_device_combined_trends_data, selectedCategories);
                var filteredDataTable = google.visualization.arrayToDataTable(filteredData);
                cec_per_device_combined_trends_chart.draw(filteredDataTable, cec_per_device_combined_trends_options);
            }});

            // Create checkboxes for Excluded BPS per device combined
            createCheckboxes('excluded_per_device_combined_trends_bps_chart_div', raw_excluded_per_device_combined_trends_bps_data, excluded_per_device_combined_trends_bps_options, function(selectedCategories) {{
                var filteredData = filterDataByCategories(raw_excluded_per_device_combined_trends_bps_data, selectedCategories);
                var filteredDataTable = google.visualization.arrayToDataTable(filteredData);
                excluded_per_device_combined_trends_bps_chart.draw(filteredDataTable, excluded_per_device_combined_trends_bps_options);
            }});

            // Create checkboxes for Excluded PPS per device combined
            createCheckboxes('excluded_per_device_combined_trends_pps_chart_div', raw_excluded_per_device_combined_trends_pps_data, excluded_per_device_combined_trends_pps_options, function(selectedCategories) {{
                var filteredData = filterDataByCategories(raw_excluded_per_device_combined_trends_pps_data, selectedCategories);
                var filteredDataTable = google.visualization.arrayToDataTable(filteredData);
                excluded_per_device_combined_trends_pps_chart.draw(filteredDataTable, excluded_per_device_combined_trends_pps_options);
            }});

			createCheckboxes('events_per_day_chart_div_alltimehigh', {events_trends_alltimehigh}, events_per_day_options_alltimehigh, function(selectedCategories) {{
				var filteredData = filterDataByCategories({events_trends_alltimehigh}, selectedCategories);
				var filteredDataTable = google.visualization.arrayToDataTable(filteredData);
				events_per_day_chart_alltimehigh.draw(filteredDataTable, events_per_day_options_alltimehigh);
			}});

			createCheckboxes('packets_per_day_chart_div_alltimehigh', {packets_trends_chart_alltimehigh}, packets_per_day_options_alltimehigh, function(selectedCategories) {{
				var filteredData = filterDataByCategories({packets_trends_chart_alltimehigh}, selectedCategories);
				var filteredDataTable = google.visualization.arrayToDataTable(filteredData);
				packets_per_day_chart_alltimehigh.draw(filteredDataTable, packets_per_day_options_alltimehigh);
			}});

			createCheckboxes('bandwidth_per_day_chart_div_alltimehigh', {bw_trends_alltimehigh}, bandwidth_per_day_options_alltimehigh, function(selectedCategories) {{
				var filteredData = filterDataByCategories({bw_trends_alltimehigh}, selectedCategories);
				var filteredDataTable = google.visualization.arrayToDataTable(filteredData);
				bandwidth_per_day_chart_alltimehigh.draw(filteredDataTable, bandwidth_per_day_options_alltimehigh);
			}});

			createCheckboxes('events_per_day_by_device_chart_div', {events_by_device_trends_chart_data}, events_per_day_by_device_options, function(selectedCategories) {{
				var filteredData = filterDataByCategories({events_by_device_trends_chart_data}, selectedCategories);
				var filteredDataTable = google.visualization.arrayToDataTable(filteredData);
				events_per_day_by_device_chart.draw(filteredDataTable, events_per_day_by_device_options);
			}});

			createCheckboxes('packets_per_day_by_device_chart_div', {packets_by_device_trends_chart_data}, packets_per_day_by_device_options, function(selectedCategories) {{
				var filteredData = filterDataByCategories({packets_by_device_trends_chart_data}, selectedCategories);
				var filteredDataTable = google.visualization.arrayToDataTable(filteredData);
				packets_per_day_by_device_chart.draw(filteredDataTable, packets_per_day_by_device_options);
			}});

			createCheckboxes('bandwidth_per_day_by_device_chart_div', {bw_by_device_trends_chart_data}, bandwidth_per_day_by_device_options, function(selectedCategories) {{
				var filteredData = filterDataByCategories({bw_by_device_trends_chart_data}, selectedCategories);
				var filteredDataTable = google.visualization.arrayToDataTable(filteredData);
				bandwidth_per_day_by_device_chart.draw(filteredDataTable, bandwidth_per_day_by_device_options);
			}});

			createCheckboxes('sip_events_per_day_chart_div', {sip_events_trends_chart}, sip_events_per_day_options, function(selectedCategories) {{
				var filteredData = filterDataByCategories({sip_events_trends_chart}, selectedCategories);
				var filteredDataTable = google.visualization.arrayToDataTable(filteredData);
				sip_events_per_day_chart.draw(filteredDataTable, sip_events_per_day_options);
			}});

			createCheckboxes('sip_packets_per_day_chart_div', {sip_packets_trends_chart}, sip_packets_per_day_options, function(selectedCategories) {{
				var filteredData = filterDataByCategories({sip_packets_trends_chart}, selectedCategories);
				var filteredDataTable = google.visualization.arrayToDataTable(filteredData);
				sip_packets_per_day_chart.draw(filteredDataTable, sip_packets_per_day_options);
			}});

			createCheckboxes('sip_bandwidth_per_day_chart_div', {sip_bw_trends_chart}, sip_bandwidth_per_day_options, function(selectedCategories) {{
				var filteredData = filterDataByCategories({sip_bw_trends_chart}, selectedCategories);
				var filteredDataTable = google.visualization.arrayToDataTable(filteredData);
				sip_bandwidth_per_day_chart.draw(filteredDataTable, sip_bandwidth_per_day_options);
			}});

			createCheckboxes('policy_events_per_day_chart_div', {policy_events_trends_chart}, policy_events_per_day_options, function(selectedCategories) {{
				var filteredData = filterDataByCategories({policy_events_trends_chart}, selectedCategories);
				var filteredDataTable = google.visualization.arrayToDataTable(filteredData);
				policy_events_per_day_chart.draw(filteredDataTable, policy_events_per_day_options);
			}});

			createCheckboxes('policy_packets_per_day_chart_div', {policy_packets_trends_chart}, policy_packets_per_day_options, function(selectedCategories) {{
				var filteredData = filterDataByCategories({policy_packets_trends_chart}, selectedCategories);
				var filteredDataTable = google.visualization.arrayToDataTable(filteredData);
				policy_packets_per_day_chart.draw(filteredDataTable, policy_packets_per_day_options);
			}});

			createCheckboxes('policy_bandwidth_per_day_chart_div', {policy_bw_trends_chart}, policy_bandwidth_per_day_options, function(selectedCategories) {{
				var filteredData = filterDataByCategories({policy_bw_trends_chart}, selectedCategories);
				var filteredDataTable = google.visualization.arrayToDataTable(filteredData);
				policy_bandwidth_per_day_chart.draw(filteredDataTable, policy_bandwidth_per_day_options);
			}});

			// Draw charts with consistent colors
			traffic_per_device_combined_trends_bps_chart.draw(traffic_per_device_combined_trends_bps_data, traffic_per_device_combined_trends_bps_options);

			traffic_per_device_combined_trends_pps_chart.draw(traffic_per_device_combined_trends_pps_data, traffic_per_device_combined_trends_pps_options);

			cps_per_device_combined_trends_chart.draw(cps_per_device_combined_trends_data, cps_per_device_combined_trends_options);

			cec_per_device_combined_trends_chart.draw(cec_per_device_combined_trends_data, cec_per_device_combined_trends_options);

			excluded_per_device_combined_trends_bps_chart.draw(excluded_per_device_combined_trends_bps_data, excluded_per_device_combined_trends_bps_options);
			excluded_per_device_combined_trends_pps_chart.draw(excluded_per_device_combined_trends_pps_data, excluded_per_device_combined_trends_pps_options);


			maxpps_per_day_chart.draw(maxpps_per_day_data, maxpps_per_day_options);
			maxbps_per_day_chart.draw(maxbps_per_day_data, maxbps_per_day_options);

			events_per_day_chart.draw(events_per_day_data, events_per_day_options);
			bandwidth_per_day_chart.draw(bandwidth_per_day_data, bandwidth_per_day_options);
			packets_per_day_chart.draw(packets_per_day_data, packets_per_day_options);

			events_per_day_chart_alltimehigh.draw(events_per_day_data_alltimehigh, events_per_day_options_alltimehigh);
			packets_per_day_chart_alltimehigh.draw(packets_per_day_data_alltimehigh, packets_per_day_options_alltimehigh);
			bandwidth_per_day_chart_alltimehigh.draw(bandwidth_per_day_data_alltimehigh, bandwidth_per_day_options_alltimehigh);

			events_per_day_by_device_chart.draw(events_per_day_by_device_data, events_per_day_by_device_options);
			packets_per_day_by_device_chart.draw(packets_per_day_by_device_data, packets_per_day_by_device_options);
			bandwidth_per_day_by_device_chart.draw(bandwidth_per_day_by_device_data, bandwidth_per_day_by_device_options);

			sip_events_per_day_chart.draw(sip_events_per_day_data, sip_events_per_day_options);
			sip_packets_per_day_chart.draw(sip_packets_per_day_data, sip_packets_per_day_options);
			sip_bandwidth_per_day_chart.draw(sip_bandwidth_per_day_data, sip_bandwidth_per_day_options);

			dip_events_bar_chart.draw(dip_events_bar_chart_data, dip_events_bar_chart_options);
			dip_packets_bar_chart.draw(dip_packets_bar_chart_data, dip_packets_bar_chart_options);
			dip_bandwidth_bar_chart.draw(dip_bandwidth_bar_chart_data, dip_bandwidth_bar_chart_options);

			policy_events_per_day_chart.draw(policy_events_per_day_data, policy_events_per_day_options);
			policy_packets_per_day_chart.draw(policy_packets_per_day_data, policy_packets_per_day_options);
			policy_bandwidth_per_day_chart.draw(policy_bandwidth_per_day_data, policy_bandwidth_per_day_options);

			

			// Add radio button toggles for stacked/non-stacked


            addStackedToggle('traffic_per_device_combined_trends_bps_chart_div', traffic_per_device_combined_trends_bps_chart, raw_traffic_per_device_combined_trends_bps_data, traffic_per_device_combined_trends_bps_options);
            addStackedToggle('traffic_per_device_combined_trends_pps_chart_div', traffic_per_device_combined_trends_pps_chart, raw_traffic_per_device_combined_trends_pps_data, traffic_per_device_combined_trends_pps_options);

            addStackedToggle('cps_per_device_combined_trends_chart_div', cps_per_device_combined_trends_chart, raw_cps_per_device_combined_trends_data, cps_per_device_combined_trends_options);
            addStackedToggle('cec_per_device_combined_trends_chart_div', cec_per_device_combined_trends_chart, raw_cec_per_device_combined_trends_data, cec_per_device_combined_trends_options);

            addStackedToggle('excluded_per_device_combined_trends_bps_chart_div', excluded_per_device_combined_trends_bps_chart, raw_excluded_per_device_combined_trends_bps_data, excluded_per_device_combined_trends_bps_options);
			addStackedToggle('excluded_per_device_combined_trends_pps_chart_div', excluded_per_device_combined_trends_pps_chart, raw_excluded_per_device_combined_trends_pps_data, excluded_per_device_combined_trends_pps_options);

			addStackedToggle('events_per_day_chart_div_alltimehigh', events_per_day_chart_alltimehigh, {events_trends_alltimehigh}, events_per_day_options_alltimehigh);
			addStackedToggle('packets_per_day_chart_div_alltimehigh', packets_per_day_chart_alltimehigh, {packets_trends_chart_alltimehigh}, packets_per_day_options_alltimehigh);
			addStackedToggle('bandwidth_per_day_chart_div_alltimehigh', bandwidth_per_day_chart_alltimehigh, {bw_trends_alltimehigh}, bandwidth_per_day_options_alltimehigh);

			addStackedToggle('events_per_day_by_device_chart_div', events_per_day_by_device_chart, {events_by_device_trends_chart_data}, events_per_day_by_device_options);
			addStackedToggle('packets_per_day_by_device_chart_div', packets_per_day_by_device_chart, {packets_by_device_trends_chart_data}, packets_per_day_by_device_options);
			addStackedToggle('bandwidth_per_day_by_device_chart_div', bandwidth_per_day_by_device_chart, {bw_by_device_trends_chart_data}, bandwidth_per_day_by_device_options);

			addStackedToggle('sip_events_per_day_chart_div', sip_events_per_day_chart, {sip_events_trends_chart}, sip_events_per_day_options);
			addStackedToggle('sip_packets_per_day_chart_div', sip_packets_per_day_chart, {sip_packets_trends_chart}, sip_packets_per_day_options);
			addStackedToggle('sip_bandwidth_per_day_chart_div', sip_bandwidth_per_day_chart, {sip_bw_trends_chart}, sip_bandwidth_per_day_options);

			addStackedToggle('policy_events_per_day_chart_div', policy_events_per_day_chart, {policy_events_trends_chart}, policy_events_per_day_options);
			addStackedToggle('policy_packets_per_day_chart_div', policy_packets_per_day_chart, {policy_packets_trends_chart}, policy_packets_per_day_options);
			addStackedToggle('policy_bandwidth_per_day_chart_div', policy_bandwidth_per_day_chart, {policy_bw_trends_chart}, policy_bandwidth_per_day_options);

		  }}

		  
			function updateColorPersistence(containerId, selectedCategories, data, options) {{
				if (!colorMap[containerId]) {{
					colorMap[containerId] = {{}};
				}}

				selectedCategories.forEach((selectedIndex, i) => {{
					let category = data[0][selectedIndex];
					if (!colorMap[containerId][category]) {{
						colorMap[containerId][category] = options.colors[i % options.colors.length];
					}}
				}});

				options.colors = selectedCategories.map(index => colorMap[containerId][data[0][index]]);
			}}


			// Function to create checkboxes
			function createCheckboxes(containerId, data, options, callback) {{
				var container = document.getElementById(containerId);
				var categories = data[0].slice(1); // Extract categories from the first row

				var checkboxContainer = document.createElement('div');
				checkboxContainer.className = 'checkbox-container';

				if (!selectedCategoriesMap[containerId]) {{
					selectedCategoriesMap[containerId] = categories.map((_, i) => i + 1);
				}}

				// Ensure colorMap is initialized
				if (!colorMap[containerId]) {{
					colorMap[containerId] = {{}};
				}}

				// **Prepopulate colorMap to avoid losing colors**
				categories.forEach((category, index) => {{
					if (!colorMap[containerId][category]) {{
						if (options && options.colors) {{
							colorMap[containerId][category] = options.colors[index % options.colors.length];
						}} else {{
							colorMap[containerId][category] = default_google_colors[index % default_google_colors.length]; // Fallback in case options are missing
						}}
					}}
				}});
				// Add "Select All" checkbox
				var selectAllLabel = document.createElement('label');
				var selectAllCheckbox = document.createElement('input');
				selectAllCheckbox.type = 'checkbox';
				selectAllCheckbox.checked = true;
				selectAllCheckbox.id = 'selectAllCheckbox_' + containerId;

				selectAllCheckbox.onchange = function () {{
					var allCheckboxes = checkboxContainer.querySelectorAll('input[type="checkbox"]:not(#' + selectAllCheckbox.id + ')');
					allCheckboxes.forEach(cb => cb.checked = selectAllCheckbox.checked);

					// Update selectedCategoriesMap accordingly
					selectedCategoriesMap[containerId] = selectAllCheckbox.checked
						? categories.map((_, i) => i + 1)
						: [];

					updateColorPersistence(containerId, selectedCategoriesMap[containerId], data, options);

					var filteredData = filterDataByCategories(data, selectedCategoriesMap[containerId]);
					var filteredDataTable = google.visualization.arrayToDataTable(filteredData);
					callback(selectedCategoriesMap[containerId]);
				}};

				selectAllLabel.appendChild(selectAllCheckbox);
				selectAllLabel.appendChild(document.createTextNode('Select All'));
				checkboxContainer.appendChild(selectAllLabel);


				// Generate dynamic checkboxes for each category
				categories.forEach(function(category, index) {{
					var checkbox = document.createElement('input');
					checkbox.type = 'checkbox';
					checkbox.checked = selectedCategoriesMap[containerId].includes(index + 1);
					checkbox.value = index + 1;

			checkbox.onchange = function() {{ 

				var selectedCategories = Array.from(checkboxContainer.querySelectorAll('input[type="checkbox"]:not(#' + selectAllCheckbox.id + '):checked'))
					.map(input => parseInt(input.value));

				selectedCategoriesMap[containerId] = selectedCategories;

				let selectedSet = new Set(selectedCategories);




				updateColorPersistence(containerId, selectedCategories, data, options);



				var filteredData = filterDataByCategories(data, selectedCategories);

				var filteredDataTable = google.visualization.arrayToDataTable(filteredData);

				callback(selectedCategories);

				// Sync "Select All" checkbox
            selectAllCheckbox.checked = selectedCategories.length === categories.length;

			}};


					var label = document.createElement('label');
					label.appendChild(checkbox);
					label.appendChild(document.createTextNode(category));

					checkboxContainer.appendChild(label);
				}});

				container.parentNode.insertBefore(checkboxContainer, container);
			}}


			// Function to filter data based on selected categories
			function filterDataByCategories(data, selectedCategories) {{
				return data.map((row, rowIndex) => rowIndex === 0 
					? [row[0], ...selectedCategories.map(index => row[index])] 
					: [row[0], ...selectedCategories.map(index => row[index])]
				);
			}}


			var selectedCategoriesMap = {{}}; // Global store for checkbox selections per chart
				

			// Function to add Stacked/Non-Stacked toggle via radio buttons
			function addStackedToggle(containerId, chart, rawData, options) {{
				var container = document.getElementById(containerId);
				var radioContainer = document.createElement('div');
				radioContainer.className = 'radio-container';

				var stackedLabel = document.createElement('label');
				var stackedRadio = document.createElement('input');
				stackedRadio.type = 'radio';
				stackedRadio.name = 'stackedToggle_' + containerId;
				stackedRadio.value = 'stacked';

				var nonStackedLabel = document.createElement('label');
				var nonStackedRadio = document.createElement('input');
				nonStackedRadio.type = 'radio';
				nonStackedRadio.name = 'stackedToggle_' + containerId;
				nonStackedRadio.value = 'non-stacked';

				// Set initial state
				stackedRadio.checked = options.isStacked === true;
				nonStackedRadio.checked = options.isStacked === false;

				stackedRadio.onchange = function () {{
					updateChartWithPersistence(containerId, chart, rawData, options, true);
				}};

				nonStackedRadio.onchange = function () {{
					updateChartWithPersistence(containerId, chart, rawData, options, false);
				}};

				stackedLabel.appendChild(stackedRadio);
				stackedLabel.appendChild(document.createTextNode('Stacked'));

				nonStackedLabel.appendChild(nonStackedRadio);
				nonStackedLabel.appendChild(document.createTextNode('Non-Stacked'));

				radioContainer.appendChild(stackedLabel);
				radioContainer.appendChild(nonStackedLabel);

				container.parentNode.insertBefore(radioContainer, container.nextSibling);
			}}


			function getValidData(data) {{
				try {{
					return google.visualization.arrayToDataTable(data);
				}} catch (error) {{
					console.error("Error processing data for stacked toggle:", error);
					return null;
				}}
			}}



			function updateChartWithPersistence(containerId, chart, rawData, options, isStacked) {{
				options.isStacked = isStacked;

				var selectedCategories = selectedCategoriesMap[containerId] || 
										[...Array(rawData[0].length - 1).keys()].map(i => i + 1);

				if ((validData = getValidData(filterDataByCategories(rawData, selectedCategories)))) {{
					chart.draw(validData, options);
				}}
			}}




		// Toggle table visibility on button click
		function toggleTable(tableId, button) {{
			const collapsibleTable = document.getElementById(tableId);

			if (collapsibleTable.style.display === 'none' || collapsibleTable.style.display === '') {{
				collapsibleTable.style.display = 'block';
				button.textContent = 'Hide Details';
				button.classList.add('active');
			}} else {{
				collapsibleTable.style.display = 'none';
				button.textContent = button.getAttribute('data-original-text'); // Restore original text
				button.classList.remove('active');
			}}
		}}

		document.addEventListener("DOMContentLoaded", function () {{
			let button = document.getElementById('backToToc');
			if (!button) return; // Safety check in case the button is missing

			// Show/hide "Back to TOC" button based on scroll position
			window.addEventListener('scroll', function () {{
				if (window.scrollY > 300) {{
					button.classList.remove('hidden'); // Show button when scrolled down
				}} else {{
					button.classList.add('hidden'); // Hide button when near the top
				}}
			}});
		}});

		// Smoothly scroll to the top of the page when button is clicked
		function scrollToToc() {{
		window.scrollTo({{ top: 0, behavior: 'smooth' }}); // Scrolls to the top of the page
		}}

		</script>

	<style>
	  body, html {{
		margin: 0;
		display: block;
		justify-content: center;
		align-items: center;
		background-color: #f0f0f0;
		font-family: Arial, sans-serif;
		font-size: 14px;
	  }}

	
	  
	  table {{
		width: 100%;
		border-collapse: collapse;
		table-layout: fixed;
	  }}

	  
	  th, td {{
		width: 33%;
		text-align: center;
		border: 1px solid black;
		padding: 10px;
	  }}

		/* Table of Contents styles */
			.toc-container {{
			background-color: #fff;
			border: 1px solid #ddd;
			padding: 20px;

			margin: 20px auto; /* Centers the TOC below the previous container */
			box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
			border-radius: 8px;
			z-index: 100;
			}}

			.toc-header {{
			font-size: 18px;
			margin-bottom: 10px;
			text-align: center;
			font-weight: bold;
			}}

			.toc-list {{
			list-style-type: none;
			padding-left: 20px; /* Controls indentation */
			margin: 0;
			}}

			.toc-list li {{
			margin: 10px 0;
			}}

			.toc-list li a {{
			text-decoration: none;
			color: #333;
			font-size: 14px;
			padding: 5px;
			border-radius: 4px;
			display: block;
			transition: background-color 0.3s ease;
			}}

			.toc-list li a:hover {{
			background-color: #f0f0f0;
			}}

		/* Subsection styling */
			.sub-list {{
			list-style-type: none;
			padding-left: 15px; /* Indents nested lists */
			margin: 5px 0;
			}}

			.sub-list li {{
			margin-left: 10px; /* Extra spacing to align better */
			}}
			.sub-list li a {{
			display: block;
			padding: 5px;
			font-size: 13px; /* Slightly smaller font for subsections */
			color: #555;
			}}
			.toc-cell {{
				text-align: left; /* Aligns content to the left */
				border: none;
				vertical-align: top; /* Aligns content to the top */
			}}

			.toc-table {{
				border: none;  /* Remove the border from the table itself */
				width: 100%;
			}}
			/* Add some margin to content to make room for TOC */
			.content {{
			margin-right: 300px; /* Make room for the TOC */
			padding: 20px;
			}}

			/* Adjust the scroll position so headings don't get covered by sticky header */
			h3, h4 {{
			scroll-margin-top: 80px; /* Adjust this value based on your sticky header height */
			}}


			/* Styling for the headings */
			h1 {{
			font-size: 30px;
			color: #333;
			margin-bottom: 10px;
			}}

			h2 {{
			font-size: 24px;
			color: #444;
			margin-bottom: 8px;
			}}

			h3 {{
			font-size: 20px;
			color: #555;
			}}

			h4 {{
			font-size: 18px;
			color: #666;
			}}

		/* Style the container div */
		.header-container {{
		position: relative;
		text-align: center; /* Center the text */
		width: 100%;
		}}

		/* Style for the header image */
		.header-image {{
		width: 100%;
		height: 150px; /* Adjust height as needed */
		object-fit: cover; /* Ensures the image covers the space */
		}}

		/* Style for the headline */
		.headline {{
		position: absolute;
		top: 30px; /* Vertically centers the text */
		left: 50%;
		transform: translate(-50%, -50%); /* Centers text exactly */
		color: white; /* White text color */
		font-size: 30px; /* Adjust the font size as needed */
		font-weight: bold; /* Optional: makes the text bold */
		text-shadow: 2px 2px 5px rgba(0, 0, 0, 0.5); /* Optional: adds shadow to the text */
		}}

	  .sticky-header {{
		position: sticky;
		top: 0;
		background-color: white; /* Keeps it visible */
		z-index: 1000; /* Ensures it's above other elements */
		padding: 10px;
		border-bottom: 2px solid #ddd; /* Adds a separator */
		text-align: center;
	  }}


		/* Floating "Back to TOC" button */
	  .back-to-toc {{
		position: fixed;
		bottom: 20px;
		right: 20px;
		background: #0073e6;
		color: white;
		border: none;
		padding: 12px 16px;
		font-size: 14px;
		font-weight: bold;
		border-radius: 8px;
		cursor: pointer;
		box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
		transition: background 0.3s ease, transform 0.2s ease;
		}}

		.back-to-toc:hover {{
		background: #005bb5;
		transform: scale(1.1);
		}}

		/* Hide button when at the top of the page */
		.hidden {{
		display: none;
		}}

	  .checkbox-container, .radio-container {{
      margin-bottom: 10px;
      }}

	  .radio-container {{
		margin-top: 20px; /* Adds space after the chart */
	  }}
	  
      .fit-text {{
        font-size: 14px; /* Adjust the font size as needed */
        word-wrap: break-word; /* Allow text to break onto the next line if needed */
      }}
  
	  #traffic_per_device_combined_trends_bps_chart_div {{
		height: 20vh;
	  }}

	  #attacks_per_device_combined_trends_bps_chart_div {{
		height: 20vh;
	  }}  

	  #cps_per_device_combined_trends_chart_div {{
		height: 20vh;
	  }}

	  #traffic_per_device_combined_trends_pps_chart_div {{
		height: 20vh;
	  }}

	  #attacks_per_device_combined_trends_pps_chart_div {{
		height: 20vh;
	  }}  

	  #cec_per_device_combined_trends_chart_div {{
		height: 20vh;
	  }}
	  
	  #maxpps_per_day_chart_div {{
		height: 25vh;
	  }}

	  #maxbps_per_day_chart_div {{
		height: 25vh;
	  }}

	  #events_per_day_chart_div {{
		height: 25vh;
	  }}

	  #bandwidth_per_day_chart_div {{
		height: 25vh;
	  }}

	  #packets_per_day_chart_div {{
		height: 25vh;
	  }}

	  #attack_packets_per_day_chart_div {{
		height: 50vh;
	  }}

	  #attack_bandwidth_per_day_chart_div {{
		height: 50vh;
	  }}

	  #attack_events_per_day_chart_div_alltimehigh {{
		height: 50vh;
	  }}

	  #packets_per_day_chart_div_alltimehigh {{
		height: 50vh;
	  }}

	  #bandwidth_per_day_chart_div_alltimehigh {{
		height: 50vh;
	  }}
	  
	  #events_per_day_by_device_chart_div {{
		height: 50vh;
	  }}

	  #packets_per_day_by_device_chart_div {{
		height: 50vh;
	  }}

	  #bandwidth_per_day_by_device_chart_div {{
		height: 50vh;
	  }}

	  #sip_events_per_day_chart_div {{
		height: 50vh;
	  }}

	  #sip_packets_per_day_chart_div {{
		height: 50vh;
	  }}

	  #sip_bandwidth_per_day_chart_div {{
		height: 50vh;
	  }}

	  
	  
	  #dip_events_bar_chart_div {{
	    width: 33vw;  /* 40% of the screen width */
        margin: 0 auto;  /* Centers the div horizontally */
        text-align: center;  /* Ensures content inside is centered */
		height: 50vh;
	  }}

	  #dip_packets_bar_chart_div {{
	    width: 33vw;  /* 40% of the screen width */
        margin: 0 auto;  /* Centers the div horizontally */
        text-align: center;  /* Ensures content inside is centered */
		height: 50vh;
	  }}

	  #dip_bandwidth_bar_chart_div {{
	    width: 33vw;  /* 40% of the screen width */
        margin: 0 auto;  /* Centers the div horizontally */
        text-align: center;  /* Ensures content inside is centered */
		height: 50vh;
	  }}



	  #policy_events_per_day_chart_div {{
		height: 50vh;
	  }}

	  #policy_packets_per_day_chart_div {{
		height: 50vh;
	  }}

	  #policy_bandwidth_per_day_chart_div {{
		height: 50vh;
	  }}


        /* Center the toggle button */
        .button-container {{
            display: flex;
            justify-content: center;
            margin: 20px 0;
        }}



        /* Styling for the toggle button */
        .toggle-btn {{
            cursor: pointer;
            background-color: #6c757d; /* Gray color */
            color: white;
            padding: 12px 24px;
            border: none;
            outline: none;
            font-size: 18px;
            border-radius: 5px;
            transition: background-color 0.3s, transform 0.2s;
        }}


        /* Style for the button when active */
        .toggle-btn.active {{
            background-color: #5a6268; /* Darker gray */
        }}


        /* Hover effect */
        .toggle-btn:hover {{
            background-color: #868e96; /* Lighter gray for hover */
            transform: scale(1.05);
        }}

        /* Initial state to hide the collapsible content */
        .collapsible-content {{
            display: none;
            margin-top: 15px;
        }}

        /* Styling for the table */
        .dataframe {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}

        .dataframe th, .dataframe td {{
            padding: 8px;
            text-align: center;
            border: 1px solid #ddd;
        }}

        .dataframe thead th {{
            background-color: #f2f2f2;
        }}

	</style>
	<title >Radware Daily Report</title>
	</head>
			

	<body>
  <!-- Header Image -->
<div class="header-container">
  <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAABWwAAACgCAYAAACYGyVAAAAAAXNSR0IArs4
  c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAytSURBVHhe7d1rkNX1fcfxtUkznXb6NMpekI
  u7sqtGYbmXiK5tpk2mwaAoCgi77E0NFi9UDRBAwAsiShYQQWI1gsvFS9pJ1NYbkIQZ2zR12ji1Nam1aUxjIRfBWAP59
  pyFR+15Iu5Zv3vm9eA1v2fnnPnPeXDmPZ/5naraGTcGAADAYFVz6Q19Z/Odj0bLnn1x4a6X+tHePpN7dkbz8k0xdvn9
  DHLNKzbHuau3xWe7l8SKc6bEhiENcV9dUyr3nDj31zbE2zVnxM8KDlJxfjFkRLw5oilWXnp5zOnsjvntnf2ubX5XXNV
  6day/9U/iyI7fidhTFbHrFMppR1X8+JvNse3152PxwaOx7O3Dsfztd+ADEWwBAIBBq+aS6wvnTTF27fa4qL9j7e5irH0
  pJq/vjbFibUU4HmsfjD/tvDVWnj0pNgyp/3+x9KO2dmhTrC/4Tm1DX9QTayvTL4eMiH874+xYftkVZY+1Gxd/Jn7V+9t
  i7UDYURX/8fSE2PLD/fGlQ7+J5WItJ0mwBQAABqW+WHv5ohh3z2Nx0e7+jbUtxVi788WYdO+OaP7yxpLxj8GlGGvPW7U
  1pnXcHKvOmpgy1t5d0FNwQKytaO8MGRGvN5wTSy6/Mq7qKmOsbbs6tiz9w3hv5ycidou15VV4vjuq4s1nJsfmNw6ItXx
  ogi0AADDoFGNt3cxFMeG+XeVZ1hZj7brtYm2FaL7tgRi9amt8oW1R3D5qQsprEIqxdkNdY7xc2xCHas7oUyr2Mbi9c9q
  IeK3hU3HLzFkxt5zL2rbueGjZ1Hh/58fF2rIrPN/HquKHz14YG9/4biw+dKxkgIMPQrAFAAAGlWKsHXrFzTGhZ0+07Nl
  fOrqerGKs7X0hJt7zqFhbIcaciLWXzL0x7jxzbPQkjbUb6xrj72rr+6KeWFuZDp82PF4989z48ytnly3Wts7virltV8f
  2FVPi6M6PibXltvN4rH39bz4TPf/+Siw+dLRkfIMPSrAFAAAGjZrpC6Nu1i0xcdMTcdHj5Yi1L8XEtV8TayvE8Vi7JWb
  MWRh31Y+JnuqEsXZoU9xf1xjfram3rK1gh08dHq80jY4bZ88tX6xt7465bd3Ru3JyHN0l1pbdiVj72nOfjfVvfl+spV8
  JtgAAwKBQjLWnz/lSTNr8ZLT0c6wt3ll7Qe+LMeHuh8XaClGMtWNWPhAzZy2Iu0eOiQ3VZ5YMph+l4rJ2S11j/EOtWFv
  JDp86LL53dnMsnDOvzLH26nhi9fg4tuu3xNpyK8ba3qp49cVpse5Hr8Xig78uGd3gZAm2AABAesVYO+yqxTH5ga/3e6w
  tLmsv6H0hJqx5OJqXibWVYMzKLX331l4589pYO+LclMvaNQVbaxvjHy1rK1ox1r58zti4bm5rzOvsKhlbP6zW+d19VyH
  85Z3NcWz3KWJtuZ1Y1v7Ti5fF2v/8QSw+aFlL/xNsAQCA1KqnL4zhrV+OP9j6V9HyeH//wdi+uGDH8zH+rofE2goxuhh
  rV2yO2Zd1xT3DPxU9CZe1a4Y2xba6xvh+TX38rEasrVSHP3l6HDhvfHxxXlvM6yhPrJ03vzva2rvjmbvPi2N7SsRF+te
  JZe0re2fFmrfeiCWHLGspD8EWAABIq/rihTFi/oqYsu0b0bKnf2Nt8RqEqdufi/F3fjXGirUVoS/WFs6rLmmPdcPOyRl
  rCx6qHRWvnoi1pUIfg9+RT54ee5snxTWtrdFatljbFW0dnfHc2rPF2oHQF2tPib/f3xp3vfWjWOIaBMpIsAUAAFKq/vy
  CGNlxW0z56jfLE2sf/esYf8e2GLtsU8n4x+AyeuXWwrkpWi9ui3WnnxVfSRhr7yr4i9pR8c9ibcUqrqWPnDosXhg3Jbr
  ntZUt1s6d3xXtHR2x795GsXYg9FbFb3o/Hi9/qzPu+MlbsfTg+yUjG/QXwRYAAEinGGvru1fFpx96pv9jbeH1pn7t2Rh
  3+4OWtRVi9KqtMW7Zpmj//Ly4b+hZ8ZWaUSWD6UepGGsfqR0V/1JTHz//P5GPylCMte+eOiyenXh+dLXOL+Oytjs6Otr
  j2+sbxNqB0FsVx3Z+Ig58Z0Gs/slPY8nB/ykZ2KA/CbYAAEAq1dMWRMM1d8SnHy7G2r0lo+vJKsba8x95JsbdvjWaLWs
  rwnmrtsb4pRui43Oz+8Joylg7tCm2142Kf7WsrViHqo8va78xaWp0tc2PtjLG2u7O9vjbnpFi7UDorYpf7/rd+PaBm2L
  Vf/13LBVrGSCCLQAAkEbNtAVRf+2aOP+RZ/uuLSgVXU9Wy+59MfXhp2P86uKyVqytBMVYO3FpT3T/8axYX9uYLtbeW1B
  c1j5WOyp+INZWrEPVI+PIacPjqSkXRmdbR9+9sqVi64c1t607rulqi+9tHC7WDoTHquL9Xb8Xe1++JVb+9FAsPfheybA
  G5SDYAgAAKVR/YWE0Xr8uLtjxfLQ88a1oeXx//ym83tRHno5xqx+McSvuj3G3bWaQG7N6a0y59d647o9mxMYhDbGpuiE
  21JyZRk/BfQVPVdfHj4eMiF8NGR5HqDjvFrx32rB48vyW6OroiPaOzugsg/b2zlh07Zx4fUt1xJNVEU8UPE7Z7C546vd
  j3yu3xeqfvxsrfnk0Vv3iPRgwVbWXFH4cAQAAJFA3Y1EMnXlLmdwcdZctooIMLXxfhk+/PkZOuy5GXlz0Z+nUFz7XqIJ
  GKtoZ0xfGsEtvKKvhM26IUTMXRNMVX4ymmZRb4xULon7Wohgxe0nBYhhQgi0AAACDWg0kUOq72d+Ov9dNDIjCs55eeO7
  Tb4ABJ9gCAAAAACQh2AIAAAAAJCHYAgAAAAAkIdgCAAAAACQh2AIAAAAAJCHYAgAAAAAkIdgCAAAAACQh2AIAAAAAJCH
  YAgAAAAAkIdgCAAAAACQh2AIAAAAAJCHYAgAAAAAkIdgCAAAAACQh2AIAAAAAJCHYAgAAAAAkIdgCAAAAACQh2AIAAAA
  AJCHYAgAAAAAkIdgCAAAAACQh2AIAAAAAJCHYAgAAAAAkIdgCAAAAACQh2AIAAAAAJCHYAgAAAAAkIdgCAAAAACQh2AI
  AAAAAJCHYAgAAAAAkIdgCAAAAACQh2AIAAAAAJCHYAgAAAAAkIdgCAAAAACQh2AIAAAAAJCHYAgAAAAAkIdgCAAAAACQ
  h2AIAAAAAJCHYAgAAAAAkIdgCAAAAACQh2AIAAAAAJCHYAgAAAAAkIdgCAAAAACQh2AIAAAAAJCHYAgAAAAAkIdgCAAA
  AACQh2AIAAAAAJCHYAgAAAAAkIdgCAAAAACQh2AIAAAAAJCHYAgAAAAAkIdgCAAAAACQh2AIAAAAAJCHYAgAAAAAkIdg
  CAAAAACQh2AIAAAAAJCHYAgAAAAAkIdgCAAAAACQh2AIAAAAAJCHYAgAAAAAkIdgCAAAAACQh2AIAAAAAJCHYAgAAAAA
  kIdgCAAAAACQh2AIAAAAAJCHYAgAAAAAkIdgCAAAAACQh2AIAAAAAJCHYAgAAAAAkIdgCAAAAACQh2AIAAAAAJCHYAgA
  AAAAkIdgCAAAAACQh2AIAAAAAJCHYAgAAAAAkIdgCAAAAACQh2AIAAAAAJCHYAgAAAAAkIdgCAAAAACQh2AIAAAAAJCH
  YAgAAAAAkIdgCAAAAACQh2AIAAAAAJCHYAgAAAAAkIdgCAAAAACQh2AIAAAAAJCHYAgAAAAAkIdgCAAAAACQh2AIAAAA
  AJCHYAgAAAAAkIdgCAAAAACQh2AIAAAAAJCHYAgAAAAAkIdgCAAAAACQh2AIAAAAAJCHYAgAAAAAkIdgCAAAAACQh2AI
  AAAAAJCHYAgAAAAAkIdgCAAAAACQh2AIAAAAAJCHYAgAAAAAkIdgCAAAAACQh2AIAAAAAJCHYAgAAAAAkIdgCAAAAACQ
  h2AIAAAAAJCHYAgAAAAAkIdgCAAAAACQh2AIAAAAAJCHYAgAAAAAkIdgCAAAAACQh2AIAAAAAJCHYAgAAAAAkIdgCAAA
  AACQh2AIAAAAAJCHYAgAAAAAkIdgCAAAAACQh2AIAAAAAJCHYAgAAAAAkIdgCAAAAACQh2AIAAAAAJCHYAgAAAAAkIdg
  CAAAAACQh2AIAAAAAJCHYAgAAAAAkIdgCAAAAACQh2AIAAAAAJCHYAgAAAAAkIdgCAAAAACQh2AIAAAAAJCHYAgAAAAA
  kIdgCAAAAACQh2AIAAAAAJCHYAgAAAAAkIdgCAAAAACQh2AIAAAAAJCHYAgAAAAAkIdgCAAAAACQh2AIAAAAAJCHYAgA
  AAAAkIdgCAAAAACQh2AIAAAAAJCHYAgAAAAAkIdgCAAAAACQh2AIAAAAApHBj/C92OYLskdJAmgAAAABJRU5ErkJggg==" alt="Header Image" width="100%" height="100px">
</div>

<h1 class="headline">Radware Daily trends report {month}, {year} - {cust_id}</h1>

<table class="toc-table">
	
		<thead>
		<tr>
		<td class="toc-cell" colspan="4">
		<div class="toc-header"><br>Table of Contents</div>
		</td>
		</tr>

          <tr>

            <td class="toc-cell">
				<!-- Table of Contents -->
				<div id="toc" class="toc-container">
					<ul class="toc-list">
						<li>
						<b><a href="#section1">Attack Traffic Overview (Volume - Mbps/Cumulative GB)</a></b>
						<ul class="sub-list">
							<li><a href="#section1-2">Traffic and Attack Rate for each DefensePro</a></li>
							<li><a href="#section1-3">Highest volume attack of the day</a></li>
							<li><a href="#section1-4">Cumulative Attack Volume per day</a></li>
							<li><a href="#section1-5">Cumulative Attack Volume breakdown by attack vector</a></li>
							<li><a href="#section1-6">Cumulative Attack Volume breakdown by DefensePro</a></li>
							<li><a href="#section1-7">Cumulative Attack Volume breakdown by policy</a></li>
							<li><a href="#section1-8">Cumulative Attack Volume breakdown by source IP's</a></li>	
							<li><a href="#section1-9">Top attacked destination IP's by volume(MB)</a></li>	
						</ul>
						</li>
					</ul>
  				</div>
			</td>

			<td class="toc-cell">
				<!-- Table of Contents -->
				<div id="toc" class="toc-container">
					<ul class="toc-list">
						<li>
						<b><a href="#section2">Attack Traffic Overview (Packets- PPS/Cumulative)</a></b>
							
							<ul class="sub-list">
								<li><a href="#section2-2">Traffic and Attack Rate for each DefensePro (PPS)</a></li>
								<li><a href="#section2-3">Highest volume attack of the day(PPS)</a></li>
								<li><a href="#section2-4">Cumulative Attack packets per day</a></li>
								<li><a href="#section2-5">Cumulative Attack packets breakdown by attack vector</a></li>
								<li><a href="#section2-6">Cumulative Attack packets breakdown by DefensePro</a></li>
								<li><a href="#section2-7">Cumulative Attack packets breakdown by policy</a></li>
								<li><a href="#section2-8">Cumulative Attack packets breakdown by source IP's</a></li>	
								<li><a href="#section2-9">Top attacked destination IP's(cumulative packets)</a></li>	
							</ul>
							
						</li>
					</ul>
  				</div>
			</td>


            <td class="toc-cell">
				<!-- Table of Contents -->
				<div id="toc" class="toc-container">
					<ul class="toc-list">
						<li>
						<b><a href="#section3">Attack Traffic Overview (Number of Attack Events)</a></b>
						<ul class="sub-list">
							<li><a href="#section3-2">Number of attack events per day</a></li>
							<li><a href="#section3-3">Number of attack events by attack vector</a></li>
							<li><a href="#section3-4">Number of attack events by DefensePro</a></li>
							<li><a href="#section3-5">Number of attack events by policy</a></li>
							<li><a href="#section3-6">Number of attack events by source IP's</a></li>
							<li><a href="#section3-7">Top attacked destination IP's(attack events)</a></li>	

						</ul>
						</li>
					</ul>
  				</div>
			</td>
			<td class="toc-cell">
				<!-- Table of Contents -->
				<div id="toc" class="toc-container">
					<ul class="toc-list">
						<li>
						<b><a href="#section4">Other statistics</a></b>
						<ul class="sub-list">
							<li><a href="#section4-1">Connections Per Second</a></li>
							<li><a href="#section4-2">Concurrent Connections</a></li>
							<li><a href="#section4-3">Excluded Uninspected Traffic Volume (Mbps)</a></li>
							<li><a href="#section4-4">Excluded Uninspected Traffic Rate (PPS)</a></li>

	
						</ul>
						</li>
					</ul>
  				</div>
			</td>


		</tr>

		</thead>
</table>

  


<div class="sticky-header">
	<h2 id="section1">Attack Traffic Overview (Volume - Mbps/Cumulative GB)</h2>
</div>	


  <table>
	
		<thead>

			
          <tr >
            <td colspan="3" style="border-bottom: 0;" >
            <h3 id="section1-2">Traffic and Attack Volume for each DP (Mbps)</h3>
            <div id="traffic_per_device_combined_trends_bps_chart_div" style="height: 510px;">
            </td>
          </tr> 
		  
		  <tr>
		  	<td colspan="3" style="border-bottom: 0;">
			<h3 id="section1-3">Highest volume attack of the day ({bps_units_desc})</h3>
			<div id="maxbps_per_day_chart_div">
			</td>
		  </tr>
		  <tr>
			<td colspan="3" valign="top" style="border-top: 0;" class="fit-text">
				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Show Details" onclick="toggleTable('maxbpsPerDayTable', this)">Show Details</button>
				</div>
		  		<div id="maxbpsPerDayTable" class="collapsible-content">
				{maxbps_per_day_table}
				</div>
			</td>
		  </tr>



		  <tr>
		  	<td colspan="3" style="border-bottom: 0;">
			  <h3 id="section1-4">Cumulative Attack Volume per day ({bw_units})</h3>
				<div id="bandwidth_per_day_chart_div">
			</td>
		  </tr>
		  <tr>
			<td colspan="3" valign="top" style="border-top: 0;" class="fit-text">
				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Show Details" onclick="toggleTable('bwPerDayTable', this)">Show Details</button>
				</div>
		  		<div id="bwPerDayTable" class="collapsible-content">
				  
				{bandwidth_per_day_table}
				</div>
			</td>
		  </tr>	




		  <tr>
		  	<td colspan="3" style="border-bottom: 0;" class="fit-text">
			<h3 id="section1-5">Cumulative Attack Volume breakdown by attack vectors</h3>
			<div id="bandwidth_per_day_chart_div_alltimehigh" style="height: 400px;">
			</td>
		  </tr>
  

		   <tr>
		  
			<td colspan="3" valign="top" style="border-top: 0;">
				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Accumulated Attack Volume per day table" onclick="toggleTable('AttackBWPerDayTable', this)">Accumulated Attack Volume per day table</button>
				</div>
		  		<div id="AttackBWPerDayTable" class="collapsible-content">
				{bw_table_alltimehigh}
				</div>


				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Distribution of accumulated Attack Volume across Devices and Policies" onclick="toggleTable('DistributionOfBWPerDayTable', this)">Distribution of accumulated Attack Volume across Devices and Policies</button>
				</div>
		  		<div id="DistributionOfBWPerDayTable" class="collapsible-content">
				
				{bandwidth_per_day_html_final}
				</div>


			</td>
	
		  </tr>		

		  


		  <tr>
		  	<td colspan="3" style="border-bottom: 0;">
			<h3 id="section1-6">Cumulative Attack Volume breakdown by DefensePro</h3>
			<div id="bandwidth_per_day_by_device_chart_div" style="height: 400px;">
			</td>
		  </tr>

		   <tr>
		  
			<td colspan="3" valign="top" style="border-top: 0;" class="fit-text">
				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Attack Volume by DefensePro table" onclick="toggleTable('AttackDeviceBWPerDayTable', this)">Attack Volume by DefensePro table</button>
				</div>
		  		<div id="AttackDeviceBWPerDayTable" class="collapsible-content">
				{bw_by_device_table}
				</div>


				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Distribution of accumulated Attack Volume across Devices and Policies" onclick="toggleTable('DistributionOfDeviceBWPerDayTable', this)">Distribution of accumulated Attack Volume across Devices and Policies</button>
				</div>
		  		<div id="DistributionOfDeviceBWPerDayTable" class="collapsible-content">
				
				{device_bandwidth_per_day_html_final}
				</div>


			</td>
	
		  </tr>

		  <tr>
		  	<td colspan="3" style="border-bottom: 0;">
			<h3 id="section1-7">Cumulative Attack Volume breakdown by policy</h3>
			<div id="policy_bandwidth_per_day_chart_div" style="height: 400px;">
			</td>
		  </tr>
		   <tr>
			<td colspan="3" valign="top" style="border-top: 0;" class="fit-text">
				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Attack Volume by policy table" onclick="toggleTable('AttackPolicyBWPerDayTable', this)">Attack Volume by policy table</button>
				</div>
		  		<div id="AttackPolicyBWPerDayTable" class="collapsible-content">
				{policy_bw_table}
				</div>


				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Distribution of accumulated Attack Volume across Devices and Policies" onclick="toggleTable('DistributionOfPolicyBWPerDayTable', this)">Distribution of accumulated Attack Volume across Devices and Policies</button>
				</div>
		  		<div id="DistributionOfPolicyBWPerDayTable" class="collapsible-content">
				
				{policy_bandwidth_per_day_html_final}
				</div>


			</td>
	
		  </tr>

		  <tr>
		  	<td colspan="3" style="border-bottom: 0;">
			<h3 id="section1-8">Cumulative Attack Volume breakdown by source IP's</h3>
			<div id="sip_bandwidth_per_day_chart_div" style="height: 400px;">
			</td>
		  </tr>
		   <tr>
		  
			<td colspan="3" valign="top" style="border-top: 0;" class="fit-text">
				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Attack Volume by Source IP" onclick="toggleTable('AttackSIPBWPerDayTable', this)">Attack Volume by Source IP</button>
				</div>
		  		<div id="AttackSIPBWPerDayTable" class="collapsible-content">
				{sip_bw_table}
				</div>


				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Distribution of topmost Attack Volume for Source IP's" onclick="toggleTable('DistributionOfSIPBWPerDayTable', this)">Distribution of topmost Attack Volume for Source IP's</button>
				</div>
		  		<div id="DistributionOfSIPBWPerDayTable" class="collapsible-content">
				
				{sip_bandwidth_per_day_html_final}
				</div>


			</td>
	
		  </tr>

		  
		<tr>
		<td colspan="3">
			<h3 id="section1-9">Top attacked destination IP's by volume (MB)</h3>
			<div id="dip_bandwidth_bar_chart_div" style="height: 400px;"></div>
		</td>
		</tr>

		  </thead>
		    </table>



			
		<div class="sticky-header">
		<h2 id="section2">Attack Traffic Overview (Packets- PPS/Cumulative)</h2>
		</div>	


		<table>
		<thead>


          <tr>
            <td colspan="3" style="border-bottom: 0;">
            <h3 id="section2-2">Traffic and Attack Rate for each DefensePro (PPS)</h3>
            <div id="traffic_per_device_combined_trends_pps_chart_div" style="height: 400px;">
            </td>
          </tr> 
		  
		  <tr>
		  	<td colspan="3" style="border-bottom: 0;">
			<h3 id="section2-3">Highest volume attack of the day(PPS)</h3>
			<div id="maxpps_per_day_chart_div">
			</td>
		  </tr>
		  <tr>
		  	<td colspan="3" valign="top" style="border-top: 0;" class="fit-text">
				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Show Details" onclick="toggleTable('maxppsPerDayTable', this)">Show Details</button>
				</div>
		  		<div id="maxppsPerDayTable" class="collapsible-content">
		  			{maxpps_per_day_table}
		  		</div>
		  	</td>
		  </tr>

		  
		  <tr>
		  	<td colspan="3" style="border-bottom: 0;">
			<h3 id="section2-4">Cumulative Attack packets per day</h3>
				<div id="packets_per_day_chart_div">
			</td>
		  </tr>
		  <tr>
			<td colspan="3" valign="top" style="border-top: 0;" class="fit-text">
				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Show Details" onclick="toggleTable('packetsPerDayTable', this)">Show Details</button>
				</div>
		  		<div id="packetsPerDayTable" class="collapsible-content">
				{packets_per_day_table}
				</div>
			</td>
		  </tr>

		  
		  <tr>
		  	<td colspan="3" style="border-bottom: 0;">
			<h3 id="section2-5">Cumulative Attack packets breakdown by attack vector</h3>
			<div id="packets_per_day_chart_div_alltimehigh" style="height: 400px;">
			</td>
		  </tr>


		  <tr>

			<td colspan="3" valign="top" style="border-top: 0;" class="fit-text">
				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Attack packets table" onclick="toggleTable('AttackPacketsPerDayTable', this)">Attack packets table</button>
				</div>
		  		<div id="AttackPacketsPerDayTable" class="collapsible-content">
				{packets_table_alltimehigh}
				</div>


				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Distribution of topmost Attack packets across Devices and Policies" onclick="toggleTable('DistributionOfPacketsPerDayTable', this)">Distribution of topmost Attack packets across Devices and Policies</button>
				</div>
		  		<div id="DistributionOfPacketsPerDayTable" class="collapsible-content">
				
				{packets_per_day_html_final} 
				</div>


			</td>
	
		  </tr>		

		  <tr>
		  	<td colspan="3" style="border-bottom: 0;">
			<h3 id="section2-6">Cumulative Attack packets breakdown by DefensePro</h3>
			<div id="packets_per_day_by_device_chart_div" style="height: 400px;">
			</td>
		  </tr>

		  

		  <tr>

			<td colspan="3" valign="top" style="border-top: 0;" class="fit-text">
				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Attack packets by DefensePro table" onclick="toggleTable('AttackDevicePacketsPerDayTable', this)">Attack packets by DefensePro table</button>
				</div>
		  		<div id="AttackDevicePacketsPerDayTable" class="collapsible-content">
				{packets_by_device_table}
				</div>


				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Distribution of topmost Attack packets for device" onclick="toggleTable('DistributionOfDevicePacketsPerDayTable', this)">Distribution of topmost Attack packets for device</button>
				</div>
		  		<div id="DistributionOfDevicePacketsPerDayTable" class="collapsible-content">
				
				{device_packets_per_day_html_final} 
				</div>


			</td>
	
		  </tr>		

		  <tr>
		  	<td colspan="3" style="border-bottom: 0;" class="fit-text">
			<h3 id="section2-7">Cumulative Attack packets breakdown by policy</h3>
			<div id="policy_packets_per_day_chart_div" style="height: 400px;">
			</td>
		  </tr>
		  <tr>

			<td colspan="3" valign="top" style="border-top: 0;" class="fit-text">
				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Attack packets by DefensePro table" onclick="toggleTable('AttackPolicyPacketsPerDayTable', this)">Attack packets by policy table</button>
				</div>
		  		<div id="AttackPolicyPacketsPerDayTable" class="collapsible-content">
				{policy_packets_table}
				</div>


				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Distribution of topmost Attack packets for device" onclick="toggleTable('DistributionOfPolicyPacketsPerDayTable', this)">Distribution of topmost Attack packets</button>
				</div>
		  		<div id="DistributionOfPolicyPacketsPerDayTable" class="collapsible-content">
				
				{policy_packets_per_day_html_final} 
				</div>


			</td>
	
		  </tr>		


		  <tr>
		  	<td colspan="3" style="border-bottom: 0;">
			<h3 id="section2-8">Cumulative Attack packets breakdown by source IP's</h3>
			<div id="sip_packets_per_day_chart_div" style="height: 400px;">
			</td>
		  </tr>
		  <tr>

			<td colspan="3" valign="top" style="border-top: 0;" class="fit-text">
				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Attack packets per day by Source IP" onclick="toggleTable('AttackSIPPacketsPerDayTable', this)">Attack packets per day by Source IP</button>
				</div>
		  		<div id="AttackSIPPacketsPerDayTable" class="collapsible-content">
				{sip_packets_table}
				</div>


				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Distribution of topmost Attack packets for Source IP's" onclick="toggleTable('DistributionOfSIPPacketsPerDayTable', this)">Distribution of topmost Attack packets for Source IP's</button>
				</div>
		  		<div id="DistributionOfSIPPacketsPerDayTable" class="collapsible-content">
				
				{sip_packets_per_day_html_final} 
				</div>


			</td>
	
		  </tr>	

		  

			<tr>
			<td colspan="3">
				<h3 id="section2-9">Top attacked Destination IP's(cumulative packets)</h3>
				<div id="dip_packets_bar_chart_div"></div>
			</td>
			</tr>







	  </thead>
	</table>

	<div class="sticky-header">
	<h2 id="section3">Attack Traffic Overview (Number of Attack Events)</h2>
	</div>
		
	<table>
  	<thead>
		    

		  <tr>
		  	<td colspan="3" style="border-bottom: 0;">
			<h3 id="section3-2">Number of attack events per day</h3>
			<div id="events_per_day_chart_div">
			</td>
		  </tr>
		  <tr>
			<td colspan="3" valign="top" style="border-top: 0;" class="fit-text">
				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Show Details" onclick="toggleTable('eventsPerDayTable', this)">Show Details</button>
				</div>
		  		<div id="eventsPerDayTable" class="collapsible-content">
				  
				{events_per_day_table}
				</div>
			</td>
		  </tr>		  



		  <tr>
		  	<td colspan="3" style="border-bottom: 0;">
			<h3 id="section3-3">Number of attack events by attack vector</h3>
			<div id="events_per_day_chart_div_alltimehigh" style="height: 400px;">
			</td>
		  </tr>	
		  <tr>
			<td colspan="3" valign="top" style="border-top: 0;" class="fit-text">
				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Attack Events count per Day" onclick="toggleTable('AttackEventsPerDayTable', this)">Attack Events count per Day</button>
				</div>
		  		<div id="AttackEventsPerDayTable" class="collapsible-content">
				  
				{events_trends_table_alltimehigh}
				
				</div>


				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Distribution of topmost attack events across Devices and Policies" onclick="toggleTable('DistributionOfAttacksPerDayTable', this)">Distribution of topmost attack events across Devices and Policies</button>
				</div>
		  		<div id="DistributionOfAttacksPerDayTable" class="collapsible-content">
				  
				
				{events_per_day_html_final}
				</div>


			</td>
	
		  </tr>		



		  <tr>
		  	<td colspan="3" style="border-bottom: 0;">
			<h3 id="section3-4">Number of attack events by DefensePro</h3>
			<div id="events_per_day_by_device_chart_div" style="height: 400px;" style="border-bottom: 0;">
			</td>
		  </tr>	

		  <tr>
			<td colspan="3" valign="top" style="border-top: 0;" class="fit-text">
				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Attack Events by DefensePro table" onclick="toggleTable('DeviceAttackEventsPerDayTable', this)">Attack Events by DefensePro table</button>
				</div>
		  		<div id="DeviceAttackEventsPerDayTable" class="collapsible-content">
				  
				{events_by_device_table}
				
				</div>

				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Distribution of topmost attack events" onclick="toggleTable('DistributionOfDeviceAttacksPerDayTable', this)">Distribution of topmost attack events</button>
				</div>
		  		<div id="DistributionOfDeviceAttacksPerDayTable" class="collapsible-content">
				  
				
				{device_events_per_day_html_final}
				</div>
			</td>
		  </tr>		




		  <tr>
		  	<td colspan="3" style="border-bottom: 0;">
			<h3 id="section3-5">Number of attack events by policy</h3>
			<div id="policy_events_per_day_chart_div" style="height: 400px;">

			</td>
		  </tr>	


		  <tr>

			<td colspan="3" valign="top" style="border-top: 0;" class="fit-text">
				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Attack Events by policy table" onclick="toggleTable('PolicyAttackEventsPerDayTable', this)">Attack Events by policy table</button>
				</div>
		  		<div id="PolicyAttackEventsPerDayTable" class="collapsible-content">
				  
				{policy_events_trends_table}
				
				</div>


				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Distribution of topmost attack events" onclick="toggleTable('DistributionOfPolicyAttacksPerDayTable', this)">Distribution of topmost attack events</button>
				</div>
		  		<div id="DistributionOfPolicyAttacksPerDayTable" class="collapsible-content">
				  
				
				{policy_events_per_day_html_final}
				</div>


			</td>
	
		  </tr>	



		  <tr>
		  	<td colspan="3" style="border-bottom: 0;">
			<h3 id="section3-6">Number of attack events by Source IP's</h3>
			<div id="sip_events_per_day_chart_div" style="height: 400px;">

			</td>
		  </tr>	
		  <tr>

			<td colspan="3" valign="top" style="border-top: 0;" class="fit-text">
				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Attack Events per day table by source IP" onclick="toggleTable('SIPAttackEventsPerDayTable', this)">Attack Events per day table by source IP</button>
				</div>
		  		<div id="SIPAttackEventsPerDayTable" class="collapsible-content">
				  
				{sip_events_trends_table}
				
				</div>


				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Distribution of topmost Attack Events for Source IP's" onclick="toggleTable('DistributionOfSIPAttacksPerDayTable', this)">Distribution of topmost Attack Events for Source IP's</button>
				</div>
		  		<div id="DistributionOfSIPAttacksPerDayTable" class="collapsible-content">
				  
				
				{sip_events_per_day_html_final}
				</div>


			</td>
	
		  </tr>	


		  <tr>
			<td colspan="3">
				<h3 id="section3-7">Top attacked Destination IP's (attack events)</h3>
				<div id="dip_events_bar_chart_div"></div>
			</td>
		  </tr>	

		  </thead>
		  </table>




			<div class="sticky-header">
			<h2 id="section4">Connections insights (CPS/Concurrent Established)</h2>
			</div>

		  <table>
		  <thead>
		  <tr>
            <td colspan="3" style="border-bottom: 0;">
            <h3 id="section4-1">Connections Per Second per device</h3>
            <div id="cps_per_device_combined_trends_chart_div" style="height: 400px;">
            </td>
          </tr> 

         <tr>
            <td colspan="3" style="border-bottom: 0;">
            <h3 id="section4-2">Concurrent Established Connections per device</h3>
            <div id="cec_per_device_combined_trends_chart_div" style="height: 400px;">
            </td>
          </tr>   

         <tr>
            <td colspan="3" style="border-bottom: 0;">
            <h3 id="section4-3">Excluded Uninspected Traffic Volume (Mbps)</h3>
            <div id="excluded_per_device_combined_trends_bps_chart_div" style="height: 400px;">
            </td>
          </tr>   

         <tr>
            <td colspan="3" style="border-bottom: 0;">
            <h3 id="section4-4">Excluded Uninspected Traffic Rate (PPS)</h3>
            <div id="excluded_per_device_combined_trends_pps_chart_div" style="height: 400px;">
            </td>
          </tr>   

		  </thead>



	  </table>

	  <!-- Floating "Back to TOC" Button -->
  <button id="backToToc" class="back-to-toc hidden" onclick="scrollToToc()">⬆ Back to TOP</button>

	</body>

	</html>
	"""

	# write html_page to file
	write_html(html_page,month,year)

# Path: trends_analyzer.py
