import pandas as pd
import sqlite3
import csv
import sys
import pandas as pd
import json

cust_id = sys.argv[1]
month = sys.argv[2]
year = sys.argv[3]

############################# Extract variables from customers.json file #############################

customers_json = json.loads(open("./config_files/customers.json", "r").read())

for cust_config_block in customers_json:
	if cust_config_block['id'].lower() == cust_id.lower():
		defensepros = cust_config_block['defensepros']
		bw_units = cust_config_block['variables']['bwUnit']
		#Can be configured "Gigabytes", "Terabytes" or "Megabytes"
		
		pkt_units = cust_config_block['variables']['pktUnit']
		#Can be configured "Millions" or "Billions" or "Thousands"

		bw_units_daily = cust_config_block['variables']['bwUnitDaily']
		#Can be configured "Gigabytes", "Terabytes" or "Megabytes"
		
		pkt_units_daily = cust_config_block['variables']['pktUnitDaily']
		#Can be configured "Millions" or "Billions" or "Thousands"

		if bw_units_daily.lower() == 'megabytes':	
			bw_units_sum = 'ROUND(SUM(packetBandwidth)/8000.0, 2)'
			bps_unit = 1000000
			bps_units_desc = 'Mbps'

		if bw_units_daily.lower() == 'gigabytes':	
			bw_units_sum = 'ROUND(SUM(packetBandwidth)/8000000.0, 2)'
			bps_unit = 1000000000
			bps_units_desc = 'Gbps'

		if bw_units_daily.lower() == 'terabytes':
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

###############################################################################################
# Paths
charts_tables_path = f"./tmp_files/{cust_id}/"
reports_path = f"./report_files/{cust_id}/"
db_path = f'./database_files/{cust_id}/'
run_file = 'run.sh'
########################################### Extracting variables from run.sh file #########################

with open (run_file) as f:
	for line in f:
		if line.startswith('db_from_forensics'):
			#print value after = sign
			db_from_forensics = (line.split('=')[1].replace('\n','').replace('"','')).lower()
			if db_from_forensics == 'true':
				db_from_forensics = True
			else:
				db_from_forensics = False
			continue
		if line.startswith('top_n'):	
			top_n = int(line.split('=')[1].replace('\n',''))
			continue

########################################### Functions ####################################################
def convert_csv_to_list_of_lists(filename):
	# Open csv file and convert to list of lists function
	data = []
	with open(filename, 'r') as file:
		reader = csv.reader(file)
		for row in reader:
			data.append(row)

	return convert_strings_to_numbers(data)

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

def convert_packets_units(data, pkt_units=None):
	converted_data = []
	for row in data:
		converted_row = []
		for value in row:
			# if the value is integer or float
			if isinstance(value, int) or isinstance(value, float):
				if pkt_units == "Billions":
					value = round(value/1000000000, 2)
				elif pkt_units == "Millions":
					value = round(value/1000000, 2)

				elif pkt_units == "Thousands":
					value = round(value/1000, 2)
				else:
					pass
					# print(f'Packet units is not set or invalid packets unit is set under "pkt_units" variable in the script. Please set it to "Millions" or "Billions" ')
				


			converted_row.append(value)
			
		converted_data.append(converted_row)
	return converted_data


def convert_bw_units(data, bw_units):
	converted_data = []
	for row in data:
		converted_row = []
		for value in row:
			# if the value is integer or float
			if isinstance(value, int) or isinstance(value, float):

				if bw_units.lower() == "megabytes":
					value = round(value/8000, 2)
				elif bw_units.lower() == "gigabytes":
					value =  round(value/8000000, 2)
				elif bw_units.lower() == "terabytes":
					value =  round(value/8000000000, 2)

				# if isinstance(value, float):
				# 	#leave only two decimal points
				# 	value = round(value, 2)

				
				else:
					print(f'Invalid bandwidth unit is set under "bw_units" variable in the script. Please set it to "Megabytes", "Gigabytes" or "Terabytes" ')
			
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
			if (count_last) < (count_previous):
				trend = "Decrease"
			else:
				trend = "Increase"
			
			difference = abs((count_last) - (count_previous))

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


def format_numeric_value(value, bw_units=None, pkt_units=None):
	# Check if value is a number (integer or float)
	if pd.notna(value) and isinstance(value, (int, float)):
		# Apply formatting based on units
		if pkt_units:
			if pkt_units.lower() == 'millions':
				value /= 1000000
			elif pkt_units.lower() == 'billions':
				value /= 1000000000
			if pkt_units.lower() == 'thousands':
				value /= 1000

		if bw_units:
			if bw_units.lower() == 'megabytes':
				value /= 8000
			elif bw_units.lower() == 'gigabytes':
				value /= 8000000
			elif bw_units.lower() == 'terabytes':
				value /= 8000000000

		# Format the value with thousands separator
		if pkt_units:
			# remove decimal points if the value is integer
			if isinstance(value, float):
				value = int(value)
				return value

		else:
			return '{:,.2f}'.format(value)
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
	if bw_units or pkt_units and filename!=charts_tables_path + 'sip_ppm_table_lm.csv':
		# formatted_df = df.applymap(lambda x: format_numeric_value(x, bw_units, pkt_units))
		formatted_df = df.apply(lambda column: column.apply(lambda x: format_numeric_value(x, bw_units, pkt_units)))

	else:
		df = df.apply(convert_to_int, axis=0)
		formatted_df = df

	# Convert the formatted DataFrame to an HTML table
	html_table = formatted_df.to_html(index=False, escape=False)
	
	return html_table


def write_html(html_page,month,year):
	# write html_page to file function

	with open(reports_path + f'trends-monthly_{cust_id}_{month}_{year}.html', 'w', encoding="utf-8") as f:
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

def events_per_day_html():

	# Group by day_of_month, name, Device Name, ruleName and aggregate sum of packetCount
	events_per_day = data_month.groupby(['Day of the Month', 'Attack Name', 'Device Name', 'Policy Name']).size()

	# Get the top 5 events with the highest sum of packet counts for each day
	events_per_day_top5 = events_per_day.groupby(level=['Day of the Month'], group_keys=False).nlargest(5).apply(format_with_commas).to_frame('Attack Events Count')
	events_per_day_top5 = events_per_day_top5.to_html()

	for device_ip, device_name in defensepros.items():
		events_per_day_top5=events_per_day_top5.replace(device_ip, device_name)

	return events_per_day_top5


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


def bandwidth_per_day_html():
	# Group by day_of_month, name, Device Name, ruleName and aggregate sum of packetCount
	bandwidth_per_day = data_month.groupby(['Day of the Month', 'Attack Name', 'Device Name', 'Policy Name'])['packetBandwidth'].sum()

	# Convert units to Megabytes/Gigabytes/Terabytes
	bandwidth_per_day = bandwidth_per_day.apply(bw_units_conversion)

	# Get the top 5 events with the highest sum of packet counts for each day
	bandwidth_per_day_top5 = bandwidth_per_day.groupby(level=['Day of the Month'], group_keys=False).nlargest(5).apply(format_with_commas).to_frame('Attack Volume sum')
	bandwidth_per_day_top5 = bandwidth_per_day_top5.to_html()

	for device_ip, device_name in defensepros.items():
		bandwidth_per_day_top5=bandwidth_per_day_top5.replace(device_ip, device_name)

	return bandwidth_per_day_top5


def packets_per_day_html():

	# Group by day_of_month, name, Device Name, ruleName and aggregate sum of packetCount
	packets_per_day = data_month.groupby(['Day of the Month', 'Attack Name', 'Device Name', 'Policy Name'])['packetCount'].sum()

	# Convert units
	packets_per_day = packets_per_day.apply(pkt_units_conversion)

	# Get the top 5 events with the highest sum of packet counts for each day
	packets_per_day_top5 = packets_per_day.groupby(level=['Day of the Month'], group_keys=False).nlargest(5).apply(format_with_commas).to_frame('Attack Packets sum')
	packets_per_day_top5 = packets_per_day_top5.to_html()

	for device_ip, device_name in defensepros.items():
		packets_per_day_top5=packets_per_day_top5.replace(device_ip, device_name)

	return packets_per_day_top5


def epm_html(epm):
	data_month_epm = data_month[data_month['Attack Name'] == epm]
	series_epm = data_month_epm.groupby(['Attack Name','Device Name','Policy Name']).size().sort_values(ascending=False).apply(format_with_commas).head(10)
	epm_html = series_epm.to_frame('Attack Events')
	epm_html=epm_html.to_html()

	for device_ip, device_name in defensepros.items():
		epm_html=epm_html.replace(device_ip, device_name)

	return epm_html

def ppm_html(ppm):
	data_month_ppm = data_month[data_month['Attack Name'] == ppm]
	series_ppm = data_month_ppm.groupby(['Attack Name','Device Name','Policy Name']).sum()['packetCount'].sort_values(ascending=False)
	# Convert units
	series_ppm = series_ppm.apply(pkt_units_conversion).apply(format_with_commas).head(10)
	ppm_html = series_ppm.to_frame('Attack Packets')
	ppm_html=ppm_html.to_html()

	for device_ip, device_name in defensepros.items():
		ppm_html=ppm_html.replace(device_ip, device_name)

	return ppm_html

def bpm_html(bpm):
	data_month_bpm = data_month[data_month['Attack Name'] == bpm]
	series_bpm = data_month_bpm.groupby(['Attack Name','Device Name','Policy Name']).sum()['packetBandwidth'].sort_values(ascending=False)
	# Convert units
	series_bpm = series_bpm.apply(bw_units_conversion).apply(format_with_commas).head(10)
	df_bpm_html = series_bpm.to_frame('Attack Volume')
	df_bpm_html=df_bpm_html.to_html()

	for device_ip, device_name in defensepros.items():
		df_bpm_html=df_bpm_html.replace(device_ip, device_name)

	return df_bpm_html



def device_epm_html(device_epm):
	device_epm_html = 'N/A'
	for device_ip, device_name in defensepros.items():
		if device_name == device_epm:
			data_month_epm = data_month[data_month['Device Name'] == device_ip]
			device_series_epm = data_month_epm.groupby(['Device Name','Attack Name','Policy Name']).size().sort_values(ascending=False).apply(format_with_commas).head(10)
			device_epm_html = device_series_epm.to_frame('Attack Events')
			device_epm_html=device_epm_html.to_html().replace(device_ip, device_name)
			return device_epm_html

	return device_epm_html


			

def device_ppm_html(device_ppm):
	device_ppm_html = 'N/A'
	for device_ip, device_name in defensepros.items():
		if device_name == device_ppm:
			data_month_ppm = data_month[data_month['Device Name'] == device_ip]
			device_series_ppm = data_month_ppm.groupby(['Device Name','Attack Name','Policy Name']).sum()['packetCount'].sort_values(ascending=False)
			device_series_ppm = device_series_ppm.apply(pkt_units_conversion).apply(format_with_commas).head(10)
			device_ppm_html = device_series_ppm.to_frame('Attack Packets')
			device_ppm_html=device_ppm_html.to_html().replace(device_ip, device_name)
			return device_ppm_html

	return device_ppm_html

def device_bpm_html(device_bpm):
	device_df_bpm_html = 'N/A'
	for device_ip, device_name in defensepros.items():
		if device_name == device_bpm:
			data_month_bpm = data_month[data_month['Device Name'] == device_ip]
			device_series_bpm = data_month_bpm.groupby(['Device Name','Attack Name','Policy Name']).sum()['packetBandwidth'].sort_values(ascending=False)
			device_series_bpm = device_series_bpm.apply(bw_units_conversion).apply(format_with_commas).head(10)
			device_df_bpm_html = device_series_bpm.to_frame('Attack Volume')
			device_df_bpm_html= device_df_bpm_html.to_html().replace(device_ip, device_name)
			return device_df_bpm_html

	return device_df_bpm_html


def policy_epm_html(policy_epm):

	data_month_epm = data_month[data_month['Policy Name'] == policy_epm]
	series_epm = data_month_epm.groupby(['Policy Name','Attack Name','Device Name']).size().sort_values(ascending=False).apply(format_with_commas).head(10)
	epm_html = series_epm.to_frame('Attack Events')
	epm_html=epm_html.to_html()

	for device_ip, device_name in defensepros.items():
		epm_html=epm_html.replace(device_ip, device_name)
		
	return epm_html

def policy_ppm_html(policy_ppm):
	data_month_ppm = data_month[data_month['Policy Name'] == policy_ppm]
	series_ppm = data_month_ppm.groupby(['Policy Name','Attack Name','Device Name']).sum()['packetCount'].sort_values(ascending=False)
	series_ppm = series_ppm.apply(pkt_units_conversion).apply(format_with_commas).head(10)
	ppm_html = series_ppm.to_frame('Attack Packets')
	ppm_html=ppm_html.to_html()
	
	for device_ip, device_name in defensepros.items():
		ppm_html=ppm_html.replace(device_ip, device_name)
	
	return ppm_html

def policy_bpm_html(policy_bpm):
	data_month_bpm = data_month[data_month['Policy Name'] == policy_bpm]
	series_bpm = data_month_bpm.groupby(['Policy Name','Attack Name','Device Name']).sum()['packetBandwidth'].sort_values(ascending=False)
	series_bpm = series_bpm.apply(bw_units_conversion).apply(format_with_commas).head(10)
	df_bpm_html = series_bpm.to_frame('Attack Volume')
	df_bpm_html=df_bpm_html.to_html()

	for device_ip, device_name in defensepros.items():
		df_bpm_html=df_bpm_html.replace(device_ip, device_name)
	
	return df_bpm_html


def sip_epm_html(sip_epm):

	data_month_epm = data_month[data_month['Source IP'] == sip_epm]
	series_epm = data_month_epm.groupby(['Source IP','Attack Name','Device Name','Policy Name']).size().sort_values(ascending=False).apply(format_with_commas).head(10)
	epm_html = series_epm.to_frame('Attack Events')
	epm_html=epm_html.to_html()

	for device_ip, device_name in defensepros.items():
		epm_html=epm_html.replace(device_ip, device_name)
		
	return epm_html


def sip_ppm_html(sip_ppm):
	data_month_ppm = data_month[data_month['Source IP'] == sip_ppm]
	series_ppm = data_month_ppm.groupby(['Source IP','Attack Name','Device Name','Policy Name']).sum()['packetCount'].sort_values(ascending=False)
	series_ppm = series_ppm.apply(pkt_units_conversion).apply(format_with_commas).head(10)
	ppm_html = series_ppm.to_frame('Attack Packets')
	ppm_html=ppm_html.to_html()
	
	for device_ip, device_name in defensepros.items():
		ppm_html=ppm_html.replace(device_ip, device_name)
	
	return ppm_html

def sip_bpm_html(sip_bpm):
	data_month_bpm = data_month[data_month['Source IP'] == sip_bpm]
	series_bpm = data_month_bpm.groupby(['Source IP','Attack Name','Device Name','Policy Name']).sum()['packetBandwidth'].sort_values(ascending=False)
	series_bpm = series_bpm.apply(bw_units_conversion).apply(format_with_commas).head(10)
	df_bpm_html = series_bpm.to_frame('Attack Volume')
	df_bpm_html=df_bpm_html.to_html()

	for device_ip, device_name in defensepros.items():
		df_bpm_html=df_bpm_html.replace(device_ip, device_name)
	
	return df_bpm_html





def format_with_commas(value):
	return '{:,}'.format(value)

if __name__ == '__main__':

	maxpps_per_day_trends = convert_csv_to_list_of_lists(charts_tables_path + 'maxpps_per_day_last_month.csv')

	# Attack Volume per day
	maxbps_per_day_trends = convert_csv_to_list_of_lists(charts_tables_path + 'maxbps_per_day_last_month.csv')
	
	# Events per day count
	events_per_day_trends = convert_csv_to_list_of_lists(charts_tables_path + 'events_per_day_last_month.csv')
	
	# Attack Volume per day
	bandwidth_per_day_trends = convert_csv_to_list_of_lists(charts_tables_path + 'bandwidth_per_day_last_month.csv')

	# Attack Volume per day
	packets_per_day_trends = convert_csv_to_list_of_lists(charts_tables_path + 'packets_per_day_last_month.csv')


	# Total events, packets and bandwidth trends (blue bars charts)
	events_total_bar_chart = convert_csv_to_list_of_lists(charts_tables_path + 'epm_total_bar.csv')
	# Add labels annotations to the bar charts
	events_total_bar_chart_max = 0
	if bar_charts_annotations:
		events_total_bar_chart[0].append({'role': 'annotation'})
		
		# Add the third column (annotation) to each row
		for row in events_total_bar_chart[1:]:
			if row[1] > events_total_bar_chart_max: # Find the maximum value for the y-axis
				events_total_bar_chart_max = int(row[1]*1.1)
			row.append(int(row[1]))  

	events_total_bar_move_text = trends_move_total(events_total_bar_chart, 'events')

	packets_total_bar = convert_csv_to_list_of_lists(charts_tables_path + 'ppm_total_bar.csv')
	packets_total_bar = convert_packets_units(packets_total_bar, pkt_units)

	# Add labels annotations to the bar charts
	packets_total_bar_max = 0
	if bar_charts_annotations:
		packets_total_bar[0].append({'role': 'annotation'})
		# Add the third column (annotation) to each row
		for row in packets_total_bar[1:]:
			if row[1] > packets_total_bar_max: # Find the maximum value for the y-axis
				packets_total_bar_max = int(row[1]*1.1)
			row.append(int(row[1])) 

	pakets_total_bar_move = trends_move_total(packets_total_bar, ' packets(' + pkt_units + ')')

	bw_total_bar = convert_csv_to_list_of_lists(charts_tables_path + 'bpm_total_bar.csv')
	bw_total_bar = convert_bw_units(bw_total_bar, bw_units)

	# Add labels annotations to the bar charts
	bw_total_bar_max = 0

	if bar_charts_annotations:
		bw_total_bar[0].append({'role': 'annotation'})
		# Add the third column (annotation) to each row
		for row in bw_total_bar[1:]:
			if row[1] > bw_total_bar_max: # Find the maximum value for the y-axis
				bw_total_bar_max = int(row[1]*1.1)
			row.append(float(row[1])) 

	bw_total_bar_move = trends_move_total(bw_total_bar, ' attack volume(' + bw_units + ')'  ) 

	################################################# Events, packets and bandwidth trends by Attack name sorted by the last month ##########################################################
	events_trends = convert_csv_to_list_of_lists(charts_tables_path + 'epm_chart_lm.csv')
	events_trends_move = trends_move(events_trends, 'events')
	events_trends_table = csv_to_html_table(charts_tables_path + 'epm_table_lm.csv')

	packets_trends_chart = convert_csv_to_list_of_lists(charts_tables_path + 'ppm_chart_lm.csv')
	packets_trends_chart = convert_packets_units(packets_trends_chart, pkt_units)
	packets_trends_move_text = trends_move(packets_trends_chart, ' packets(' + pkt_units + ')')
	packets_table = csv_to_html_table(charts_tables_path + 'ppm_table_lm.csv',bw_units=None, pkt_units=pkt_units)


	bw_trends = convert_csv_to_list_of_lists(charts_tables_path + 'bpm_chart_lm.csv')
	bw_trends = convert_bw_units(bw_trends, bw_units)
	bw_trends_move = trends_move(bw_trends, bw_units)
	bw_table = csv_to_html_table(charts_tables_path + 'bpm_table_lm.csv',bw_units)


	total_attacks_days_bar_chart = convert_csv_to_list_of_lists(charts_tables_path + 'total_attack_time_bar.csv')

	# Add labels annotations to the bar charts
	total_attacks_days_bar_chart_max = 0

	if bar_charts_annotations:
		total_attacks_days_bar_chart[0].append({'role': 'annotation'})
		# Add the third column (annotation) to each row
		for row in total_attacks_days_bar_chart[1:]:
			if row[1] > total_attacks_days_bar_chart_max: # Find the maximum value for the y-axis
				total_attacks_days_bar_chart_max = int(row[1]*1.2)
			row.append(float(row[1]))  


	################################################# Analyze deeper top category ##########################################################

	#1 Create a data frame
	con = sqlite3.connect(db_path + 'database_' + cust_id + '_' + str(month) + '_' + str(year) + '.sqlite')
	# data = pd.read_sql_query("SELECT * from attacks", con)
	if db_from_forensics:
		data_month = pd.read_sql_query(f"SELECT deviceName as 'Device Name',month,year,packetBandwidth,name as 'Attack Name',packetCount,ruleName as 'Policy Name',category,sourceAddress as 'Source IP',destAddress,startTime,endTime,startDate,attackIpsId,actionType,maxAttackPacketRatePps,maxAttackRateBps,destPort,protocol,startDayOfMonth as 'Day of the Month' from attacks", con)
	else:
		data_month = pd.read_sql_query(f"SELECT deviceName as 'Device Name',month,year,packetBandwidth,name as 'Attack Name',packetCount,ruleName as 'Policy Name',category,sourceAddress as 'Source IP',destAddress,startTime,endTime,startDate,attackIpsId,actionType,maxAttackPacketRatePps,maxAttackRateBps,destPort,protocol,geoLocation,startDayOfMonth as 'Day of the Month' from attacks", con)

	#export data to csv
	data_month.to_csv(reports_path +'database_'+cust_id+'_'+str(month)+'_'+str(year)+'.csv', encoding='utf-8', index=False)


	con.close()

	#2 Extract Top Attacks list

	epm_top_list=extract_values_from_csv('epm_table_lm.csv')
	ppm_top_list=extract_values_from_csv('ppm_table_lm.csv')
	bpm_top_list=extract_values_from_csv('bpm_table_lm.csv')

	device_epm_top_list=extract_values_from_csv('device_epm_table_lm.csv')
	device_ppm_top_list=extract_values_from_csv('device_ppm_table_lm.csv')
	device_bpm_top_list=extract_values_from_csv('device_bpm_table_lm.csv')

	policy_epm_top_list=extract_values_from_csv('policy_epm_table_lm.csv')
	policy_ppm_top_list=extract_values_from_csv('policy_ppm_table_lm.csv')
	policy_bpm_top_list=extract_values_from_csv('policy_bpm_table_lm.csv')

	sip_epm_top_list=extract_values_from_csv('sip_epm_table_lm.csv')
	sip_ppm_top_list=extract_values_from_csv('sip_ppm_table_lm.csv')
	sip_bpm_top_list=extract_values_from_csv('sip_bpm_table_lm.csv')

	#3 Create empty html table
	epm_html_final = ''
	ppm_html_final = ''
	bpm_html_final = ''

	device_epm_html_final = ''
	device_ppm_html_final = ''
	device_bpm_html_final = ''

	policy_epm_html_final = ''
	policy_ppm_html_final = ''
	policy_bpm_html_final = ''

	sip_epm_html_final = ''
	sip_ppm_html_final = ''
	sip_bpm_html_final = ''

	#4 Iterate through each Device and popluate the html table



	for index, value in enumerate(epm_top_list):
		epm_html_final+=f'<h4>{value} distribution across devices and policies</h4>'
		epm_html_final+= epm_html(epm_top_list[index])

	for index, value in enumerate(ppm_top_list):
		ppm_html_final+=f'<h4>{value} distribution across devices and policies</h4>'
		ppm_html_final+= ppm_html(ppm_top_list[index])
		
	for index, value in enumerate(bpm_top_list):
		bpm_html_final+=f'<h4>{value} distribution across devices and policies</h4>'
		bpm_html_final+= bpm_html(bpm_top_list[index])


	for index, value in enumerate(device_epm_top_list):
		device_epm_html_final+=f'<h4>Top Attacks and policies for device {value}</h4>'
		device_epm_html_final+= device_epm_html(device_epm_top_list[index])

	for index, value in enumerate(device_ppm_top_list):
		device_ppm_html_final+=f'<h4>Top Attacks and policies for device {value}</h4>'
		device_ppm_html_final+= device_ppm_html(device_ppm_top_list[index])

	for index, value in enumerate(device_bpm_top_list):
		device_bpm_html_final+=f'<h4>Top Attacks and policies for device {value}</h4>'
		device_bpm_html_final+= device_bpm_html(device_ppm_top_list[index])


	for index, value in enumerate(policy_epm_top_list):
		policy_epm_html_final+=f'<h4>Distribution of attacks and devices for policy {value}</h4>'
		policy_epm_html_final+= policy_epm_html(policy_epm_top_list[index])

	for index, value in enumerate(policy_ppm_top_list):
		policy_ppm_html_final+=f'<h4>Distribution of attacks and devices for policy {value}</h4>'
		policy_ppm_html_final+= policy_ppm_html(policy_ppm_top_list[index])
		
	for index, value in enumerate(policy_bpm_top_list):
		policy_bpm_html_final+=f'<h4>Distribution of attacks and devices for policy {value}</h4>'
		policy_bpm_html_final+= policy_bpm_html(policy_bpm_top_list[index])


	for index, value in enumerate(sip_epm_top_list):
		sip_epm_html_final+=f'<h4>Distribution of attacks and devices for Source IP {value}</h4>'
		sip_epm_html_final+= sip_epm_html(sip_epm_top_list[index])

	for index, value in enumerate(sip_ppm_top_list):
		sip_ppm_html_final+=f'<h4>Distribution of attacks and devices for Source IP {value}</h4>'
		sip_ppm_html_final+= sip_ppm_html(sip_ppm_top_list[index])
		
	for index, value in enumerate(sip_bpm_top_list):
		sip_bpm_html_final+=f'<h4>Distribution of attacks and devices for Source IP {value}</h4>'
		sip_bpm_html_final+= sip_bpm_html(sip_bpm_top_list[index])


	#5 Generate html for the last month


	maxpps_per_day_table = maxpps_per_day_html_table()
	maxbps_per_day_table = maxbps_per_day_html_table()

	events_per_day_table = events_per_day_html()
	bandwidth_per_day_table = bandwidth_per_day_html()
	packets_per_day_table = packets_per_day_html()
	################################################# Events, packets and bandwidth trends by Attack name sorted by the overall sum of all months together ##########################################################


	events_trends_alltimehigh = convert_csv_to_list_of_lists(charts_tables_path + 'epm_chart_alltimehigh.csv')
	events_trends_move_alltimehigh = trends_move(events_trends_alltimehigh, 'events')
	events_trends_table_alltimehigh = csv_to_html_table(charts_tables_path + 'epm_table_alltimehigh.csv')

	packets_trends_chart_alltimehigh = convert_csv_to_list_of_lists(charts_tables_path + 'ppm_chart_alltimehigh.csv')
	packets_trends_chart_alltimehigh = convert_packets_units(packets_trends_chart_alltimehigh, pkt_units)
	packets_trends_move_text_alltimehigh = trends_move(packets_trends_chart_alltimehigh, ' packets(' + pkt_units + ')')
	packets_table_alltimehigh = csv_to_html_table(charts_tables_path + 'ppm_table_alltimehigh.csv',bw_units=None, pkt_units=pkt_units)


	bw_trends_alltimehigh = convert_csv_to_list_of_lists(charts_tables_path + 'bpm_chart_alltimehigh.csv')
	bw_trends_alltimehigh = convert_bw_units(bw_trends_alltimehigh, bw_units)
	bw_trends_move_alltimehigh = trends_move(bw_trends_alltimehigh, bw_units)
	bw_table_alltimehigh = csv_to_html_table(charts_tables_path + 'bpm_table_alltimehigh.csv',bw_units)


	################################################# Events, packets and bandwidth trends by Device  ##########################################################

	events_by_device_trends_chart_data = convert_csv_to_list_of_lists(charts_tables_path + 'device_epm_chart_lm.csv')
	events_by_device_trends_move_text = trends_move(events_by_device_trends_chart_data, 'events')
	events_by_device_table = csv_to_html_table(charts_tables_path + 'device_epm_table_lm.csv')

	packets_by_device_trends_chart_data = convert_csv_to_list_of_lists(charts_tables_path + 'device_ppm_chart_lm.csv')
	packets_by_device_trends_chart_data = convert_packets_units(packets_by_device_trends_chart_data, pkt_units)
	packets_by_device_trends_move_text = trends_move(packets_by_device_trends_chart_data, ' packets(' + pkt_units + ')')
	packets_by_device_table = csv_to_html_table(charts_tables_path + 'device_ppm_table_lm.csv',bw_units=None, pkt_units=pkt_units)


	bw_by_device_trends_chart_data = convert_csv_to_list_of_lists(charts_tables_path + 'device_bpm_chart_lm.csv')
	bw_by_device_trends_chart_data = convert_bw_units(bw_by_device_trends_chart_data, bw_units)
	bw_by_device_trends_move_text = trends_move(bw_by_device_trends_chart_data, bw_units)
	bw_by_device_table = csv_to_html_table(charts_tables_path + 'device_bpm_table_lm.csv',bw_units)



	# Total events by device this month (blue bars charts)
	device_epm_chart_this_month = convert_csv_to_list_of_lists(charts_tables_path + 'device_epm_chart_this_month.csv')

	# Add labels annotations to the bar charts and replace IPs with names


	device_epm_chart_this_month_max = 0

	# Add the third column (annotation) to each row
	if bar_charts_annotations:
		device_epm_chart_this_month[0].append({'role': 'annotation'})

	for row in device_epm_chart_this_month[1:]:
		row[0] = defensepros.get(row[0], row[0])  # Keep IP if no match found

		if bar_charts_annotations:
			if row[1] > device_epm_chart_this_month_max: # Find the maximum value for the y-axis
				device_epm_chart_this_month_max = int(row[1]*1.1)
			row.append(int(row[1]))
		

	# Attack Packets by device this month (blue bars charts)
	device_ppm_chart_this_month = convert_csv_to_list_of_lists(charts_tables_path + 'device_ppm_chart_this_month.csv')
	device_ppm_chart_this_month = convert_packets_units(device_ppm_chart_this_month, pkt_units)

	device_ppm_chart_this_month_max = 0
	# Add labels annotations to the bar charts and replace IPs with names
	if bar_charts_annotations:
		device_ppm_chart_this_month[0].append({'role': 'annotation'})
	
	# Add the third column (annotation) to each row
	
	for row in device_ppm_chart_this_month[1:]:
		row[0] = defensepros.get(row[0], row[0])  	# Replace IPs with names # Keep IP if no match found
		if bar_charts_annotations:
			if row[1] > device_ppm_chart_this_month_max: # Find the maximum value for the y-axis
				device_ppm_chart_this_month_max = int(row[1]*1.1)
			row.append(int(row[1]))  # Populate annotataion column with the same value as the data column

	# Attack Volume by device this month (blue bars charts)
	device_bpm_chart_this_month = convert_csv_to_list_of_lists(charts_tables_path + 'device_bpm_chart_this_month.csv')
	device_bpm_chart_this_month = convert_bw_units(device_bpm_chart_this_month, bw_units)

	# Add labels annotations to the bar charts and replace IPs with names
	device_bpm_chart_this_month_max = 0
	if bar_charts_annotations:
		device_bpm_chart_this_month[0].append({'role': 'annotation'})
		
	# Add the third column (annotation) to each row
	for row in device_bpm_chart_this_month[1:]:
		row[0] = defensepros.get(row[0], row[0])  	# Replace IPs with names # Keep IP if no match found
		if bar_charts_annotations:
			if row[1] > device_bpm_chart_this_month_max: # Find the maximum value for the y-axis
				device_bpm_chart_this_month_max = int(row[1]*1.1)
			row.append(float(row[1]))  

	################################################# Top source IP(bw is Megabytes) ##########################################################		
	sip_events_trends_chart = convert_csv_to_list_of_lists(charts_tables_path + 'sip_epm_chart_lm.csv')
	sip_events_trends_move_text = trends_move(sip_events_trends_chart, 'events')
	sip_events_trends_table = csv_to_html_table(charts_tables_path + 'sip_epm_table_lm.csv')

	sip_packets_trends_chart = convert_csv_to_list_of_lists(charts_tables_path + 'sip_ppm_chart_lm.csv')
	sip_packets_trends_chart = convert_packets_units(sip_packets_trends_chart, pkt_units=None)
	sip_packets_trends_move_text = trends_move(sip_packets_trends_chart, ' packets(' + pkt_units + ')')
	sip_packets_table = csv_to_html_table(charts_tables_path + 'sip_ppm_table_lm.csv',bw_units=None, pkt_units=None)


	sip_bw_trends_chart = convert_csv_to_list_of_lists(charts_tables_path + 'sip_bpm_chart_lm.csv')
	# sip_bw_trends_chart = convert_bw_units(sip_bw_trends_chart, sip_bw_units)
	# sip_bw_trends_move_text = trends_move(sip_bw_trends_chart, sip_bw_units)
	sip_bw_table = csv_to_html_table(charts_tables_path + 'sip_bpm_table_lm.csv')

	################################################# Events, packets and bandwidth trends by Policy ##########################################################

	policy_events_trends_chart = convert_csv_to_list_of_lists(charts_tables_path + 'policy_epm_chart_lm.csv')
	policy_events_trends_move_text = trends_move(policy_events_trends_chart, 'events')
	policy_events_trends_table = csv_to_html_table(charts_tables_path + 'policy_epm_table_lm.csv')

	policy_packets_trends_chart = convert_csv_to_list_of_lists(charts_tables_path + 'policy_ppm_chart_lm.csv')
	policy_packets_trends_chart = convert_packets_units(policy_packets_trends_chart, pkt_units)
	policy_packets_trends_move_text = trends_move(policy_packets_trends_chart, ' packets(' + pkt_units + ')')
	policy_packets_table = csv_to_html_table(charts_tables_path + 'policy_ppm_table_lm.csv',bw_units=None, pkt_units=pkt_units)

	policy_bw_trends_chart = convert_csv_to_list_of_lists(charts_tables_path + 'policy_bpm_chart_lm.csv')
	policy_bw_trends_chart = convert_bw_units(policy_bw_trends_chart, bw_units)
	policy_bw_trends_move_text = trends_move(policy_bw_trends_chart, bw_units)
	policy_bw_table = csv_to_html_table(charts_tables_path + 'policy_bpm_table_lm.csv',bw_units)


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
		  var colorMap = {{}}; // Store colors globally
		  function drawChart() {{
			


  
			var epm_total_data = google.visualization.arrayToDataTable({events_total_bar_chart});
			var ppm_total_data = google.visualization.arrayToDataTable({packets_total_bar});
			var bpm_total_data = google.visualization.arrayToDataTable({bw_total_bar});

			var epm_data = google.visualization.arrayToDataTable({events_trends});
			var ppm_data = google.visualization.arrayToDataTable({packets_trends_chart});
			var bpm_data = google.visualization.arrayToDataTable({bw_trends});

			var epm_data_alltimehigh = google.visualization.arrayToDataTable({events_trends_alltimehigh});
			var ppm_data_alltimehigh = google.visualization.arrayToDataTable({packets_trends_chart_alltimehigh});
			var bpm_data_alltimehigh = google.visualization.arrayToDataTable({bw_trends_alltimehigh});

			var epm_by_device_data = google.visualization.arrayToDataTable({events_by_device_trends_chart_data});
			var ppm_by_device_data = google.visualization.arrayToDataTable({packets_by_device_trends_chart_data});
			var bpm_by_device_data = google.visualization.arrayToDataTable({bw_by_device_trends_chart_data});

			var device_epm_chart_this_month_data = google.visualization.arrayToDataTable({device_epm_chart_this_month});
			var device_ppm_chart_this_month_data = google.visualization.arrayToDataTable({device_ppm_chart_this_month});
			var device_bpm_chart_this_month_data = google.visualization.arrayToDataTable({device_bpm_chart_this_month});

			var sip_epm_data = google.visualization.arrayToDataTable({sip_events_trends_chart});
			var sip_ppm_data = google.visualization.arrayToDataTable({sip_packets_trends_chart});
			var sip_bpm_data = google.visualization.arrayToDataTable({sip_bw_trends_chart});

			var policy_epm_data = google.visualization.arrayToDataTable({policy_events_trends_chart });
			var policy_ppm_data = google.visualization.arrayToDataTable({policy_packets_trends_chart });
			var policy_bpm_data = google.visualization.arrayToDataTable({policy_bw_trends_chart });

			var total_attacks_days_data = google.visualization.arrayToDataTable({total_attacks_days_bar_chart});

			


			var epm_total_options = {{
			  title: 'Total Attack Events trends',
			  bar: {{groupWidth: "70%"}},
			  legend: {{position: 'bottom'}},
			  hAxis: {{
				title: 'Months',
				}},
			  vAxis: {{
				title: 'Number of attack events',
				minValue: 0,
				maxValue: {events_total_bar_chart_max}
				}},
			  annotations: {{
            	alwaysOutside: true
				}},
			  width: '100%'
			}};

			var ppm_total_options = {{
			  title: 'Total Attack Packets trends(cumulative)',
			  bar: {{groupWidth: "70%"}},
			  legend: {{
				position: 'bottom'
				}},
			  hAxis: {{
				title: 'Months',
				}},
			  vAxis: {{
				title: 'Attack packets (units {pkt_units})',
				minValue: 0,
				maxValue: {packets_total_bar_max}
				}},
			  annotations: {{
            	alwaysOutside: true
				}},
			  width: '100%'
			}};

			var bpm_total_options = {{
			  title: 'Total Attack volume trends(cumulative)',
			  bar: {{
				groupWidth: "70%"
				}},
			  legend: {{
				position: 'bottom'
				}},
			  hAxis: {{
				title: 'Months'
				}},
			  vAxis: {{
				title: 'Attack volume (units {bw_units})',
				minValue: 0,
				maxValue: {bw_total_bar_max}
				}},
			  annotations: {{
            	alwaysOutside: true
				}},
			  width: '100%'
			}};

			var epm_options = {{
			  title: 'Number of Attack Events - Ranked by Last Month',
			  vAxis: {{
				minValue: 0,
				title: 'Number of attack events'}},
			  hAxis: {{
				title: 'Months'
				}},
			  isStacked: false,
			  focusTarget: 'category',
			  legend: {{position: 'top', maxLines: 5}},
			  width: '100%'
			}};

			var ppm_options = {{
			  title: 'Attack Packets trends - Ranked by Last Month',
			  vAxis: {{
				minValue: 0,
				title: 'Attack packets (units {pkt_units})'}},
			  hAxis: {{
				title: 'Months'
				}},
			  isStacked: false,
			  focusTarget: 'category',
			  legend: {{position: 'top', maxLines: 5}},
			  width: '100%'
			}};

			var bpm_options = {{
			  title: 'Attack volume trends - Ranked by Last Month',
			  vAxis: {{
				minValue: 0,
				title: 'Attack volume (units {bw_units})'}},
			  hAxis: {{
				title: 'Months',
				}},
			  isStacked: false,
			  focusTarget: 'category',
			  legend: {{position: 'top', maxLines: 5}},
			  width: '100%'
			}};

			var epm_options_alltimehigh = {{
			  title: 'Top {top_n} Attacks trends - Ranked by All Months Combined',
			  vAxis: {{
				minValue: 0,
				title: 'Number of Attack Events'}},
			  hAxis: {{
				title: 'Months',
				}},
			  isStacked: false,
			  focusTarget: 'category',
			  legend: {{position: 'top', maxLines: 5}},
			  width: '100%'
			}};

			var ppm_options_alltimehigh = {{
			  title: 'Attack Packets trends - {top_n} all time high',
			  vAxis: {{
				minValue: 0,
				title: 'Attack Packets (units {pkt_units})'}},
			  hAxis: {{
				title: 'Months',
				}},
			  isStacked: false,
			  focusTarget: 'category',
			  legend: {{position: 'top', maxLines: 5}},
			  width: '100%'
			}};

			var bpm_options_alltimehigh = {{
			  title: 'Attack Volume trends - {top_n} all time high',
			  vAxis: {{
				minValue: 0,
				title: 'Attack Volume (units {bw_units})'}},
			  hAxis: {{
				title: 'Months',
				}},
			  isStacked: false,
			  focusTarget: 'category',
			  legend: {{position: 'top', maxLines: 5}},
			  width: '100%'
			}};

			var epm_by_device_options = {{
			  title: 'Attack Events by device trends',
			  vAxis: {{
				minValue: 0,
				title: 'Number of Attack Events'}},
			  hAxis: {{
				title: 'Months',
				}},
			  isStacked: false,
			  focusTarget: 'category',
			  legend: {{position: 'top', maxLines: 5}},
			  width: '100%'
			}};

			var ppm_by_device_options = {{
			  title: 'Attack Packets by device trends',
			  vAxis: {{
				minValue: 0,
				title: 'Attack Packets (units {pkt_units})'}},
			  hAxis: {{
				title: 'Months',
				}},
			  isStacked: false,
			  focusTarget: 'category',
			  legend: {{position: 'top', maxLines: 5}},
			  width: '100%'
			}};

			var bpm_by_device_options = {{
			  title: 'Attack Volume by device trends',
			  vAxis: {{
				minValue: 0,
				title: 'Attack Volume (units {bw_units})'}},
			  hAxis: {{
				title: 'Months',
				}},
			  isStacked: false,
			  focusTarget: 'category',
			  legend: {{position: 'top', maxLines: 5}},
			  width: '100%'
			}};

			
			var device_epm_chart_this_month_options = {{
			  title: 'Number of Attack Events by device - this Month',
			  bar: {{groupWidth: "70%"}},
			  legend: {{position: 'bottom'}},
			  hAxis: {{
				title: 'Device',
				}},
			  vAxis: {{
				title: 'Number of Attack Events',
				minValue: 0,
				maxValue: {device_epm_chart_this_month_max}
				}},
			  annotations: {{
            	alwaysOutside: true
				}},
			  width: '100%'
			}};

			var device_ppm_chart_this_month_options = {{
			  title: 'Attack Packets by device - this Month',
			  bar: {{groupWidth: "70%"}},
			  legend: {{
				position: 'bottom'
				}},
			  hAxis: {{
				title: 'Device',
				}},
			  vAxis: {{
				title: 'Attack Packets (units {pkt_units})',
				minValue: 0,
				maxValue: {device_ppm_chart_this_month_max}
				}},
			  annotations: {{
            	alwaysOutside: true
				}},
			  width: '100%'
			}};

			var device_bpm_chart_this_month_options = {{
			  title: 'Attack Volume by device - this Month',
			  bar: {{groupWidth: "70%"}},
			  legend: {{
				position: 'bottom'
				}},
			  hAxis: {{
				title: 'Device',
				}},
			  vAxis: {{
				title: 'Attack Volume (units {bw_units})',
				minValue: 0,
				maxValue: {device_bpm_chart_this_month_max}
				}},
			  annotations: {{
				alwaysOutside: true
				}},
			  width: '100%'
			}};



			var sip_epm_options = {{
			  title: 'Attack Events trends by source IP',
			  vAxis: {{
				minValue: 0,
				title: 'Number of Attack Events'}},
			  hAxis: {{
				title: 'Months',
				}},
			  isStacked: false,
			  focusTarget: 'category',
			  legend: {{position: 'top', maxLines: 5}},
			  width: '100%'
			}};

			var sip_ppm_options = {{
			  title: 'Attack Packets trends - by source IP',
			  vAxis: {{
				minValue: 0,
				title: 'Attack Packets'}},
			  hAxis: {{
				title: 'Months',
				}},
			  isStacked: false,
			  focusTarget: 'category',
			  legend: {{position: 'top', maxLines: 5}},
			  width: '100%'
			}};

			var sip_bpm_options = {{
			  title: 'Attack Volume trends - by source IP',
			  vAxis: {{
				minValue: 0,
				title: 'Attack Volume (units Megabytes)'}},
			  hAxis: {{
				title: 'Months',
				}},
			  isStacked: false,
			  focusTarget: 'category',
			  legend: {{position: 'top', maxLines: 5}},
			  width: '100%'
			}};

			var policy_epm_options = {{
			  title: 'Attack Events trends by Policy',
			  vAxis: {{
				minValue: 0,
				title: 'Number of Attack Events'}},
			  hAxis: {{
				title: 'Months',
				}},
			  isStacked: false,
			  focusTarget: 'category',
			  legend: {{position: 'top', maxLines: 5}},
			  width: '100%'
			}};

			var policy_ppm_options = {{
			  title: 'Attack Packets trends - by Policy',
			  vAxis: {{
				minValue: 0,
				title: 'Attack Packets (units {pkt_units})'}},
			  hAxis: {{
				title: 'Months',
				}},
			  isStacked: false,
			  focusTarget: 'category',
			  legend: {{position: 'top', maxLines: 5}},
			  width: '100%'
			}};

			var policy_bpm_options = {{
			  title: 'Attack Volume trends - by Policy',
			  vAxis: {{
				minValue: 0,
				title: 'Attack Volume (units {bw_units})'}},
			  hAxis: {{
				title: 'Months',
				}},
			  isStacked: false,
			  focusTarget: 'category',
			  legend: {{position: 'top', maxLines: 5}},
			  width: '100%'
			}};


			var total_attacks_days_options = {{
			  title: 'Total Attack Time in days',
			  bar: {{groupWidth: "70%"}},

			  vAxis: {{
				title: 'Sum of Attack Duration in Days',
				minValue: 0,
				maxValue: {total_attacks_days_bar_chart_max}
				}},
			  hAxis: {{
				title: 'Months',
				}},
			  legend: {{position: 'bottom'}},
			  annotations: {{
            	alwaysOutside: true
				}},
			  width: '100%'
			}};



			var epm_total_chart = new google.visualization.ColumnChart(document.getElementById('epm_total_chart_div'));
			var ppm_total_chart = new google.visualization.ColumnChart(document.getElementById('ppm_total_chart_div'));
			var bpm_total_chart = new google.visualization.ColumnChart(document.getElementById('bpm_total_chart_div'));

			var epm_chart = new google.visualization.AreaChart(document.getElementById('epm_chart_div'));
			var ppm_chart = new google.visualization.AreaChart(document.getElementById('ppm_chart_div'));
			var bpm_chart = new google.visualization.AreaChart(document.getElementById('bpm_chart_div'));

			var epm_chart_alltimehigh = new google.visualization.AreaChart(document.getElementById('epm_chart_div_alltimehigh'));
			var ppm_chart_alltimehigh = new google.visualization.AreaChart(document.getElementById('ppm_chart_div_alltimehigh'));
			var bpm_chart_alltimehigh = new google.visualization.AreaChart(document.getElementById('bpm_chart_div_alltimehigh'));

			var device_epm_chart_this_month_chart = new google.visualization.ColumnChart(document.getElementById('device_epm_chart_this_month_div'));
			var device_ppm_chart_this_month_chart = new google.visualization.ColumnChart(document.getElementById('device_ppm_chart_this_month_div'));
			var device_bpm_chart_this_month_chart = new google.visualization.ColumnChart(document.getElementById('device_bpm_chart_this_month_div'));

			var epm_by_device_chart = new google.visualization.AreaChart(document.getElementById('epm_by_device_chart_div'));
			var ppm_by_device_chart = new google.visualization.AreaChart(document.getElementById('ppm_by_device_chart_div'));
			var bpm_by_device_chart = new google.visualization.AreaChart(document.getElementById('bpm_by_device_chart_div'));

			var sip_epm_chart = new google.visualization.AreaChart(document.getElementById('sip_epm_chart_div'));
			var sip_ppm_chart = new google.visualization.AreaChart(document.getElementById('sip_ppm_chart_div'));
			var sip_bpm_chart = new google.visualization.AreaChart(document.getElementById('sip_bpm_chart_div'));		

			var policy_epm_chart = new google.visualization.AreaChart(document.getElementById('policy_epm_chart_div'));
			var policy_ppm_chart = new google.visualization.AreaChart(document.getElementById('policy_ppm_chart_div'));
			var policy_bpm_chart = new google.visualization.AreaChart(document.getElementById('policy_bpm_chart_div'));

			var total_attacks_days_chart = new google.visualization.ColumnChart(document.getElementById('total_attacks_days_chart_div'));		



			// Create checkboxes for "Number of Attack Events - Ranked by Last Month"
			createCheckboxes('epm_chart_div', {events_trends}, epm_options, function(selectedCategories) {{
				var filteredData = filterDataByCategories({events_trends}, selectedCategories);
				var filteredDataTable = google.visualization.arrayToDataTable(filteredData);
				epm_chart.draw(filteredDataTable, epm_options);
			}});

			// Create checkboxes for "Attack Packets trends - Ranked by Last Month"
			createCheckboxes('ppm_chart_div', {packets_trends_chart}, ppm_options, function(selectedCategories) {{
				var filteredData = filterDataByCategories({packets_trends_chart}, selectedCategories);
				var filteredDataTable = google.visualization.arrayToDataTable(filteredData);
				ppm_chart.draw(filteredDataTable, ppm_options);
			}});

			// Create checkboxes for "Attack volume trends - Ranked by Last Month"
			createCheckboxes('bpm_chart_div', {bw_trends}, bpm_options, function(selectedCategories) {{
				var filteredData = filterDataByCategories({bw_trends}, selectedCategories);
				var filteredDataTable = google.visualization.arrayToDataTable(filteredData);
				bpm_chart.draw(filteredDataTable, bpm_options);
			}});

			////////////////////////////////////////////////////////////////////////////////////////////////////////////

			// Create checkboxes for "Top {top_n} Attacks trends - Ranked by All Months Combined"
			createCheckboxes('epm_chart_div_alltimehigh', {events_trends_alltimehigh}, epm_options_alltimehigh, function(selectedCategories) {{
				var filteredData = filterDataByCategories({events_trends_alltimehigh}, selectedCategories);
				var filteredDataTable = google.visualization.arrayToDataTable(filteredData);
				epm_chart_alltimehigh.draw(filteredDataTable, epm_options_alltimehigh);
			}});

			// Create checkboxes for "Attack Packets trends - {top_n} all time high"
			createCheckboxes('ppm_chart_div_alltimehigh', {packets_trends_chart_alltimehigh}, ppm_options_alltimehigh, function(selectedCategories) {{
				var filteredData = filterDataByCategories({packets_trends_chart_alltimehigh}, selectedCategories);
				var filteredDataTable = google.visualization.arrayToDataTable(filteredData);
				ppm_chart_alltimehigh.draw(filteredDataTable, ppm_options_alltimehigh);
			}});

			// Create checkboxes for "Attack Volume trends - {top_n} all time high"
			createCheckboxes('bpm_chart_div_alltimehigh', {bw_trends_alltimehigh}, bpm_options_alltimehigh, function(selectedCategories) {{
				var filteredData = filterDataByCategories({bw_trends_alltimehigh}, selectedCategories);
				var filteredDataTable = google.visualization.arrayToDataTable(filteredData);
				bpm_chart_alltimehigh.draw(filteredDataTable, bpm_options_alltimehigh);
			}});

			///////////////////////////////////////////////////////////////////////////////////////////////////////

			// Create checkboxes for "Events by device trends"
			createCheckboxes('epm_by_device_chart_div', {events_by_device_trends_chart_data}, epm_by_device_options, function(selectedCategories) {{
				var filteredData = filterDataByCategories({events_by_device_trends_chart_data}, selectedCategories);
				var filteredDataTable = google.visualization.arrayToDataTable(filteredData);
				epm_by_device_chart.draw(filteredDataTable, epm_by_device_options);
			}});

			// Create checkboxes for "Attack Packets by device trends"
			createCheckboxes('ppm_by_device_chart_div', {packets_by_device_trends_chart_data}, ppm_by_device_options, function(selectedCategories) {{
				var filteredData = filterDataByCategories({packets_by_device_trends_chart_data}, selectedCategories);
				var filteredDataTable = google.visualization.arrayToDataTable(filteredData);
				ppm_by_device_chart.draw(filteredDataTable, ppm_by_device_options);
			}});

			// Create checkboxes for "Attack Volume by device trends"
			createCheckboxes('bpm_by_device_chart_div', {bw_by_device_trends_chart_data}, bpm_by_device_options, function(selectedCategories) {{
				var filteredData = filterDataByCategories({bw_by_device_trends_chart_data}, selectedCategories);
				var filteredDataTable = google.visualization.arrayToDataTable(filteredData);
				bpm_by_device_chart.draw(filteredDataTable, bpm_by_device_options);
			}});

			//////////////////////////////////////////////////////////////////////////////////////////////////////////

			// Create checkboxes for "Attack Events trends by source IP"
			createCheckboxes('sip_epm_chart_div', {sip_events_trends_chart}, sip_epm_options, function(selectedCategories) {{
				var filteredData = filterDataByCategories({sip_events_trends_chart}, selectedCategories);
				var filteredDataTable = google.visualization.arrayToDataTable(filteredData);
				sip_epm_chart.draw(filteredDataTable, sip_epm_options);
			}});

			// Create checkboxes for "Attack Packets trends by source IP"
			createCheckboxes('sip_ppm_chart_div', {sip_packets_trends_chart}, sip_ppm_options, function(selectedCategories) {{
				var filteredData = filterDataByCategories({sip_packets_trends_chart}, selectedCategories);
				var filteredDataTable = google.visualization.arrayToDataTable(filteredData);
				sip_ppm_chart.draw(filteredDataTable, sip_ppm_options);
			}});

			// Create checkboxes for "Attack Volume trends by source IP"
			createCheckboxes('sip_bpm_chart_div', {sip_bw_trends_chart}, sip_bpm_options, function(selectedCategories) {{
				var filteredData = filterDataByCategories({sip_bw_trends_chart}, selectedCategories);
				var filteredDataTable = google.visualization.arrayToDataTable(filteredData);
				sip_bpm_chart.draw(filteredDataTable, sip_bpm_options);
			}});

			//////////////////////////////////////////////////////////////////////////////////////////////////////////

			// Create checkboxes for "Attack Events trends by Policy"
			createCheckboxes('policy_epm_chart_div', {policy_events_trends_chart}, policy_epm_options, function(selectedCategories) {{
				var filteredData = filterDataByCategories({policy_events_trends_chart}, selectedCategories);
				var filteredDataTable = google.visualization.arrayToDataTable(filteredData);
				policy_epm_chart.draw(filteredDataTable, policy_epm_options);
			}});

			// Create checkboxes for "Attack Packets trends by Policy"
			createCheckboxes('policy_ppm_chart_div', {policy_packets_trends_chart}, policy_ppm_options, function(selectedCategories) {{
				var filteredData = filterDataByCategories({policy_packets_trends_chart}, selectedCategories);
				var filteredDataTable = google.visualization.arrayToDataTable(filteredData);
				policy_ppm_chart.draw(filteredDataTable, policy_ppm_options);
			}});

			// Create checkboxes for "Attack Volume trends by Policy"
			createCheckboxes('policy_bpm_chart_div', {policy_bw_trends_chart}, policy_bpm_options, function(selectedCategories) {{
				var filteredData = filterDataByCategories({policy_bw_trends_chart}, selectedCategories);
				var filteredDataTable = google.visualization.arrayToDataTable(filteredData);
				policy_bpm_chart.draw(filteredDataTable, policy_bpm_options);
			}});



			// Draw charts with consistent colors


			epm_total_chart.draw(epm_total_data, epm_total_options);
			ppm_total_chart.draw(ppm_total_data, ppm_total_options);
			bpm_total_chart.draw(bpm_total_data, bpm_total_options);

			epm_chart.draw(epm_data, epm_options);
			ppm_chart.draw(ppm_data, ppm_options);
			bpm_chart.draw(bpm_data, bpm_options);

			epm_chart_alltimehigh.draw(epm_data_alltimehigh, epm_options_alltimehigh);
			ppm_chart_alltimehigh.draw(ppm_data_alltimehigh, ppm_options_alltimehigh);
			bpm_chart_alltimehigh.draw(bpm_data_alltimehigh, bpm_options_alltimehigh);

			epm_by_device_chart.draw(epm_by_device_data, epm_by_device_options);
			ppm_by_device_chart.draw(ppm_by_device_data, ppm_by_device_options);
			bpm_by_device_chart.draw(bpm_by_device_data, bpm_by_device_options);

			device_epm_chart_this_month_chart.draw(device_epm_chart_this_month_data, device_epm_chart_this_month_options);
			device_ppm_chart_this_month_chart.draw(device_ppm_chart_this_month_data, device_ppm_chart_this_month_options);
			device_bpm_chart_this_month_chart.draw(device_bpm_chart_this_month_data, device_bpm_chart_this_month_options);

			sip_epm_chart.draw(sip_epm_data, sip_epm_options);
			sip_ppm_chart.draw(sip_ppm_data, sip_ppm_options);
			sip_bpm_chart.draw(sip_bpm_data, sip_bpm_options);

			policy_epm_chart.draw(policy_epm_data, policy_epm_options);
			policy_ppm_chart.draw(policy_ppm_data, policy_ppm_options);
			policy_bpm_chart.draw(policy_bpm_data, policy_bpm_options);

			total_attacks_days_chart.draw(total_attacks_days_data, total_attacks_days_options);

			

			// Add radio button toggles for stacked/non-stacked

			addStackedToggle('epm_chart_div', epm_chart, {events_trends}, epm_options);
			addStackedToggle('ppm_chart_div', ppm_chart, {packets_trends_chart}, ppm_options);
			addStackedToggle('bpm_chart_div', bpm_chart, {bw_trends}, bpm_options);

			addStackedToggle('epm_chart_div_alltimehigh', epm_chart_alltimehigh, {events_trends_alltimehigh}, epm_options_alltimehigh);
			addStackedToggle('ppm_chart_div_alltimehigh', ppm_chart_alltimehigh, {packets_trends_chart_alltimehigh}, ppm_options_alltimehigh);
			addStackedToggle('bpm_chart_div_alltimehigh', bpm_chart_alltimehigh, {bw_trends_alltimehigh}, bpm_options_alltimehigh);

			addStackedToggle('epm_by_device_chart_div', epm_by_device_chart, {events_by_device_trends_chart_data}, epm_by_device_options);
			addStackedToggle('ppm_by_device_chart_div', ppm_by_device_chart, {packets_by_device_trends_chart_data}, ppm_by_device_options);
			addStackedToggle('bpm_by_device_chart_div', bpm_by_device_chart, {bw_by_device_trends_chart_data}, bpm_by_device_options);

			addStackedToggle('sip_epm_chart_div', sip_epm_chart, {sip_events_trends_chart}, sip_epm_options);
			addStackedToggle('sip_ppm_chart_div', sip_ppm_chart, {sip_packets_trends_chart}, sip_ppm_options);
			addStackedToggle('sip_bpm_chart_div', sip_bpm_chart, {sip_bw_trends_chart}, sip_bpm_options);

			addStackedToggle('policy_epm_chart_div', policy_epm_chart, {policy_events_trends_chart}, policy_epm_options);
			addStackedToggle('policy_ppm_chart_div', policy_ppm_chart, {policy_packets_trends_chart}, policy_ppm_options);
			addStackedToggle('policy_bpm_chart_div', policy_bpm_chart, {policy_bw_trends_chart}, policy_bpm_options);

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

		// New function for merged row behavior
		function toggleTableMerged(tableId, button) {{
			const collapsibleRow = document.getElementById(tableId);

			if (collapsibleRow.style.display === 'none' || collapsibleRow.style.display === '') {{
				collapsibleRow.style.display = 'table-row'; // Ensure it's displayed as a full row
				button.textContent = 'Hide Details';
				button.classList.add('active');
			}} else {{
				collapsibleRow.style.display = 'none';
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

	  thead {{
        background-color: #1C5373;  /* Green background for the header */
        color: white;               /* White text */
        font-weight: bold;          /* Bold text for headers */
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
			width: 500px;
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
		border-top: 2px solid #ddd; /* Adds a separator */
		text-align: center;
	  }}


		/* Floating "Back to TOC" button */
	  .back-to-toc {{
		position: fixed;
		bottom: 20px;
		right: 20px;
		background: #1C5373;
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

	

	  #epm_total_chart_div {{
		height: 50vh;
	  }}

	  #ppm_total_chart_div {{
		height: 50vh;
	  }}

	  #bpm_total_chart_div {{
		height: 50vh;
	  }}

	  #epm_chart_div {{
		height: 50vh;
	  }}

	  #ppm_chart_div {{
		height: 50vh;
	  }}

	  #bpm_chart_div {{
		height: 50vh;
	  }}


	  #epm_chart_div_alltimehigh {{
		height: 50vh;
	  }}

	  #ppm_chart_div_alltimehigh {{
		height: 50vh;
	  }}

	  #bpm_chart_div_alltimehigh {{
		height: 50vh;
	  }}
	  

	  #epm_by_device_chart_div {{
		height: 50vh;
	  }}

	  #ppm_by_device_chart_div {{
		height: 50vh;
	  }}

	  #bpm_by_device_chart_div {{
		height: 50vh;
	  }}

	  #device_epm_chart_this_month_div {{
		height: 50vh;
	  }}

	  #device_ppm_chart_this_month_div {{
		height: 50vh;
	  }}

	  #device_bpm_chart_this_month_div {{
		height: 50vh;
	  }}
	  
	  #sip_epm_chart_div {{
		height: 50vh;
	  }}

	  #sip_ppm_chart_div {{
		height: 50vh;
	  }}

	  #sip_bpm_chart_div {{
		height: 50vh;
	  }}

	  #policy_epm_chart_div {{
		height: 50vh;
	  }}

	  #policy_ppm_chart_div {{
		height: 50vh;
	  }}

	  #policy_bpm_chart_div {{
		height: 50vh;
	  }}

	  #total_attacks_days_chart_div {{
	    width: 33vw;  /* 33% of the screen width */
        margin: 0 auto;  /* Centers the div horizontally */
        text-align: center;  /* Ensures content inside is centered */
		height: 50vh;
	  }}

        /* Center the toggle button */
        .button-container {{
            display: flex;
            justify-content: center;
			gap: 17%; /* Adds spacing between buttons */
            margin: 20px 0;
        }}



        /* Styling for the toggle button */
        .toggle-btn {{
            cursor: pointer;
            background-color: #1C5373; /* Dark blue Radware Banner color */
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

		table thead th {{
			color: black !important; /* Forces table headers to be black */
			// background-color: #f0f0f0; /* Optional: Change background for better contrast */
		}}

		thead.white-header th {{
			color: white !important;
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
	<title>Radware Monthly Reports</title>
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

<h1 class="headline">Radware Monthly trends report {month}, {year} - {cust_id}</h1>

<table class="toc-table">
	
		<thead>



            <td class="toc-cell">
				<!-- Table of Contents -->
				<div id="toc" class="toc-container">
					<ul class="toc-list">
						<li>
						<b><a href="#section1">Table of Contents</a></b>
						<ul class="sub-list">
							<li><a href="#section1">Monthly Attack Trends - Total</a></li>
							<li><a href="#section2">Monthly Attack Trends by Attack Vectors</a></li>
							<li><a href="#section3">Monthly Attack Trends by Distribution Across Devices</a></li>
							<li><a href="#section4">Attacks Distribution Across Devices - This Month</a></li>
							<li><a href="#section5">Monthly Attack Trends by distribution across policies</a></li>
							<li><a href="#section6">Monthly Attack Trends by Source IP</a></li>
							<li><a href="#section7">Monthly attack trends by total attack time</a></li>
						</ul>
						</li>
					</ul>
  				</div>
			</td>



		</tr>

		</thead>
</table>



<div class="sticky-header">
	<h2 id="section1">Monthly Attack Trends - Total</h2>
</div>

	  <table>
		<thead class="white-header">


		  <tr>
			<th>Month to month trends by Number of Attack Events</th>
			<th>Month to month trends by Attack Packets(cumulative)</th>
			<th>Month to month trends by Attack Volume(cumulative)</th>
		  </tr>
		</thead>

		<tbody>
		  <tr>
			<td style="vertical-align: top; text-align: left;">
				<div id="epm_total_chart_div"></div>
				<h4>Change in Attack events this month compared to the previous month</h4>
				<div style="text-align: left;"><ul>{events_total_bar_move_text}</ul></div>
			</td>


			<td style="vertical-align: top; text-align: left;">
				<div id="ppm_total_chart_div"></div>
				<h4>Change in Attack packets this month compared to the previous month</h4>
				<div style="text-align: left;"><ul>{pakets_total_bar_move}</ul></div>
			</td>
				


			<td style="vertical-align: top; text-align: left;">
				<div id="bpm_total_chart_div"></div>
				<h4>Change in Attack volume this month compared to the previous month</h4>
				<div style="text-align: left;"><ul>{bw_total_bar_move}</ul></div>
			</td>
			
		  </tr>
		</tbody>
	  </table>

<div class="sticky-header">
	<h2 id="section2">Monthly Attack Trends by Attack Vectors</h2>
	<h3>Top {top_n} Attacks - Ranked by Last Month's Data</h3>
</div>		

<table>
	<thead class="white-header">

		  <tr>
			<th>Month to month trends by Number of Attack Events</th>
			<th>Month to month trends by Attack Packets(cumulative)</th>
			<th>Month to month trends by Attack Volume(cumulative)</th>
		  </tr>
	</thead>
	<tbody>
		  <tr>
			<td style="vertical-align: top;border-bottom: 0;">
				
				<div id="epm_chart_div" style="height: 600px;"></div>
				<h4>Change in Attack vectors this month compared to the previous month</h4>
				<div style="text-align: left;"><ul>{events_trends_move}</ul></div>
			</td>
			<td style="vertical-align: top;border-bottom: 0;">
				<div id="ppm_chart_div" style="height: 600px;"></div>
				<h4>Change in Attack vectors this month compared to the previous month</h4>
				<div style="text-align: left;"><ul>{packets_trends_move_text}</ul></div>
			</td>
			<td style="vertical-align: top;border-bottom: 0;">
				<div id="bpm_chart_div" style="height: 600px;"></div>
				<h4>Change in Attack vectors this month compared to the previous month</h4>
				<div style="text-align: left;"><ul>{bw_trends_move}</ul></div>
			</td>
		  </tr>

		  
		  <tr >

		  <td style="vertical-align: top;border-top: 0;border-bottom: 0;">
			
				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Attack events distribution" onclick="toggleTable('LMeventsDistribution', this)">Attack events distribution</button>
				</div>
		  		<div id="LMeventsDistribution" class="collapsible-content" style="text-align: left;">
					{epm_html_final}
				</div>

		  </td>		  

		  <td style="vertical-align: top;border-top: 0;border-bottom: 0;">

				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Attack packets distribution" onclick="toggleTable('LMPacketsDistribution', this)">Attack packets distribution</button>
				</div>
		  		<div id="LMPacketsDistribution" class="collapsible-content" style="text-align: left;">
					{ppm_html_final}
				</div>


			</td>

			
		  <td style="vertical-align: top;border-top: 0;border-bottom: 0;">

				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Attack Volume Distribution" onclick="toggleTable('LMBWDistribution', this)">Attack Volume Distribution</button>
				</div>
		  		<div id="LMBWDistribution" class="collapsible-content" style="text-align: left;">
					{bpm_html_final}
				</div>


			</td>

		  </tr>			  


    <!-- Second Row with Monthly Buttons (Expands Across 3 Columns) -->
    <tr>
        <td style="text-align: center;border-top: 0">
            <button class="toggle-btn" data-original-text="Number of Attack Events per Month" onclick="toggleTableMerged('SecurityEventsPerMonth', this)">Number of Attack Events per Month</button>
        </td>
        <td style="text-align: center;border-top: 0">
            <button class="toggle-btn" data-original-text="Attack Packets per Month" onclick="toggleTableMerged('PacketsPerMonth', this)">Attack Packets per Month</button>
        </td>
        <td style="text-align: center;border-top: 0">
            <button class="toggle-btn" data-original-text="Attack Volume per Month" onclick="toggleTableMerged('BWPerMonth', this)">Attack Volume per Month</button>
        </td>
    </tr>

    <!-- Hidden expandable content for second row (Expands Across 3 Columns) -->
    <tr id="SecurityEventsPerMonth" class="collapsible-content" style="display: none;">
        <td colspan="3">
            <h4 align="center">Attack Events table</h4>
            {events_trends_table}
        </td>
    </tr>
    <tr id="PacketsPerMonth" class="collapsible-content" style="display: none;">
        <td colspan="3">
            <h4 align="center">Attack Packets table (units {pkt_units})</h4>
            {packets_table}
        </td>
    </tr>
    <tr id="BWPerMonth" class="collapsible-content" style="display: none;">
        <td colspan="3">
            <h4 align="center">Attack Volume table (units {bw_units})</h4>
            {bw_table}
        </td>
    </tr>




		  

	</tbody>
	  </table>


<div class="sticky-header">
	<h2 id="section2">Monthly Attack Trends by Attack Vectors</h2>
	<h3>Top {top_n} Attacks - Ranked by All Months Combined</h3>
</div>		


  
<table>
	<thead  class="white-header">
		   <tr>
			<th>Month to month trends by Number of Attack Events</th>
			<th>Month to month trends by Attack Packets(cumulative)</th>
			<th>Month to month trends by Attack Volume(cumulative)</th>
		  </tr>
	</thead>

		<tbody>
		  <tr>
			<td><div id="epm_chart_div_alltimehigh" style="height: 600px;"></td>
			<td><div id="ppm_chart_div_alltimehigh" style="height: 600px;"></td>
			<td><div id="bpm_chart_div_alltimehigh" style="height: 600px;"></td>
		  </tr>
		</tbody>
	
</table>

<div class="sticky-header">
	<h2 id="section3">Monthly Attack Trends by distribution across devices</h2>
	<h3>Top {top_n} Devices - Ranked by Last Month's data</h3>
</div>		

<table>
	<thead  class="white-header">
		   <tr>
			<th>Month to month trends by Number of Attack Events</th>
			<th>Month to month trends by Attack Packets(cumulative)</th>
			<th>Month to month trends by Attack Volume(cumulative)</th>
		  </tr>
	</thead>

	<tbody>
		  <tr>
			<td style="vertical-align: top;border-bottom: 0;"><div id="epm_by_device_chart_div" style="height: 600px;"></td>
			<td style="vertical-align: top;border-bottom: 0;"><div id="ppm_by_device_chart_div" style="height: 600px;"></td>
			<td style="vertical-align: top;border-bottom: 0;"><div id="bpm_by_device_chart_div" style="height: 600px;"></td>
		  </tr>


		  <tr >
		  <td style="vertical-align: top;border-top: 0;">
				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Attack Events change trends" onclick="toggleTable('eventsDeviceTrendText', this)">Attack Events change trends</button>
				</div>
		  		<div id="eventsDeviceTrendText" class="collapsible-content" style="text-align: left;">
					<h4>Change in Attack Events number by device this month compared to the previous month</h4>
					{events_by_device_trends_move_text}
				</div>


				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Attack Events distribution" onclick="toggleTable('LMeventsDeviceDistribution', this)">Attack Events distribution</button>
				</div>
		  		<div id="LMeventsDeviceDistribution" class="collapsible-content" style="text-align: center;">
					{device_epm_html_final}
				</div>

		  </td>		  

		  <td valign="top" style="border-top: 0;">
				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Attack Packets change trends" onclick="toggleTable('PacketsDeviceTrendText', this)">Attack Packets change trends</button>
				</div>
		  		<div id="PacketsDeviceTrendText" class="collapsible-content" style="text-align: left;">
					<h4>Change in Attack Packets number by device this month compared to the previous month</h4>
					{packets_by_device_trends_move_text}
				</div>

				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Attack packets distribution" onclick="toggleTable('LMPacketsDeviceDistribution', this)">Attack packets distribution</button>
				</div>
		  		<div id="LMPacketsDeviceDistribution" class="collapsible-content" style="text-align: center;">
					{device_ppm_html_final}
				</div>


			</td>

			
		  <td valign="top" style="border-top: 0;">
				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Attack Volume change trends" onclick="toggleTable('BWDeviceTrendText', this)">Attack Volume change trends</button>
				</div>
		  		<div id="BWDeviceTrendText" class="collapsible-content" style="text-align: left;">
					<h4>Change in Attack Traffic sum by device this month compared to the previous month</h4>
					{bw_by_device_trends_move_text}
				</div>

				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Attack Volume Distribution" onclick="toggleTable('LMBWDeviceDistribution', this)">Attack Volume Distribution</button>
				</div>
		  		<div id="LMBWDeviceDistribution" class="collapsible-content" style="text-align: center;">
					{device_bpm_html_final}
				</div>


			</td>

		  </tr>	


	</tbody>


</table>	  
<div class="sticky-header">
	<h2 id="section4">Attacks distribution across devices - this month</h2>
	<h3>Top {top_n} devices - this month</h3>
</div>	

<table>
	<thead class="white-header">
		  <tr>
			<th>Number of Attack Events - this month</th>
			<th>Attack Packets(cumulative) - this month</th>
			<th>Attack Volume(cumulative) - this month</th>
		  </tr>
	</thead>
	<tbody>
		  <tr>
			<td style="vertical-align: top;border-bottom: 0;"><div id="device_epm_chart_this_month_div" style="height: 600px;"></td>
			<td style="vertical-align: top;border-bottom: 0;"><div id="device_ppm_chart_this_month_div" style="height: 600px;"></td>
			<td style="vertical-align: top;border-bottom: 0;"><div id="device_bpm_chart_this_month_div" style="height: 600px;"></td>
		  </tr>	

		  <tr>
			<td colspan="3" style="border-top: 0;">
				<!-- Button container for centering -->
				<div class="button-container" align="center">
					<button class="toggle-btn" data-original-text="Number of Attack Events per Month" onclick="toggleTable('SecurityEventsDevicePerMonth', this)">Number of Attack Events per Month</button>
				

					<button align="center" class="toggle-btn" data-original-text="Attack Packets per Month" onclick="toggleTable('PacketsDevicePerMonth', this)">Attack Packets per Month</button>

					<button class="toggle-btn" data-original-text="Attack Volume per Month" onclick="toggleTable('BWDevicePerMonth', this)">Attack Volume per Month</button>
				</div>


		  		<div id="SecurityEventsDevicePerMonth" class="collapsible-content" style="text-align: left;">
				  <h4 align="center">Attack Events by device table</h4>
					{events_by_device_table}
				</div>

		  		<div id="PacketsDevicePerMonth" class="collapsible-content" style="text-align: left;">
				  <h4 align="center">Attack Packets by device table (units {pkt_units})</h4>
					{packets_by_device_table}
				</div>
				
		  		<div id="BWDevicePerMonth" class="collapsible-content" style="text-align: left;">
				  <h4 align="center">Malicious Bandwidth by device table (units {bw_units})</h4>
					{bw_by_device_table}
				</div>
			</td>
		  </tr>	  
	</tbody>
</table>

<div class="sticky-header">
	<h2 id="section5">Monthly Attack Trends by distribution across policies</h2>
	<h3>Top {top_n} Policies - Ranked by Last Month's data</h3>
</div>	


<table>
	<thead  class="white-header">
		  <tr>
			<th>Month to month trends by Number of Attack Events</th>
			<th>Month to month trends by Attack Packets(cumulative)</th>
			<th>Month to month trends by Attack Volume(cumulative)</th>
		  </tr>
	</thead>
	<tbody>
		  <tr>
			<td style="vertical-align: top;border-bottom: 0;">
				<div id="policy_epm_chart_div" style="height: 600px;">
			</td>
			<td style="vertical-align: top;border-bottom: 0;">
				<div id="policy_ppm_chart_div" style="height: 600px;">
			</td>
			<td style="vertical-align: top;border-bottom: 0;">
				<div id="policy_bpm_chart_div" style="height: 600px;">
			</td>
		  </tr>

		  

		  <tr >
		  <td style="vertical-align: top;border-bottom: 0;border-top: 0;">

				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Attack Events distribution" onclick="toggleTable('eventsPolicyDistribution', this)">Attack Events distribution</button>
				</div>
		  		<div id="eventsPolicyDistribution" class="collapsible-content" style="text-align: center;">
					{policy_epm_html_final}
				</div>

		  </td>		  

		  <td style="vertical-align: top;border-bottom: 0;border-top: 0;">

				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Attack packets distribution" onclick="toggleTable('PacketsPolicyDistribution', this)">Attack packets distribution</button>
				</div>
		  		<div id="PacketsPolicyDistribution" class="collapsible-content" style="text-align: center;">
					{policy_ppm_html_final}
				</div>


			</td>

			
		  <td style="vertical-align: top;border-bottom: 0;border-top: 0;">

				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Attack Volume Distribution" onclick="toggleTable('BWPolicyDistribution', this)">Attack Volume Distribution</button>
				</div>
		  		<div id="BWPolicyDistribution" class="collapsible-content" style="text-align: center;">
					{policy_bpm_html_final}
				</div>


			</td>

		  </tr>		

    <tr>
        <td style="text-align: center;border-top: 0">
            <button class="toggle-btn" data-original-text="Number of Attack Events per Month" onclick="toggleTableMerged('SecurityEventsPolicyPerMonth', this)">Number of Attack Events per Month</button>
        </td>
        <td style="text-align: center;border-top: 0">
            <button class="toggle-btn" data-original-text="Attack Packets per Month" onclick="toggleTableMerged('PacketsPolicyPerMonth', this)">Attack Packets per Month</button>
        </td>
        <td style="text-align: center;border-top: 0">
            <button class="toggle-btn" data-original-text="Attack Volume per Month" onclick="toggleTableMerged('BWPolicyPerMonth', this)">Attack Volume per Month</button>
        </td>
    </tr>

    <!-- Hidden expandable content for second row (Expands Across 3 Columns) -->
    <tr id="SecurityEventsPolicyPerMonth" class="collapsible-content" style="display: none;">
        <td colspan="3">
            <h4 align="center">Attack Events table</h4>
            {policy_events_trends_table}
        </td>
    </tr>
    <tr id="PacketsPolicyPerMonth" class="collapsible-content" style="display: none;">
        <td colspan="3">
            <h4 align="center">Attack Packets table (units {pkt_units})</h4>
            {policy_packets_table}
        </td>
    </tr>
    <tr id="BWPolicyPerMonth" class="collapsible-content" style="display: none;">
        <td colspan="3">
            <h4 align="center">Attack Volume table (units {bw_units})</h4>
            {policy_bw_table}
        </td>
    </tr>

	</tbody>
</table>


<div class="sticky-header">
	<h2 id="section6">Monthly Attack Trends by Source IP</h2>
	<h3>Top {top_n} Attacking Source IP - Ranked by Last Month's data</h3>
</div>	

<table>
	<thead  class="white-header">
		<tr>
			<th>Month to month trends by Number of Attack Events</th>
			<th>Month to month trends by Attack Packets(cumulative)</th>
			<th>Month to month trends by Attack Volume(cumulative)</th>
		  </tr>
	</thead>
	<tbody>
		  <tr>
			<td style="vertical-align: top;border-bottom: 0;">
				<div id="sip_epm_chart_div" style="height: 600px;">
			</td>
			<td style="vertical-align: top;border-bottom: 0;">
				<div id="sip_ppm_chart_div" style="height: 600px;">
			</td>
			<td style="vertical-align: top;border-bottom: 0;">
				<div id="sip_bpm_chart_div" style="height: 600px;">
			</td>
		  </tr>




		  <tr >
		  <td style="vertical-align: top;border-top: 0;border-bottom: 0;">

				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Attack Events distribution" onclick="toggleTable('eventsSIPDistribution', this)">Attack Events distribution</button>
				</div>
		  		<div id="eventsSIPDistribution" class="collapsible-content" style="text-align: center;">
					{sip_epm_html_final}
				</div>

		  </td>		  

		  <td style="vertical-align: top;border-top: 0;border-bottom: 0;">

				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Attack packets distribution" onclick="toggleTable('PacketsSIPDistribution', this)">Attack packets distribution</button>
				</div>
		  		<div id="PacketsSIPDistribution" class="collapsible-content" style="text-align: center;">
					{sip_ppm_html_final}
				</div>


			</td>

			
		  <td style="vertical-align: top;border-top: 0;border-bottom: 0;">

				<!-- Button container for centering -->
				<div class="button-container">
					<button class="toggle-btn" data-original-text="Attack Volume Distribution" onclick="toggleTable('BWSIPDistribution', this)">Attack Volume Distribution</button>
				</div>
		  		<div id="BWSIPDistribution" class="collapsible-content" style="text-align: center;">
					{sip_bpm_html_final}
				</div>


			</td>

		  </tr>		




    <tr>
        <td style="text-align: center;border-top: 0">
            <button class="toggle-btn" data-original-text="Number of Attack Events per Month" onclick="toggleTableMerged('SecurityEventsSIPPerMonth', this)">Number of Attack Events per Month</button>
        </td>
        <td style="text-align: center;border-top: 0">
            <button class="toggle-btn" data-original-text="Attack Packets per Month" onclick="toggleTableMerged('PacketsSIPPerMonth', this)">Attack Packets per Month</button>
        </td>
        <td style="text-align: center;border-top: 0">
            <button class="toggle-btn" data-original-text="Attack Volume per Month" onclick="toggleTableMerged('BWSIPPerMonth', this)">Attack Volume per Month</button>
        </td>
    </tr>

    <!-- Hidden expandable content for second row (Expands Across 3 Columns) -->
    <tr id="SecurityEventsSIPPerMonth" class="collapsible-content" style="display: none;">
        <td colspan="3">
            <h4 align="center">Attack Events table</h4>
            {sip_events_trends_table}
        </td>
    </tr>
    <tr id="PacketsSIPPerMonth" class="collapsible-content" style="display: none;">
        <td colspan="3">
            <h4 align="center">Attack Packets table (units {pkt_units})</h4>
            {sip_packets_table}
        </td>
    </tr>
    <tr id="BWSIPPerMonth" class="collapsible-content" style="display: none;">
        <td colspan="3">
            <h4 align="center">Attack Volume table (units {bw_units})</h4>
            {sip_bw_table}
        </td>
    </tr>

	</tbody>
</table>



<div class="sticky-header">
	<h2 id="section7">Monthly Attack Trends by Total Attack Time</h2>
	<h3>Duration of all attacks per month</h2>
</div>	


			<div id="total_attacks_days_chart_div"></div>

		

	  <!-- Floating "Back to TOC" Button -->
  <button id="backToToc" class="back-to-toc hidden" onclick="scrollToToc()">⬆ Back to TOP</button>

	</body>

	</html>
	"""

	# write html_page to file
	write_html(html_page,month,year)

# Path: trends_analyzer.py
