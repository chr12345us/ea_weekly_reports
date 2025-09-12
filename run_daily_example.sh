#!/bin/bash

#-------------------------------------------
# PHP code by Marcelo Dantas
# Bash orchestration, dockerization, python - by Egor Egorov
#-------------------------------------------

current_date_time=$(date +"%Y-%m-%d %H:%M:%S")
echo "Current Date and Time: $current_date_time"

###################### Mandatory variables #########################################################
cust_list=(Customer-Name)	#space separated list of customer IDs, do not use underscore

####################################################################################################

##################### Report Range #################################################################

cur_day=$(date +'%d')
#cur_day=1

cur_month=$(date +'%m') # This sets the month to the current month by default, so the data will be collected and report will be generatd for the previous $report_range. If the data needs to be collected for the different month, set the numberic value. For example if set to 4 (April), the script will collect and generate report for March.
#cur_month=1

cur_year=$(date +%Y)
#cur_year=2024

prev_year=$(expr $cur_year - 1)

if [[ "$cur_month" != "01" ]] && [[ "$cur_month" != "1" ]]; then
    prev_month=$(($cur_month - 1))
else
    prev_month=12
fi

if (( "$cur_month" >= 1 && "$cur_month" <= 9 )); then
    # Add a leading zero if the number is between 1 and 9
    cur_month=$(printf "%02d" "$cur_month")
    #echo "Formatted current month: $cur_month"
fi

if (( "$prev_month" >= 1 && "$prev_month" <= 9 )); then
    # Add a leading zero if the number is between 1 and 9
    prev_month=$(printf "%02d" "$prev_month")
    #echo "Formatted prev month: $prev_month"
fi

abuseipdb=false
abuseipdb_key="xxx"
#This variable is needed to fetch the information about top 10 malicious IP addresses from abuseipdb.com.
#Register and obtain your API key from https://www.abuseipdb.com/account/api

delete_old_files_retention=6
#Number of months to keep the old files. For example if set to 6, the script will delete all files older than 6 months.

top_n=7
#Number of top N items to be displayed in the report. For example if set to 10, the script will display top 10 items in the report.



####################################################################################################

#######################Action variables switch on/off(optional)####################################################
collect_data=true
gen_python_csv_data=true  #generate csv data using python scripts
modify_csv=true
db_from_forensics=false
analyze_trends=true
email_send=true
####################################################################################################


####################### Email set up parameters for sending email with reports######################
smtp_auth=false
smtp_server="smtpserver.com" # SMTP server name
smtp_server_port=25 # SMTP server port
smtp_sender="radware@radware.com" # Email sender address setting
smtp_password="radware"  #Email password (optional)
smtp_list=(user@radware.com user2@radware.com)


####################################################################################################

### cd app

#######################Proxy variables##############################################################
is_http_proxy=false
is_https_proxy=false

is_proxy_for_email=false

http_proxy="proxyserver.com:3128"
https_proxy="proxyserver.com:3128"
####################################################################################################





#if directory source_files,database_files,report_files does not exist, create it
if [ ! -d "source_files" ]; then
  mkdir source_files
fi

if [ ! -d "database_files" ]; then
  mkdir database_files
fi

if [ ! -d "report_files" ]; then
  mkdir report_files
fi

cd app #change directory to app





################# Collect data from Vision ############################

for cust_id in "${cust_list[@]}"
do

	if [ $collect_data == "true" ]; then
		
		python3 script_files/collector.py $cust_id daily $cur_month $cur_day $cur_year
	fi
done

################# Set Proxy ##########################################################################

if [ $is_https_proxy == "true" ]; then
	echo "Setting HTTPS Proxy"	

	export https_proxy="$https_proxy"
fi

if [ $is_http_proxy == "true" ]; then
	echo "Setting HTTP Proxy"
	export http_proxy="$http_proxy"
fi	


###Loop through customer list, delete old files, generate appendixes ###################################
for cust_id in "${cust_list[@]}"
do

	####################### Delete old files #################################

	if [[ "$del_old_files" == "true" ]]; then
		echo "Deleting old files"
		python3 script_files/del_old_files.py $cust_id #Delete old files
	fi

	####################### Generate CSV Data #################################

	if [[ $gen_python_csv_data == "true" ]]; then
	
		if [[ "$cur_day" == 1 ]] || [ "$cur_day" == 01 ]; then
			if [[ "$cur_month" == 1 ]] || [ "$cur_month" == 01 ]; then # 1st of the month and January
				echo "Generating csv data for $prev_month $prev_year"
				python3 script_files/charts_and_tables_daily.py $cust_id $prev_month $prev_year #this will generate csv for the previouis month
			else
				# 1st of the month not January
				echo "Generating csv data for $prev_month $cur_year"
				python3 script_files/charts_and_tables_daily.py $cust_id $prev_month $cur_year #this will generate csv for the previouis month
			fi	
		else # if day is not 1
			echo "Generating csv data for $cur_month $cur_year"
			python3 script_files/charts_and_tables_daily.py $cust_id $cur_month $cur_year #this will generate csv for the previouis month
		fi

	fi
	
	####################### Modify CSV Data #################################
	

	if [ $modify_csv == "true" ]; then
		echo "Modifying csv data"
		python3 script_files/delete_column_csv.py $cust_id
		echo "csv data modified"
	fi

	



	######################### Analyze Trends ######################

	if [[ "$analyze_trends" == "true" ]]; then
	
		if [[ "$cur_day" == 1 ]] || [ "$cur_day" == 01 ]; then
			if [[ "$cur_month" == 1 ]] || [ "$cur_month" == 01 ]; then # 1st of the month and January
				echo "Analyzing daily trends for $prev_month $prev_year"
				python3 script_files/analyze_trends_daily.py $cust_id $prev_month $prev_year #this will generate appendix for the previouis month
			else
				# 1st of the month not January
				echo "Analyzing daily trends for $prev_month $cur_year"
				python3 script_files/analyze_trends_daily.py $cust_id $prev_month $cur_year #this will generate appendix for the previouis month
			fi	
		else # if day is not 1
			echo "Analyzing daily trends for $cur_month $cur_year"
			python3 script_files/analyze_trends_daily.py $cust_id $cur_month $cur_year #this will generate appendix for the previouis month
		fi

	fi

done


################# Send email ##########################################################################
if [ $email_send == "true" ]; then
	if [ $is_proxy_for_email == "false" ]; then
		echo "proxy email is false"
		unset https_proxy
		unset http_proxy
	fi

	for cust_id in "${cust_list[@]}"
		do
			smtp_subject_prefix="$cust_id" # Email Subject

			if [[ "$cur_day" != 1 ]] && [ "$cur_day" != 01 ]; then
				echo "Sending email - non 1st of the month case - all months"
				python3 script_files/email_send_daily.py $cust_id $cur_month $cur_year $smtp_auth $smtp_server $smtp_server_port $smtp_sender $smtp_password $smtp_subject_prefix ${smtp_list[@]}
		
			
			else # 1st of the month
			
				if [[ "$cur_month" != 01 ]] && [ "$cur_month" != 1 ]; then
					# Case for 1st of the month for all months except January
				
					echo "Sending email - 1st of the month non January case"


					python3 script_files/email_send_daily.py $cust_id $prev_month $cur_year $smtp_auth $smtp_server $smtp_server_port $smtp_sender $smtp_password $smtp_subject_prefix ${smtp_list[@]}


				else # 1st of the month, January
					echo "Sending email - 1st of the month January case"
					python3 script_files/email_send_daily.py $cust_id $prev_month $prev_year $smtp_auth $smtp_server $smtp_server_port $smtp_sender $smtp_password $smtp_subject_prefix ${smtp_list[@]}
				
				fi





			fi

		done
fi
#######################################################################################################
