#!/bin/bash

#-------------------------------------------
# PHP code by Marcelo Dantas
# Bash orchestration, dockerization, python - by Egor Egorov
#-------------------------------------------
cd /app

current_date_time=$(date +"%Y-%m-%d %H:%M:%S")
echo "Current Date and Time: $current_date_time"

###################### Mandatory variables #########################################################
cust_list=(IBM IBM-dp01 IBM-dp02)	#space separated list of customer IDs

####################################################################################################

##################### Report Range #################################################################

cur_day=$(date +'%d')
#cur_day=5

cur_month=$(date +'%m') # This sets the month to the current month by default, so the data will be collected and report will be generatd for the previous $report_range. If the data needs to be collected for the different month, set the numberic value. For example if set to 4 (April), the script will collect and generate report for March.
#cur_month=8
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
######################################################################################################
exit 0
