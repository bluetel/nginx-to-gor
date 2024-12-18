#!/bin/bash

# Usage: ./logs.sh <log_group_name> <since>
# Example: ./logs.sh /aws/lambda/my-lambda 3h

set -eo pipefail

if [ "$#" -ne 2 ]; then
  echo "Usage: ./logs.sh <log_group_name> <since>"
  exit 1
fi

if ! command -v awslogs &> /dev/null; then
  echo "awslogs is not installed. Run 'pip install awslogs' to install."
  exit 1
fi

# Validate since
if [[ ! $2 =~ ^[0-9]+[dsmh]$ ]]; then
  echo "Invalid since. Example: 3h, 30m, 10s"
  exit 1
fi


log_group_name=$1
since=$2
filename_timestamp=$(date '+%Y-%m-%d-%H-%M-%S')
sanitized_log_group_name=$(echo $log_group_name | sed 's/[^a-zA-Z0-9]/-/g')
log_file="logs/$filename_timestamp-$sanitized_log_group_name-$since.log"

mkdir -p logs || true
AWS_REGION=ap-northeast-1 awslogs get $log_group_name --start=$since > $log_file