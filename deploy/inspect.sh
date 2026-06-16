#!/usr/bin/env bash

get_logs_by_version() {
    local SERVICE_NAME=$1
    
    # Get current version number
    CURRENT_VERSION=$(docker service inspect --format '{{.Version.Index}}' $SERVICE_NAME)
    
    # Get all tasks with this version
    TASK_IDS=$(docker service ps --filter "desired-state=running" \
        --format '{{.ID}}' $SERVICE_NAME)
    
    # Get logs from these specific tasks
    for TASK_ID in $TASK_IDS; do
        docker service logs --raw "$TASK_ID"
    done
}

echo ""
echo "================================="
echo "           CN1 "
echo "================================="

get_logs_by_version interfold_cn1


echo ""
echo "================================="
echo "           CN2 "
echo "================================="

get_logs_by_version interfold_cn2


echo ""
echo "================================="
echo "           CN3 "
echo "================================="

get_logs_by_version interfold_cn3


echo ""
echo "================================="
echo "           CN4 "
echo "================================="

get_logs_by_version interfold_cn4
