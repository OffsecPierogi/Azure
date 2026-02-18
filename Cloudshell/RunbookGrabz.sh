#!/bin/bash

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="./automation_report_${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

MASTER_SUMMARY="$OUTPUT_DIR/00_master_summary.txt"

{
  echo ""
  echo "======================================"
  echo " Azure Automation Account Report"
  echo " Generated: $(date)"
  echo "======================================"
} | tee "$MASTER_SUMMARY"

SUBSCRIPTIONS=$(az account list --query "[].{id:id, name:name}" -o json)

echo "$SUBSCRIPTIONS" | jq -c '.[]' | while read SUB; do
  SUB_ID=$(echo $SUB | jq -r '.id')
  SUB_NAME=$(echo $SUB | jq -r '.name')

  SUB_DIR="$OUTPUT_DIR/$SUB_NAME"
  mkdir -p "$SUB_DIR"
  SUMMARY_FILE="$SUB_DIR/${SUB_NAME}_summary.txt"

  {
    echo ""
    echo "======================================"
    echo " Subscription: $SUB_NAME"
    echo " ID: $SUB_ID"
    echo "======================================"
  } | tee "$SUMMARY_FILE" | tee -a "$MASTER_SUMMARY"

  az account set --subscription $SUB_ID

  ACCOUNTS=$(az automation account list -o json 2>/dev/null)
  ACCOUNT_COUNT=$(echo $ACCOUNTS | jq length)

  if [ "$ACCOUNT_COUNT" -eq 0 ]; then
    echo "  No Automation Accounts found." | tee -a "$SUMMARY_FILE" | tee -a "$MASTER_SUMMARY"
    continue
  fi

  echo "$ACCOUNTS" | jq -c '.[]' | while read ACCOUNT; do
    ACCOUNT_NAME=$(echo $ACCOUNT | jq -r '.name')
    RG=$(echo $ACCOUNT | jq -r '.resourceGroup')
    CURRENT_FILE="$SUB_DIR/${ACCOUNT_NAME}.txt"
    RUNBOOK_DIR="$SUB_DIR/${ACCOUNT_NAME}_runbooks"
    mkdir -p "$RUNBOOK_DIR"

    {
      echo ""
      echo "============================================"
      echo " Subscription : $SUB_NAME"
      echo " Account      : $ACCOUNT_NAME"
      echo " Resource Group: $RG"
      echo " Generated    : $(date)"
      echo "============================================"

      # --- Runbooks ---
      echo ""
      echo "--- Runbooks ---"
      RUNBOOKS=$(az rest --method GET \
        --uri "https://management.azure.com/subscriptions/$SUB_ID/resourceGroups/$RG/providers/Microsoft.Automation/automationAccounts/$ACCOUNT_NAME/runbooks?api-version=2023-11-01")

      RB_COUNT=$(echo $RUNBOOKS | jq '.value | length')
      if [ "$RB_COUNT" -eq 0 ]; then
        echo "  No runbooks found."
      else
        echo "$RUNBOOKS" | jq -r '.value[] | "  Name: \(.name)  |  Type: \(.properties.runbookType)  |  State: \(.properties.state)  |  Last Modified: \(.properties.lastModifiedTime)"'

        echo "$RUNBOOKS" | jq -c '.value[]' | while read RB; do
          RB_NAME=$(echo $RB | jq -r '.name')
          RB_TYPE=$(echo $RB | jq -r '.properties.runbookType')

          case $RB_TYPE in
            PowerShell|PowerShell7|PowerShellWorkflow) EXT="ps1" ;;
            Python2|Python3)                           EXT="py"  ;;
            Graph|GraphPowerShell*)                    EXT="json";;
            *)                                         EXT="txt" ;;
          esac

          RB_FILE="$RUNBOOK_DIR/${RB_NAME}.${EXT}"
          CONTENT=$(az rest --method GET \
            --uri "https://management.azure.com/subscriptions/$SUB_ID/resourceGroups/$RG/providers/Microsoft.Automation/automationAccounts/$ACCOUNT_NAME/runbooks/$RB_NAME/content?api-version=2023-11-01" 2>/dev/null)

          if [ -n "$CONTENT" ] && [ "$CONTENT" != "null" ] && [ "$CONTENT" != '""' ]; then
            echo "$CONTENT" > "$RB_FILE"
            echo "  Runbook content saved: $RB_FILE"
          else
            echo "  Runbook content unavailable for: $RB_NAME (may not be published)"
          fi
        done
      fi

      # --- Webhooks ---
      echo ""
      echo "--- Webhooks ---"
      WEBHOOKS=$(az rest --method GET \
        --uri "https://management.azure.com/subscriptions/$SUB_ID/resourceGroups/$RG/providers/Microsoft.Automation/automationAccounts/$ACCOUNT_NAME/webhooks?api-version=2015-10-31")

      WEBHOOK_COUNT=$(echo $WEBHOOKS | jq '.value | length')
      if [ "$WEBHOOK_COUNT" -eq 0 ]; then
        echo "  No webhooks found."
      else
        echo "$WEBHOOKS" | jq -r '.value[] | "  Name: \(.name)  |  Enabled: \(.properties.isEnabled)  |  Expires: \(.properties.expiryTime)  |  Runbook: \(.properties.runbook.name)"'
      fi

      # --- Schedules ---
      echo ""
      echo "--- Schedules ---"
      SCHEDULES=$(az rest --method GET \
        --uri "https://management.azure.com/subscriptions/$SUB_ID/resourceGroups/$RG/providers/Microsoft.Automation/automationAccounts/$ACCOUNT_NAME/schedules?api-version=2023-11-01")

      SCHED_COUNT=$(echo $SCHEDULES | jq '.value | length')
      if [ "$SCHED_COUNT" -eq 0 ]; then
        echo "  No schedules found."
      else
        echo "$SCHEDULES" | jq -r '.value[] | "  Name: \(.name)  |  Enabled: \(.properties.isEnabled)  |  Frequency: \(.properties.frequency)  |  Interval: \(.properties.interval)  |  Next Run: \(.properties.nextRun)  |  Start: \(.properties.startTime)  |  Expiry: \(.properties.expiryTime)"'
      fi

      # --- Job Schedules (Runbook linkage + Parameters) ---
      echo ""
      echo "--- Job Schedules (Runbook Assignments & Parameters) ---"
      JOB_SCHEDULES=$(az rest --method GET \
        --uri "https://management.azure.com/subscriptions/$SUB_ID/resourceGroups/$RG/providers/Microsoft.Automation/automationAccounts/$ACCOUNT_NAME/jobSchedules?api-version=2023-11-01")

      JS_COUNT=$(echo $JOB_SCHEDULES | jq '.value | length')
      if [ "$JS_COUNT" -eq 0 ]; then
        echo "  No job schedules found."
      else
        echo "$JOB_SCHEDULES" | jq -c '.value[]' | while read JS; do
          JS_RUNBOOK=$(echo $JS | jq -r '.properties.runbook.name')
          JS_SCHEDULE=$(echo $JS | jq -r '.properties.schedule.name')
          JS_RUN_ON=$(echo $JS | jq -r '.properties.runOn // "Azure"')
          JS_PARAMS=$(echo $JS | jq -r '.properties.parameters')

          echo "  Runbook: $JS_RUNBOOK  |  Schedule: $JS_SCHEDULE  |  Run On: $JS_RUN_ON"

          if [ "$JS_PARAMS" != "null" ] && [ "$JS_PARAMS" != "{}" ]; then
            echo "  Parameters:"
            echo "$JS_PARAMS" | jq -r 'to_entries[] | "    \(.key) = \(.value)"'
          else
            echo "  Parameters: (none)"
          fi
          echo ""
        done
      fi

      # --- Hybrid Worker Groups ---
      echo ""
      echo "--- Hybrid Worker Groups ---"
      HYBRID_GROUPS=$(az rest --method GET \
        --uri "https://management.azure.com/subscriptions/$SUB_ID/resourceGroups/$RG/providers/Microsoft.Automation/automationAccounts/$ACCOUNT_NAME/hybridRunbookWorkerGroups?api-version=2022-08-08")

      HYBRID_COUNT=$(echo $HYBRID_GROUPS | jq '.value | length')
      if [ "$HYBRID_COUNT" -eq 0 ]; then
        echo "  No hybrid worker groups found."
      else
        echo "$HYBRID_GROUPS" | jq -c '.value[]' | while read GROUP; do
          GROUP_NAME=$(echo $GROUP | jq -r '.name')
          GROUP_TYPE=$(echo $GROUP | jq -r '.properties.groupType')
          echo "  Group: $GROUP_NAME  |  Type: $GROUP_TYPE"

          WORKERS=$(az rest --method GET \
            --uri "https://management.azure.com/subscriptions/$SUB_ID/resourceGroups/$RG/providers/Microsoft.Automation/automationAccounts/$ACCOUNT_NAME/hybridRunbookWorkerGroups/$GROUP_NAME/hybridRunbookWorkers?api-version=2022-08-08")

          echo "$WORKERS" | jq -r '.value[] | "    Worker: \(.name)  |  IP: \(.properties.ip)  |  Last Seen: \(.properties.lastSeenDateTime)"'
        done
      fi

      # --- Jobs (Last 30 Days) ---
      echo ""
      echo "--- Jobs (Last 30 Days) ---"
      THIRTY_DAYS_AGO=$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)

      JOBS=$(az rest --method GET \
        --uri "https://management.azure.com/subscriptions/$SUB_ID/resourceGroups/$RG/providers/Microsoft.Automation/automationAccounts/$ACCOUNT_NAME/jobs?api-version=2023-11-01&\$filter=properties/startTime ge $THIRTY_DAYS_AGO")

      JOB_COUNT=$(echo $JOBS | jq '.value | length')
      if [ "$JOB_COUNT" -eq 0 ]; then
        echo "  No jobs found in the last 30 days."
      else
        echo "$JOBS" | jq -c '.value[]' | while read JOB; do
          JOB_ID=$(echo $JOB | jq -r '.name')
          JOB_RUNBOOK=$(echo $JOB | jq -r '.properties.runbook.name')
          JOB_STATUS=$(echo $JOB | jq -r '.properties.status')
          JOB_START=$(echo $JOB | jq -r '.properties.startTime')
          JOB_END=$(echo $JOB | jq -r '.properties.endTime')

          echo "  Job: $JOB_ID  |  Runbook: $JOB_RUNBOOK  |  Status: $JOB_STATUS  |  Start: $JOB_START  |  End: $JOB_END"

          OUTPUT_RAW=$(az rest --method GET \
            --uri "https://management.azure.com/subscriptions/$SUB_ID/resourceGroups/$RG/providers/Microsoft.Automation/automationAccounts/$ACCOUNT_NAME/jobs/$JOB_ID/output?api-version=2023-11-01" 2>/dev/null)

          CLEAN_OUTPUT=$(echo "$OUTPUT_RAW" \
            | sed 's/^"//;s/"$//' \
            | sed 's/\\n/\n/g' \
            | sed 's/\\r//g' \
            | sed 's/\\t/\t/g')

          if [ -n "$CLEAN_OUTPUT" ] && \
             [ "$CLEAN_OUTPUT" != "null" ] && \
             [[ "$CLEAN_OUTPUT" != *"All job output will display"* ]]; then
            echo "    --- Output ---"
            echo "$CLEAN_OUTPUT" | sed 's/^/    /'
            echo "    --- End Output ---"
          else
            echo "    Output: (none or job still running)"
          fi
        done
      fi

    } | tee "$CURRENT_FILE"

    echo "  Written: $CURRENT_FILE" | tee -a "$SUMMARY_FILE" | tee -a "$MASTER_SUMMARY"

  done
done

{
  echo ""
  echo "======================================"
  echo " Report Complete"
  echo " Output Directory: $OUTPUT_DIR"
  echo "======================================"
} | tee -a "$MASTER_SUMMARY"
