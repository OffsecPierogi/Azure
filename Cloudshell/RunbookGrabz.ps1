$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputDir = "./automation_report_$timestamp"
New-Item -ItemType Directory -Path $outputDir | Out-Null

$masterSummary = "$outputDir\00_master_summary.txt"
$baseUri = "https://management.azure.com"
$apiBase = "api-version=2023-11-01"

function Write-Log {
  param($msg, $file, $color = "White")
  Write-Host $msg -ForegroundColor $color
  Add-Content -Path $file -Value $msg
}

@(
  "",
  "======================================",
  " Azure Automation Account Report",
  " Generated: $(Get-Date)",
  "======================================"
) | ForEach-Object { Write-Log $_ $masterSummary Cyan }

$subscriptions = Get-AzSubscription

foreach ($sub in $subscriptions) {
  Set-AzContext -SubscriptionId $sub.Id | Out-Null

  $subName = $sub.Name
  $subId   = $sub.Id
  $subDir  = "$outputDir\$subName"
  New-Item -ItemType Directory -Path $subDir -Force | Out-Null
  $summaryFile = "$subDir\${subName}_summary.txt"

  @(
    "",
    "======================================",
    " Subscription: $subName",
    " ID: $subId",
    "======================================"
  ) | ForEach-Object { Write-Log $_ $summaryFile Cyan; Add-Content -Path $masterSummary -Value $_ }

  $accountsResp = Invoke-AzRestMethod -Method GET `
    -Uri "$baseUri/subscriptions/$subId/providers/Microsoft.Automation/automationAccounts?$apiBase"
  $accounts = ($accountsResp.Content | ConvertFrom-Json).value

  if ($accounts.Count -eq 0) {
    Write-Log "  No Automation Accounts found." $summaryFile Yellow
    Add-Content -Path $masterSummary -Value "  No Automation Accounts found."
    continue
  }

  foreach ($account in $accounts) {
    $accountName = $account.name
    $rg = $account.id -split '/' | Select-Object -Index 4
    $accountFile = "$subDir\${accountName}.txt"
    $accountBase = "$baseUri/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.Automation/automationAccounts/$accountName"
    $runbookDir  = "$subDir\${accountName}_runbooks"
    New-Item -ItemType Directory -Path $runbookDir -Force | Out-Null

    Write-Log "" $accountFile
    Write-Log "============================================" $accountFile Magenta
    Write-Log " Subscription : $subName"                    $accountFile Magenta
    Write-Log " Account      : $accountName"                $accountFile Magenta
    Write-Log " Resource Group: $rg"                        $accountFile Magenta
    Write-Log " Generated    : $(Get-Date)"                 $accountFile Magenta
    Write-Log "============================================" $accountFile Magenta

    # --- Runbooks ---
    Write-Log ""                  $accountFile
    Write-Log "--- Runbooks ---"  $accountFile Yellow
    $runbooks = ((Invoke-AzRestMethod -Method GET -Uri "$accountBase/runbooks?$apiBase").Content | ConvertFrom-Json).value

    if ($runbooks.Count -eq 0) {
      Write-Log "  No runbooks found." $accountFile
    } else {
      foreach ($rb in $runbooks) {
        Write-Log "  Name: $($rb.name)  |  Type: $($rb.properties.runbookType)  |  State: $($rb.properties.state)  |  Last Modified: $($rb.properties.lastModifiedTime)" $accountFile

        $ext = switch -Wildcard ($rb.properties.runbookType) {
          "PowerShell*"  { "ps1"  }
          "Python*"      { "py"   }
          "Graph*"       { "json" }
          default        { "txt"  }
        }

        $rbFile = "$runbookDir\$($rb.name).$ext"
        $contentResp = Invoke-AzRestMethod -Method GET -Uri "$accountBase/runbooks/$($rb.name)/content?$apiBase"

        if ($contentResp.StatusCode -eq 200 -and $contentResp.Content -and $contentResp.Content.Length -gt 0) {
          Set-Content -Path $rbFile -Value $contentResp.Content -Encoding UTF8
          Write-Log "  Runbook content saved: $rbFile" $accountFile
        } else {
          Write-Log "  Runbook content unavailable for: $($rb.name) (may not be published)" $accountFile
        }
      }
    }

    # --- Webhooks ---
    Write-Log ""                  $accountFile
    Write-Log "--- Webhooks ---"  $accountFile Yellow
    $webhooks = ((Invoke-AzRestMethod -Method GET -Uri "$accountBase/webhooks?api-version=2015-10-31").Content | ConvertFrom-Json).value

    if ($webhooks.Count -eq 0) {
      Write-Log "  No webhooks found." $accountFile
    } else {
      foreach ($wh in $webhooks) {
        Write-Log "  Name: $($wh.name)  |  Enabled: $($wh.properties.isEnabled)  |  Expires: $($wh.properties.expiryTime)  |  Runbook: $($wh.properties.runbook.name)" $accountFile
      }
    }

    # --- Schedules ---
    Write-Log ""                   $accountFile
    Write-Log "--- Schedules ---"  $accountFile Yellow
    $schedules = ((Invoke-AzRestMethod -Method GET -Uri "$accountBase/schedules?$apiBase").Content | ConvertFrom-Json).value

    if ($schedules.Count -eq 0) {
      Write-Log "  No schedules found." $accountFile
    } else {
      foreach ($sched in $schedules) {
        Write-Log "  Name: $($sched.name)  |  Enabled: $($sched.properties.isEnabled)  |  Frequency: $($sched.properties.frequency)  |  Interval: $($sched.properties.interval)  |  Next Run: $($sched.properties.nextRun)  |  Start: $($sched.properties.startTime)  |  Expiry: $($sched.properties.expiryTime)" $accountFile
      }
    }

    # --- Job Schedules (Runbook Assignments & Parameters) ---
    Write-Log ""                                                      $accountFile
    Write-Log "--- Job Schedules (Runbook Assignments & Parameters) ---" $accountFile Yellow
    $jobSchedules = ((Invoke-AzRestMethod -Method GET -Uri "$accountBase/jobSchedules?$apiBase").Content | ConvertFrom-Json).value

    if ($jobSchedules.Count -eq 0) {
      Write-Log "  No job schedules found." $accountFile
    } else {
      foreach ($js in $jobSchedules) {
        $jsRunbook  = $js.properties.runbook.name
        $jsSchedule = $js.properties.schedule.name
        $jsRunOn    = if ($js.properties.runOn) { $js.properties.runOn } else { "Azure" }

        Write-Log "  Runbook: $jsRunbook  |  Schedule: $jsSchedule  |  Run On: $jsRunOn" $accountFile

        $jsParams = $js.properties.parameters
        if ($jsParams -and ($jsParams | Get-Member -MemberType NoteProperty).Count -gt 0) {
          Write-Log "  Parameters:" $accountFile
          foreach ($param in ($jsParams | Get-Member -MemberType NoteProperty).Name) {
            Write-Log "    $param = $($jsParams.$param)" $accountFile
          }
        } else {
          Write-Log "  Parameters: (none)" $accountFile
        }
        Write-Log "" $accountFile
      }
    }

    # --- Hybrid Worker Groups ---
    Write-Log ""                            $accountFile
    Write-Log "--- Hybrid Worker Groups ---" $accountFile Yellow
    $hybridGroups = ((Invoke-AzRestMethod -Method GET -Uri "$accountBase/hybridRunbookWorkerGroups?api-version=2022-08-08").Content | ConvertFrom-Json).value

    if ($hybridGroups.Count -eq 0) {
      Write-Log "  No hybrid worker groups found." $accountFile
    } else {
      foreach ($group in $hybridGroups) {
        Write-Log "  Group: $($group.name)  |  Type: $($group.properties.groupType)" $accountFile
        $workers = ((Invoke-AzRestMethod -Method GET `
          -Uri "$accountBase/hybridRunbookWorkerGroups/$($group.name)/hybridRunbookWorkers?api-version=2022-08-08").Content | ConvertFrom-Json).value

        foreach ($worker in $workers) {
          Write-Log "    Worker: $($worker.name)  |  IP: $($worker.properties.ip)  |  Last Seen: $($worker.properties.lastSeenDateTime)" $accountFile
        }
      }
    }

    # --- Jobs (Last 30 Days) ---
    Write-Log ""                             $accountFile
    Write-Log "--- Jobs (Last 30 Days) ---"  $accountFile Yellow
    $thirtyDaysAgo = (Get-Date).AddDays(-30).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    $jobsResp = Invoke-AzRestMethod -Method GET `
      -Uri "$accountBase/jobs?$apiBase&`$filter=properties/startTime ge $thirtyDaysAgo"
    $jobs = ($jobsResp.Content | ConvertFrom-Json).value

    if ($jobs.Count -eq 0) {
      Write-Log "  No jobs found in the last 30 days." $accountFile
    } else {
      foreach ($job in $jobs) {
        $jobId = $job.name
        Write-Log "  Job: $jobId  |  Runbook: $($job.properties.runbook.name)  |  Status: $($job.properties.status)  |  Start: $($job.properties.startTime)  |  End: $($job.properties.endTime)" $accountFile

        $outputResp = Invoke-AzRestMethod -Method GET -Uri "$accountBase/jobs/$jobId/output?$apiBase"
        $outputText = $outputResp.Content
        $outputText = $outputText.Trim('"')
        $outputText = [System.Text.RegularExpressions.Regex]::Unescape($outputText)
        $outputText = $outputText.Trim()

        if ($outputText -and
            $outputText -ne "null" -and
            $outputText -notmatch "All job output will display" -and
            $outputText.Length -gt 0) {
          Write-Log "    --- Output ---" $accountFile
          foreach ($line in $outputText -split "`n") {
            Write-Log "    $($line.TrimEnd())" $accountFile
          }
          Write-Log "    --- End Output ---" $accountFile
        } else {
          Write-Log "    Output: (none or job still running)" $accountFile
        }
      }
    }

    Write-Log "  Written: $accountFile" $summaryFile
    Add-Content -Path $masterSummary -Value "  Written: $accountFile"
  }
}

@(
  "",
  "======================================",
  " Report Complete",
  " Output Directory: $outputDir",
  "======================================"
) | ForEach-Object { Write-Log $_ $masterSummary Cyan }
