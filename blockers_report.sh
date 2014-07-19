#!/bin/bash
# BLOCKERS REPORT
#
# ----------------------------------------------------------------------------
shopt -s -o nounset

declare -r SUBJECT="Prod IP Blocking Report"
declare -r REPORT="/tmp/block_report.$$"
declare -r RECIPIENT="your_mail@your_mail_server.com"
# %e pads with space but there's no padding in date's default format.  fix
# with sed
declare -r LOG_FILTER=`date '+%a %b %e' | sed 's/\ \ /\ /g'`
declare -rx SCRIPT=${0##*/}

# ----------------------------------------------------------------------------
# Sanity Tests
# ----------------------------------------------------------------------------

if [ "$LOGNAME" != "root" ] ; then
   echo "$SCRIPT: $LINENO: Must run script as root" >&2
   exit 192
fi

# ----------------------------------------------------------------------------
# Help
# ----------------------------------------------------------------------------

if [ $# -gt 0 ] ; then
   if [ "$1" = "-h" ] ; then
      echo "$SCRIPT: email a summary of blocking activity"
      exit 0
   fi
fi

# ----------------------------------------------------------------------------
# Create the Report
# ----------------------------------------------------------------------------

echo >> "$REPORT"
echo "Prod IP Blocking Report" >> "$REPORT"
echo >> "$REPORT"
echo "Date: "`date` >> "$REPORT"
echo >> "$REPORT"

echo "Top 20 Reasons for Blocking" >> "$REPORT"
echo >> "$REPORT"
grep "$LOG_FILTER" /var/log/blocker.log | fgrep -v "blocked " | fgrep -v "attack vector:" | fgrep -v "blacklisted " | fgrep -v "sleeping" | fgrep -v "cleared" | fgrep -v "recycling dos_blocker" | fgrep -v "suspicious vector:" | cut -d: -f5- | sort | uniq | head -n 20 >> "$REPORT"

echo >> "$REPORT"
echo "Blocked IP's for Today" >> "$REPORT"
echo >> "$REPORT"
grep "$LOG_FILTER" /var/log/blocker.log | fgrep "blocked " | sed 's/blocked //g' | cut -d: -f5- | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n | uniq >> "$REPORT"

echo >> "$REPORT"
echo "See /var/log/blocker.log for more information" >> "$REPORT"
echo "To check an IP, https://www.projecthoneypot.org/search_ip.php" >> "$REPORT"

echo >> "$REPORT"
echo "End of Report" >> "$REPORT"

mail -s "$SUBJECT" "$RECIPIENT" < "$REPORT"

rm "$REPORT"

exit 0

