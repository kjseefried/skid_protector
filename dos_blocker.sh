#!/bin/bash
#
# Web Blocker (Denial of Service) Daemon
#
# This script performs only a check for a large number of TCP connections,
# indicating a brute force break-in attempt or a denial of service attack.
# Since this check is much faster than the website log scan, this can be run
# more often.
#
# To start this script as a background process use
#
# nohup ./wb_dos.sh 0<&- &>/dev/null &
#
# Ken O. Burtch
# March 25, 2013
#
# ----------------------------------------------------------------------------
shopt -s -o nounset

# Load Configuration

if [ ! -f /root/bin/wb_config.inc.sh ] ; then
   echo "wb_config.inc.sh cannot be found"
   exit 192
fi
if [ ! -r /root/bin/wb_config.inc.sh ] ; then
   echo "wb_config.inc.sh cannot be read"
   exit 192
fi
. /root/bin/wb_config.inc.sh

# Additional Script variables
# ----------------------------------------------------------------------------

declare -rx FILTER_TIME=`date '+%d/%b/%Y:%H'` # date/hour in the web log format
declare -rx FILTER_TIME_DAY=`date '+%d/%b/%Y'` # date in the web log format
declare     SEVERE_OVERLOAD=""

declare ADJUSTMENT
declare OLD_PID
declare TMP
declare -i TIMEOUT

# This is a kludge.  DOS blocker keeps running when other scripts
# are running despite the lock file.  Until I can track down the
# problem, use a different file for list of blocking IP's so the
# scripts don't overwrite each other's data.
# Could it be due to the minor race condition?

declare -rx DOS_BLOCK_LIST="$PREFIX/data/dos_block_list.txt"


#  SCAN TCP CONNECTIONS
#
# This blocks an IP with a large number of connections, no matter what
# network port.  It is intended to protect against a DoS attack.  Whitelisted
# IPs are ignored.  Presumably Bell has something like this in place already
# but this check is very quick.
#
# Since this could indicate a massive web site attack, we don't only want
# to block new traffic but we also want to block any pending requests
# being returned.  So we add the IP to iptable's output filter here.
#
# TODO: awk could switched to cut if we compressed spaces with sed
# TODO: doesn't do udp
# Based on http://deflate.medialayer.com/
# ----------------------------------------------------------------------------

function scan_tcp_connections {
  declare OFFENDER
  declare COUNT

  nice netstat -ntu | fgrep tcp | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | (while read COUNT OFFENDER ; do
    if [ -n "$OFFENDER" ] ; then  # one entry will be blank due to titles
       if [ "$COUNT" -gt "$TCP_LIMIT" ] ; then
          case "$IP_WHITELIST $IP_CUSTOMERS" in
          *"$OFFENDER "* )
             ;;
          *) NAME=`nslookup $OFFENDER | fgrep "name =" | head -1 | cut -d\   -f3`
             : ${NAME:=unknown}
             if [ "$NAME" = "unknown" ] ; then
                if asian_ip "$OFFENDER" ; then
                   NAME="unknown asian ip"
                elif russian_ip "$OFFENDER" ; then
                   NAME="unknown eastern europe ip"
                elif samerican_ip "$OFFENDER" ; then
                   NAME="unknown south armerican ip"
                fi
             fi
             echo `date`": ""$SCRIPT"": $OFFENDER ($NAME) has a large amount of TCP/IP connections ($COUNT vs limit of $TCP_LIMIT)" >> "$LOG"
             echo "$OFFENDER" >> "$DOS_BLOCK_LIST"
             ;;
          esac
       fi
    fi
done )
}
readonly -f scan_tcp_connections

#  CLEANUP
#
# Delete any temp files.  Don't delete the lock file because we can't be sure
# our program made it.
# ----------------------------------------------------------------------------

function cleanup {
  test -f "$DOS_BLOCK_LIST"       && rm "$DOS_BLOCK_LIST" 2>> "$LOG"
  test -f "$NEW_BLOCKED_LIST"     && rm "$NEW_BLOCKED_LIST" 2>> "$LOG"
}
readonly -f cleanup


# ----------------------------------------------------------------------------
#  Setup
# ----------------------------------------------------------------------------


# Sanity tests

if [ "$LOGNAME" != "root" ] ; then
   echo "$SCRIPT: $LINENO: Must run script as root" >&2
   exit 192
fi
if [ ! -x "$IPTABLES_CMD" ] ; then
   echo "$SCRIPT: $LINENO: $IPTABLES_CMD command not found or is not executable" >&2
   exit 192
fi

# ----------------------------------------------------------------------------
# Main Loop
# ----------------------------------------------------------------------------

while true ; do

# Spin lock.
# The runtime depends on the size of the logs.  Use a lock file to guarantee
# two copies won't run at the same time.  We reuse the mail log since it also
# changes ip tables  Retry up to 5 times.

TIMEOUT=5
# Stale lock file? Remove it.
OLD_PID=`cat "$LOCK_FILE" 2>> /dev/null`
if [ -n "$OLD_PID" ] ; then
   /bin/ps -p "$OLD_PID" > /dev/null 2>> "$LOG"
   if [ "$?" -ne 0 ] ; then
      # Still there?
      if [ -f "$LOCK_FILE" ] ; then
         echo `date`": $SCRIPT: $LINENO: removing stale lock file '$LOCK_FILE'" >> "$LOG"
         rm "$LOCK_FILE" 2>> "$LOG"
      fi
   fi
fi
# Lock file? Wait 2 seconds and try again
while [ -f "$LOCK_FILE" ] ; do
   sleep 2
   if [ "$TIMEOUT" -eq 5 ] ; then
      # Don't panic people...just sleep
      sleep 10
   elif [ "$TIMEOUT" -gt 0 ] ; then
      echo `date`": $SCRIPT: $LINENO: WARNING: '$LOCK_FILE' exists...still sleeping..." >> "$LOG"
      sleep 10
   else
      echo `date`": $SCRIPT: $LINENO: ERROR: '$LOCK_FILE' exists...aborting on timeout" >> "$LOG"
      cleanup
      exit 192
   fi
   let "TIMEOUT--"
done

# Cleanup and delete lockfile if we are interrupted
trap "cleanup; test -f $LOCK_FILE && rm $LOCK_FILE" SIGINT SIGQUIT SIGTERM

# Write the PID of this script to the lockfile
echo "$$" > "$LOCK_FILE"

# Firewall check
#
# This must occur after the spin lock because the lock may be in place while
# the firewall is being cleared/reset.

CNT=`"$IPTABLES_CMD" -L -n | fgrep DROP | wc -l`
if [ "$CNT" -lt 20 ] ; then
   echo `date`": $SCRIPT: $LINENO: Warning: firewall appears to have lost its settings...unexpectedly few DROP's" >> "$LOG"
   echo `date`": $SCRIPT: $LINENO: Warning: reloading firewall blocking rules" >> "$LOG"
   # SuSEfirewall: when the network interface is restarted, the firewall is restarted and all
   # settings are lost.  SuSEfirewall will load run an file with IP tables commands when it
   # restarts but we don't have that yet.  TODO: FW_CUSTOMRULES could be used to run this in a small
   # recovery script.
   if [ "$OS_NAME" = "suse" ] ; then
      if [ ! -r "/root/bin/suse_firewall_repair.sh" ] ; then
         echo `date`": $SCRIPT: $LINENO: suse_firewall_repair.sh not found nor is not readable" >> "$LOG"
      else
         /root/bin/suse_firewall_repair.sh -l
      fi
   fi
fi

# DEBUG

if [ -f "$LOCK_FILE" ] ; then
   echo `date`": $SCRIPT: $LINENO: Error: lock_file exists even though dos_blocker checked it" >> "$LOG"
fi

# ----------------------------------------------------------------------------
#  Run Checks
# ----------------------------------------------------------------------------


# These are the scans and the web logs that are checked.

scan_tcp_connections

# ----------------------------------------------------------------------------
# Apply blocking
# ----------------------------------------------------------------------------

if [ -f "$DOS_BLOCK_LIST" ] ; then

   # Take the list of IP numbers to block and remove any duplicates.

   nice sort -u -o "$DOS_BLOCK_LIST" < "$DOS_BLOCK_LIST" 2>> "$LOG"

   # Don't add IP's that are already blocked.  If the blocked list is missing
   # (i.e. a first run of this script), create an empty one.

   if [ ! -f "$BLOCKED_ALREADY_LIST" ] ; then
      touch "$BLOCKED_ALREADY_LIST"
      chmod 640 "$BLOCKED_ALREADY_LIST"
      touch "$NEW_BLOCKED_LIST"
      chmod 640 "$NEW_BLOCKED_LIST"
   else
     nice fgrep -v -f "$BLOCKED_ALREADY_LIST" < "$DOS_BLOCK_LIST" > "$NEW_BLOCKED_LIST" 2>> "$LOG"
   fi

   # Add rules to block the new offenders

   ( while read OFFENDER ; do
     # Append on the input chain the offender IP, asking that it be dropped.
     # This also assumes the default policy is to accept connections.
     if [ -n "$MONITOR_ONLY" ] ; then
        echo `date`": ""$SCRIPT"": would block ""$OFFENDER" >> "$LOG"
     elif ! valid_ip "$OFFENDER" ; then
        echo `date`": ""$SCRIPT"": cannot block ""$OFFENDER"" - not a valid ip number" >> "$LOG"
     else
        echo `date`": ""$SCRIPT"": blocked ""$OFFENDER" >> "$LOG"
        "$IPTABLES_CMD" -I INPUT 1 -s "$OFFENDER" -j DROP 2>> "$LOG"
        "$IPTABLES_CMD" -I OUTPUT 1 -d "$OFFENDER" -j REJECT 2>> "$LOG"
        echo "$OFFENDER" >> "$BLOCKED_ALREADY_LIST"
     fi
   done ) < "$NEW_BLOCKED_LIST"

fi

# ----------------------------------------------------------------------------
# Cleanup
# ----------------------------------------------------------------------------

cleanup

# Release the lock after cleanup as some files may be reused by other blockers

rm "$LOCK_FILE" 2>> "$LOG"

sleep 10

done # main loop

exit $?

