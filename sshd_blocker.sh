#!/bin/bash
# SSH BLOCKER
#
# ----------------------------------------------------------------------------

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

declare OLD_PID
declare TMP
declare -i TIMEOUT
declare -r TMPFILE="/tmp/sshd_blocker.$$"

# ----------------------------------------------------------------------------
# Sanity tests
# ----------------------------------------------------------------------------

if [ "$LOGNAME" != "root" ] ; then
   echo "$SCRIPT: $LINENO: Must run script as root" >&2
   exit 192
fi
if [ ! -x "$IPTABLES_CMD" ] ; then
   echo "$SCRIPT: $LINENO: $IPTABLES_CMD command not found or is not executable" >&2
   exit 192
fi

# ----------------------------------------------------------------------------
# Help
# ----------------------------------------------------------------------------

if [ $# -gt 0 ] ; then
   if [ "$1" = "-h" ] ; then
      echo "$SCRIPT: sshd logs for attacker activity"
      exit 0
   fi
fi

# Spin lock.
# The runtime depends on the size of the logs.  Use a lock file to guarantee
# two copies won't run at the same time.  We reuse the mail log since it also
# changes ip tables.  Retry up to 5 times.

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
# Lock file? Wait
while [ -f "$LOCK_FILE" ] ; do
   sleep 5                                                      # wait 5 to 14 
   sleep `echo "$RANDOM" | cut -c1`                                  # seconds
   if [ "$TIMEOUT" -eq 5 ] ; then
      # Don't panic people...just sleep
      sleep 10
   elif [ "$TIMEOUT" -gt 0 ] ; then
      echo `date`": $SCRIPT: $LINENO: WARNING: '$LOCK_FILE' exists...still sleeping..." >> "$LOG"
      sleep 10
   else
      echo `date`": $SCRIPT: $LINENO: ERROR: '$LOCK_FILE' exists...aborting on timeout" >> "$LOG"
      exit 192
   fi
   let "TIMEOUT--"
done

# Delete lockfile if we are interrupted
trap "test -f $LOCK_FILE && rm $LOCK_FILE; test -f $TMPFILE && rm $TMPFILE" SIGINT SIGQUIT SIGTERM

# Write the PID of this script to the lockfile
echo "$$" > "$LOCK_FILE"


# Block
# ----------------------------------------------------------------------------
#
# Search the sshd log for offenders in the past hour and block any you find.
#
# For the purposes of SSHD blocking, treat every offender as blocked 5 times.
# (That is, weigh this offense heavy.)
#
# Red Hat 5 log format: Feb  9 07:10:55
#2014-01-19T09:15:12.593495-05:00 armitage sshd[11603]: input_userauth_request: invalid user sam [preauth]
#Feb 14 09:14:34 www sshd[10546]: Invalid user foobar from 10.20.3.11
# ----------------------------------------------------------------------------

if [ "$OS_NAME" = "red hat" ] ; then
   THIS_HOUR=`date '+%b %e %H'`
   fgrep "$THIS_HOUR" < "$SSHD_LOG_FILE" | fgrep "Invalid user" | fgrep sshd | cut -d\  -f10 | cut -d: -f 1 | sort | uniq -c | fgrep -v -f "$BLOCKED_ALREADY_LIST" > "$TMPFILE"
else
   THIS_HOUR=`date +%Y-%m-%dT%H`
   fgrep "$THIS_HOUR" < "$SSHD_LOG_FILE" | fgrep "Bye Bye" | fgrep sshd | cut -d\  -f7 | cut -d: -f 1 | sort | uniq -c | fgrep -v -f "$BLOCKED_ALREADY_LIST"  > "$TMPFILE"
fi

( while read CNT OFFENDER ; do # Red Hat
   if [ -n "$MONITOR_ONLY" ] ; then
      echo `date`": ""$SCRIPT"": would block ""$OFFENDER" >> "$LOG"
   elif ! valid_ip "$OFFENDER" ; then
      echo `date`": ""$SCRIPT"": cannot block ""$OFFENDER"" - not a valid ip number" >> "$LOG"
   elif [ "$CNT" -gt "$SSHD_LIMIT_PER_HOUR" ] ; then
      case "$IP_WHITELIST $IP_CUSTOMERS" in
        *"$OFFENDER "* )
          ;;
        *)
          echo `date`": ""$SCRIPT"": IP $OFFENDER blocked for $CNT sshd login attempts this hour" >> "$LOG"
          "$IPTABLES_CMD" -I "INPUT" 1 -s "$OFFENDER" -j "DROP" 2>> "$LOG"
          "$IPTABLES_CMD" -I OUTPUT 1 -d "$OFFENDER" -j REJECT 2>> "$LOG"
          # Treat ssh attackers as a frequent offender (long term ban)
          echo "$OFFENDER" >> "$BLOCKED_ALREADY_LIST"
          echo "$OFFENDER" >> "$BLOCKED_ALREADY_LIST"
          echo "$OFFENDER" >> "$BLOCKED_ALREADY_LIST"
          echo "$OFFENDER" >> "$BLOCKED_ALREADY_LIST"
          echo "$OFFENDER" >> "$BLOCKED_ALREADY_LIST"
          ;;
      esac
   fi
done ) < "$TMPFILE"
rm "$TMPFILE"

# Release the lock

rm "$LOCK_FILE" 2>> "$LOG"

