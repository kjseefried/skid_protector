#!/bin/bash
#
# Erase the list of weekly offenders.  This list contains one IP for
# every day of an offense.  IP's of 5 or more are auto-blocked when
# during the daily reset.  This resets the list.
#
# Ken O. Burtch
# November 12, 2013
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

declare -r NEW_WEEKLY_LIST="$PREFIX/data/new_weekly_list.txt"

# Sanity Tests

if [ "$LOGNAME" != "root" ] ; then
   echo "$SCRIPT: you must be logged in as root" >&2
   exit 192
fi
if [ -f "$BLOCKED_WEEKLY_LIST" ] ; then
   if [ ! -w "$BLOCKED_WEEKLY_LIST" ] ; then
      echo "$SCRIPT: cannot write to the blocked weekly list" >&2
      exit 192
   fi
fi

# ----------------------------------------------------------------------------
# Help
# ----------------------------------------------------------------------------

if [ $# -gt 0 ] ; then
   if [ "$1" = "-h" ] ; then
      echo "$SCRIPT: update the list of frequent offenders"
      exit 0
   fi
fi

# Lock
# ----------------------------------------------------------------------------

# Wait indefinitely until lock file is released.
# Stale lock files are removed by the blocking script.

while [ -f "$LOCK_FILE" ] ; do
      echo "$SCRIPT: $LINENO: Waiting on lock..." >> "$LOG"
      sleep 5                                                   # wait 5 to 14
      sleep `echo "$RANDOM" | cut -c1`                               # seconds
done

# Delete lockfile if we are interrupted
trap "test -f $LOCK_FILE && rm $LOCK_FILE" SIGINT SIGQUIT SIGTERM

echo "$$" > "$LOCK_FILE"

# Reset the offenders list.  Depending on the number of recent offences, keep
# a record of the IP number.  The number gradually is reduced over time.
#

touch "$NEW_WEEKLY_LIST"

sort "$BLOCKED_WEEKLY_LIST" | uniq -c | sort -nr | ( while read CNT OFFENDER ; do
   if [ $CNT = "" ] ; then
      echo `date`": $SCRIPT: Parse error" >> "$LOG"
      break
   elif [ $CNT -ge 5 ] ; then
      echo "$OFFENDER" >> "$NEW_WEEKLY_LIST"
      echo "$OFFENDER" >> "$NEW_WEEKLY_LIST"
      echo "$OFFENDER" >> "$NEW_WEEKLY_LIST"
      echo "$OFFENDER" >> "$NEW_WEEKLY_LIST"
   elif [ $CNT -ge 4 ] ; then
      echo "$OFFENDER" >> "$NEW_WEEKLY_LIST"
      echo "$OFFENDER" >> "$NEW_WEEKLY_LIST"
      echo "$OFFENDER" >> "$NEW_WEEKLY_LIST"
   elif [ $CNT -ge 3 ] ; then
      echo "$OFFENDER" >> "$NEW_WEEKLY_LIST"
      echo "$OFFENDER" >> "$NEW_WEEKLY_LIST"
   elif [ $CNT -ge 2 ] ; then
      echo "$OFFENDER" >> "$NEW_WEEKLY_LIST"
   else
      break
   fi
done )

# DEBUG
mv "$NEW_WEEKLY_LIST" "$BLOCKED_WEEKLY_LIST" >> "$LOG"
if [ $? -eq 0 ] ; then
   echo `date`": $SCRIPT: Weekly offenders list reset" >> "$LOG"
fi

rm "$LOCK_FILE"

