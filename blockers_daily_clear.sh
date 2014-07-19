#!/bin/bash
#
# Reset the iptables firewall to allow everything.
#
# The goal is not to block IP's indefinitely (our iptables list would get
# very long).  Instead, detect them quickly, block them to slow them down
# to make password cracking infeasiable.  Fail2ban blocks IP's for 10
# minutes.  I'm blocking them until this is run during the nightly cron
# tasks.  This should be more than enough to prevent the server from being
# compromised.
#
# Ken O. Burtch
# August 8, 2013
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

# Other variables

declare WAS_CLEARED
declare DOS_IP

#  BAN
#
# Ban a blacklisted IP
# ----------------------------------------------------------------------------

function ban {
   echo `date`": $SCRIPT: Banning blacklisted IP $1" >> "$LOG"
   "$IPTABLES_CMD" -I INPUT 1 -s "$1" -j DROP 2>> "$LOG"
}
readonly -f ban

# Sanity Tests

if [ "$LOGNAME" != "root" ] ; then
   echo "$SCRIPT: you must be logged in as root" >&2
   exit 192
fi
if [ -f "$BLOCKED_ALREADY_LIST" ] ; then
   if [ ! -w "$BLOCKED_ALREADY_LIST" ] ; then
      echo "$SCRIPT: cannot write to the blocked already list" >&2
      exit 192
   fi
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
      echo "$SCRIPT: reset the firewall, apply black list and frequent offenders"
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
# Write the PID of this script to the lockfile
echo "$$" > "$LOCK_FILE"


# Maintenance Tasks
# ----------------------------------------------------------------------------

# Update the blocked weekly list

if [ -f "$BLOCKED_ALREADY_LIST" ] ; then
   cat "$BLOCKED_ALREADY_LIST" >> "$BLOCKED_WEEKLY_LIST"
   sort -o "$BLOCKED_WEEKLY_LIST" < "$BLOCKED_WEEKLY_LIST"
fi

# Remove the blocked already list

if [ -f "$BLOCKED_ALREADY_LIST" ] ; then
   rm "$BLOCKED_ALREADY_LIST" 2>> "$LOG"
   touch "$BLOCKED_ALREADY_LIST" 2>> "$LOG"
   chmod 640 "$BLOCKED_ALREADY_LIST" 2>> "$LOG"
fi

# Restart the firewall, restoring default settings
# ----------------------------------------------------------------------------

WAS_CLEARED=1
if [ "$FIREWALL_TYPE" = "custom" ] ; then
   # There's no command to clear all rules.  You must destroy all existing rules
   # and reinitialize iptables to except everyting.  Use iptables -L to verify.
   # See http://www.cyberciti.biz/tips/linux-iptables-how-to-flush-all-rules.html
   /sbin/iptables -F 2>> "$LOG"
   /sbin/iptables -X 2>> "$LOG"
   /sbin/iptables -t nat -F 2>> "$LOG"
   /sbin/iptables -t nat -X 2>> "$LOG"
   /sbin/iptables -t mangle -F 2>> "$LOG"
   /sbin/iptables -t mangle -X 2>> "$LOG"
   /sbin/iptables -P INPUT ACCEPT 2>> "$LOG"
   /sbin/iptables -P FORWARD ACCEPT 2>> "$LOG"
   /sbin/iptables -P OUTPUT ACCEPT 2>> "$LOG"
elif [ "$FIREWALL_TYPE" = "suse" ] ; then
   /sbin/SuSEfirewall2 start >> "$LOG" 2>&1
elif [ "$FIREWALL_TYPE" = "initd_iptables" ] ; then
   /etc/init.d/iptables restart >> "$LOG" 2>&1
else
   WAS_CLEARED=
   echo `date`": $SCRIPT: firewall reset failed - unknown firewall type '$FIREWALL_TYPE'" >> "$LOG"
fi

# Report the firewall has been reset...but only if it has been reset.

if [ -n "$WAS_CLEARED" ] ; then
   echo `date`": $SCRIPT: Firewall reset - block ip list cleared" >> "$LOG"
fi

# Frequent offenders
#
# Most offenders aren't that frequent.  They visit every few days or weeks.
# Few (if any) reoccur daily.
# ----------------------------------------------------------------------------

sort "$BLOCKED_WEEKLY_LIST" | uniq -c | ( while read CNT OFFENDER ; do
   if [ $CNT -ge 2 ] ; then
      echo `date`": $SCRIPT: Auto-banning frequent offender $OFFENDER" >> "$LOG"
      "$IPTABLES_CMD" -I INPUT 1 -s "$OFFENDER" -j DROP 2>> "$LOG"
   fi
done )

# Blacklist
# ----------------------------------------------------------------------------
# Known spammers, attackers, spiders that we've seen, checked against
# https://www.projecthoneypot.org
#
# There are literally millions of attackers so we cannot permanently
# black list them all.
#
# Place the black list in the BLACK_LIST file
# ----------------------------------------------------------------------------

if [ -f "/root/bin/wb_blacklist.inc.sh" ] ; then
   . "/root/bin/wb_blacklist.inc.sh"
fi

# Custom Rules
# ----------------------------------------------------------------------------
# Add your own custom iptables rules in the CUSTOM_RULES file
# ----------------------------------------------------------------------------

if [ -f "/root/bin/custom_rules.sh" ] ; then
   echo `date`": $SCRIPT: Loading custom rules..." >> "$LOG"
   sh "/root/bin/custom_rules.sh"
fi

# Release the lock file prior to recycling the DOS daemon because the DOS
# daemon checks for it.

rm "$LOCK_FILE" 2>> "$LOG"

# Recycle the DOS Blocker Daemon
# ----------------------------------------------------------------------------
# Restart it to guard against memory leaks

DOS_IP=`ps -e | fgrep dos_blocker | fgrep -v fgrep | tr -s '\ ' | cut -d' ' -f 1`
if [ -n "$DOS_IP" ] ; then
   echo `date`": $SCRIPT: recycling dos_blocker daemon" >> "$LOG"
   kill "$DOS_IP" 2>> "$LOG"
fi

exit 0

