#!/bin/bash
# RUN BLOCKERS
#
# Run all the blocker scripts
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

# ----------------------------------------------------------------------------
# Help
# ----------------------------------------------------------------------------

if [ $# -gt 0 ] ; then
   if [ "$1" = "-h" ] ; then
      echo "$SCRIPT: run all web blockers, restarting any daemons if necessary"
      exit 0
   fi
fi

# ----------------------------------------------------------------------------
# Blockers
# ----------------------------------------------------------------------------

# Start/Restart denial-of-service blocker daemon, if it's not already running
# Sleep 1's used to reduce likelihood of lock file causing a wait

TMP=`ps -ef | fgrep dos_blocker | fgrep -v fgrep`
if [ -z "$TMP" ] ; then
   echo `date`": ""$SCRIPT: Restarting dos_blocker.sh" >> "$LOG"
   sleep 1
   nohup /root/bin/dos_blocker.sh 0<&- &>/dev/null &
   sleep 1
fi

# Run SSH failed login blocker

if [ -n "$HAS_SSH" ] ; then
   /bin/bash sshd_blocker.sh
fi

# Run Mail Attack blocker

if [ -n "$HAS_MAIL" ] ; then
   /bin/bash mail_blocker.sh
fi

# Run Web Attack blocker

if [ -n "$HAS_WEB" ] ; then
   /bin/bash web_blocker.sh
fi


