#!/bin/bash
#
# Block hostile IP's by checking mail logs
#
# Ken O. Burtch
# August 8, 2013
#
# Checks  IMAP or POP3.  Doesn't check SMTP yet.
# This assumes that the redirected traffic from Bell's firewall has the
# Source IP number intact.  This assumes dovecot auth_debug is on, that
# dovecot is logging unsuccessful login attempts.
# ----------------------------------------------------------------------------
shopt -s -o nounset

# Configuration

if [ ! -f /root/bin/wb_config.inc.sh ] ; then
   echo "wb_config.inc.sh cannot be found"
   exit 192
fi
if [ ! -r /root/bin/wb_config.inc.sh ] ; then
   echo "wb_config.inc.sh cannot be read"
   exit 192
fi
. /root/bin/wb_config.inc.sh

# Script variables

declare -r MAIL_LOG_DATE=`date '+%Y-%m-%d'T`    # date in SuSE mail log format
declare OLD_PID
declare -i TIMEOUT
declare TMP

# Sanity tests

if [ "$LOGNAME" != "root" ] ; then
   echo "$SCRIPT: $LINENO: Must run script as $LOGNAME" >&2
   exit 192
fi
if [ ! -x "$IPTABLES_CMD" ] ; then
   echo "$SCRIPT: $LINENO: iptables command not found or is not executable" >&2
   exit 192
fi

# This often starts the same time as the web blocker.  Wait a second.
sleep 5

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
      cleanup
      exit 192
   fi
   let "TIMEOUT--"
done

# Delete lockfile if we are interrupted
trap "test -f $LOCK_FILE && rm $LOCK_FILE" SIGINT SIGQUIT SIGTERM

# Write the PID of this script to the lockfile
echo "$$" > "$LOCK_FILE"


# Get the Dovecot pop3-login rejections, Look at today only, sort by the
# second, count the number per second, sort highest first.  Grab only first
# 100 results.  For IP's with greater than LIMIT_PER_SEC login requests per
# second, save the IP's to the block list.

TMP="/tmp/mail_blocker.$$"

if [ "$OS_NAME" = "red hat" ] ; then
   fgrep "pop3-login: Aborted" "$MAILLOG" | fgrep "$MAIL_LOG_DATE" | cut -d= -f2 | cut -d, -f1 | sort | uniq -c | sort -nr | head -n 100 > "$TMP"
else
   fgrep "pop3-login: Aborted" "$MAILLOG" | fgrep "$MAIL_LOG_DATE" | cut -d= -f3 | cut -d, -f1 | sort | uniq -c | sort -nr | head -n 100 > "$TMP"
fi
( while read COUNT_PER_SEC OFFENDER ; do
   if [ "$COUNT_PER_SEC" -gt "$MAIL_LIMIT_PER_MIN" ] ; then
      if [ -n "$OFFENDER" ] ; then # sanity check: no empty values
         echo "$OFFENDER" >> "$BLOCK_LIST"  2>> "$LOG"
      else
         echo `date`": $SCRIPT: $LINENO: Offending IP is unexpectedly empty" >> "$LOG"
      fi
   fi
done ) < "$TMP"

if [ "$OS_NAME" = "red hat" ] ; then
   fgrep "pop3-login: Login failed" "$MAILLOG" | fgrep "$MAIL_LOG_DATE" | cut -d= -f2 | cut -d, -f1 | sort | uniq -c | sort -nr | head -n 100 > "$TMP"
else
   fgrep "pop3-login: Login failed" "$MAILLOG" | fgrep "$MAIL_LOG_DATE" | cut -d= -f3 | cut -d, -f1 | sort | uniq -c | sort -nr | head -n 100 > "$TMP"
fi
( while read COUNT_PER_SEC OFFENDER ; do
   if [ "$COUNT_PER_SEC" -gt "$MAIL_LIMIT_PER_MIN" ] ; then
      if [ -n "$OFFENDER" ] ; then # sanity check: no empty values
         echo "$OFFENDER" >> "$BLOCK_LIST"  2>> "$LOG"
      else
         echo `date`": $SCRIPT: $LINENO: Offending IP is unexpectedly empty" >> "$LOG"
      fi
   fi
done ) < "$TMP"


# Get the Dovecot imap-login rejections, Look at today only, sort by the
# second, count the number per second, sort highest first.  Grab only first
# 100 results.  For IP's with greater than LIMIT_PER_SEC login requests per
# second, save the IP's to the block list.

if [ "$OS_NAME" = "red hat" ] ; then
   fgrep "imap-login: Aborted" "$MAILLOG" | fgrep "$MAIL_LOG_DATE" | cut -d= -f2 | cut -d, -f1 | sort | uniq -c | sort -nr | head -n 100 > "$TMP"
else
   fgrep "imap-login: Aborted" "$MAILLOG" | fgrep "$MAIL_LOG_DATE" | cut -d= -f3 | cut -d, -f1 | sort | uniq -c | sort -nr | head -n 100 > "$TMP"
fi
( while read COUNT_PER_SEC OFFENDER ; do
   if [ "$COUNT_PER_SEC" -gt "$MAIL_LIMIT_PER_MIN" ] ; then
      if [ -n "$OFFENDER" ] ; then # sanity check: no empty values
         echo "$OFFENDER" >> "$BLOCK_LIST"  2>> "$LOG"
      else
         echo `date`": $SCRIPT: $LINENO: Offending IP is unexpectedly empty" >> "$LOG"
      fi
   fi
done ) < "$TMP"


# Get the Postfix smptd login rejections, Look at today only, sort by the
# second, count the number per second, sort highest first.  Grab only first
# 100 results.  For IP's with greater than LIMIT_PER_SEC login requests per
# second, save the IP's to the block list.

if [ "$OS_NAME" = "red hat" ] ; then
   fgrep "lost connection after" "$MAILLOG" | fgrep "$MAIL_LOG_DATE" | cut -d[ -f3 | cut -d] -f1 | sort | uniq -c | sort -nr | head -n 100 > "$TMP"
else
   fgrep "lost connection after" "$MAILLOG" | fgrep "$MAIL_LOG_DATE" | cut -d[ -f3 | cut -d] -f1 | sort | uniq -c | sort -nr | head -n 100 > "$TMP"
fi
( while read COUNT_PER_SEC OFFENDER ; do
   if [ "$COUNT_PER_SEC" -gt "$MAIL_LIMIT_PER_MIN" ] ; then
      if [ -n "$OFFENDER" ] ; then # sanity check: no empty values
         echo "$OFFENDER" >> "$BLOCK_LIST"  2>> "$LOG"
      else
         echo `date`": $SCRIPT: $LINENO: Offending IP is unexpectedly empty" >> "$LOG"
      fi
   fi
done ) < "$TMP"

# Bad password checks "SASL PLAIN authentication failed"
# postfix/smtpd[32507]: warning: unknown[209.41.186.31]: SASL PLAIN authentication failed:

if [ "$OS_NAME" = "red hat" ] ; then
   fgrep "SASL PLAIN authentication failed" "$MAILLOG" | fgrep "$MAIL_LOG_DATE" | cut -d[ -f3 | cut -d] -f1 | sort | uniq -c | sort -nr | head -n 100 > "$TMP"
else
   fgrep "SASL PLAIN authentication failed" "$MAILLOG" | fgrep "$MAIL_LOG_DATE" | cut -d[ -f3 | cut -d] -f1 | sort | uniq -c | sort -nr | head -n 100 > "$TMP"
fi
( while read COUNT_PER_SEC OFFENDER ; do
   if [ "$COUNT_PER_SEC" -gt "$MAIL_LIMIT_PER_MIN" ] ; then
      if [ -n "$OFFENDER" ] ; then # sanity check: no empty values
         echo "$OFFENDER" >> "$BLOCK_LIST"  2>> "$LOG"
      else
         echo `date`": $SCRIPT: $LINENO: Offending IP is unexpectedly empty" >> "$LOG"
      fi
   fi
done ) < "$TMP"

if [ "$OS_NAME" = "red hat" ] ; then
   fgrep "SASL LOGIN authentication failed" "$MAILLOG" | fgrep "$MAIL_LOG_DATE" | cut -d[ -f3 | cut -d] -f1 | sort | uniq -c | sort -nr | head -n 100 > "$TMP"
else
   fgrep "SASL LOGIN authentication failed" "$MAILLOG" | fgrep "$MAIL_LOG_DATE" | cut -d[ -f3 | cut -d] -f1 | sort | uniq -c | sort -nr | head -n 100 > "$TMP"
fi
( while read COUNT_PER_SEC OFFENDER ; do
   if [ "$COUNT_PER_SEC" -gt "$MAIL_LIMIT_PER_MIN" ] ; then
      if [ -n "$OFFENDER" ] ; then # sanity check: no empty values
         echo "$OFFENDER" >> "$BLOCK_LIST"  2>> "$LOG"
      else
         echo `date`": $SCRIPT: $LINENO: Offending IP is unexpectedly empty" >> "$LOG"
      fi
   fi
done ) < "$TMP"

# No offending IP's found?  Finish with success.  Release the lock.

rm "$TMP"

if [ ! -f "$BLOCK_LIST" ] ; then
   rm "$LOCK_FILE" 2>> "$LOG"
   exit 0
fi


# Keep only unique IP's

sort -u -o "$BLOCK_LIST" < "$BLOCK_LIST" 2>> "$LOG"


# Don't add IP's that are already blocked

#/usr/sbin/iptables -L -n | grep "^DROP" | tr -s ' ' | cut -d\  -f4 > "$BLOCKED_ALREADY_LIST" 2>> "$LOG"
fgrep -v -f "$BLOCKED_ALREADY_LIST" < "$BLOCK_LIST" > "$NEW_BLOCKED_LIST" 2>> "$LOG"


# Add rules to block the new offenders

(while read OFFENDER ; do
  # Append on the input chain the offender IP, asking that it be dropped.
  # This also assumes the default policy is to accept connections.
   if [ -n "$MONITOR_ONLY" ] ; then
      echo `date`": ""$SCRIPT"": would block ""$OFFENDER" >> "$LOG"
   elif ! valid_ip "$OFFENDER" ; then
      echo `date`": ""$SCRIPT"": cannot block ""$OFFENDER"" - not a valid ip number" >> "$LOG"
   else
      echo `date`": $SCRIPT: blocked ""$OFFENDER" >> "$LOG"
      "$IPTABLES_CMD" -I INPUT 1 -s "$OFFENDER" -j DROP 2>> "$LOG"
      "$IPTABLES_CMD" -I OUTPUT 1 -d "$OFFENDER" -j REJECT 2>> "$LOG"
      echo "$OFFENDER" >> "$BLOCKED_ALREADY_LIST"
   fi
done ) < "$NEW_BLOCKED_LIST"


# Cleanup

rm "$BLOCK_LIST" 2>> "$LOG"
# rm "$BLOCKED_ALREADY_LIST" 2>> "$LOG"
rm "$NEW_BLOCKED_LIST" 2>> "$LOG"

# Release the lock

rm "$LOCK_FILE" 2>> "$LOG"

exit $?

