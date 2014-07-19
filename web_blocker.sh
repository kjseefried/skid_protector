#!/bin/bash
#
# Web Blocker
#
# This script searches for website activity during the current hour.
# If, at any time, the number of HTTP errors (4xx), HTTP successful
# hits (200) or HTTP successful hits bytes exceed given limits, the
# IP number is blocked.  The script should be run every 1 to 5 minutes.
#
# Attacker blocking is very complicated and mathematical.  This script
# is a "negative blocker": that is, it looks for prohibited
# activity, unlike a "positive blocker" that has a list of allowed
# activity.   It tries to identify aggressive and blatant attackers
# which threaten site performance, rather than more subtle attackers
# that try to obscure their efforts to breach security.  This script
# is not a replacement for secure programming or other security
# features.
#
# Since Apache allows you to customize your logs, this only works
# with the standard log file layout.  You'll have to change the way
# the log file fields are parsed if you change your log layout.
#
# Since this script only greps activity of the current the hour, it
# will ban borderline cases closer to the end of the hour, rather than
# the beginning.
#
# Ken O. Burtch
# September 26, 2013
#
# This script could be improved by computing a sliding window of time instead
# of grepping per hour.
#
# To delete a block: iptables -D INPUT line_no
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

# Load white list

if [ ! -f /root/bin/wb_whitelist.inc.sh ] ; then
   echo "wb_whitelist.inc.sh cannot be found"
   exit 192
fi
if [ ! -r /root/bin/wb_whitelist.inc.sh ] ; then
   echo "wb_whitelist.inc.sh cannot be read"
   exit 192
fi
. /root/bin/wb_whitelist.inc.sh

# Load attack pages and exceptions

if [ ! -f /root/bin/attack_vectors.inc.sh ] ; then
   echo "attack_vectors.inc.sh cannot be found"
   exit 192
fi
if [ ! -r /root/bin/attack_vectors.inc.sh ] ; then
   echo "attack_vectors.inc.sh cannot be read"
   exit 192
fi
. /root/bin/attack_vectors.inc.sh

# Additional Script variables
# ----------------------------------------------------------------------------

declare -rx FILTER_TIME=`date '+%d/%b/%Y:%H'` # date/hour in the web log format
declare -rx FILTER_TIME_DAY=`date '+%d/%b/%Y'` # date in the web log format
declare     SEVERE_OVERLOAD=""

declare ADJUSTMENT
declare OLD_PID
declare TMP
declare -i TIMEOUT


#  IS SEARCH ENGINE
#
# True if name seems to be a major search engine.  The name comes from
# nslookup and includes trailing period.  Returns 0 (OK) if a search engine
# or 1 if not.
# TODO: reverse DNS lookup
# ----------------------------------------------------------------------------

function is_search_engine {
  declare NAME="$1"
  declare -i FOUND=0

  # case is fast for pattern matching
  case "$NAME" in
  *".archive.org""." )    # Archive.org
  ;;
  *"crawl.baidu.com""." ) # China
  ;;
  *"exabot.com""." )      # France
  ;;
  *"googlebot.com""." )   # Google
  ;;
  *"naver.jp""." )        # Japan / Korea
  ;;
  *"search.msn.com""." )  # Microsoft
  ;;
  *".seznam.cz""." )      # Czek Republic search engine
  ;;
  *"softlayer.com""." )
  ;;
  *".yahoo.com""." )      # Slurp URL's hard to distinguish from basic yahoo.com
  ;;
  *".yahoo.net""." )      # Slurp URL's hard to distinguish from basic yahoo.com
  ;;
  *"yandex.com""." )      # Russia
  ;;
  *) FOUND=1
  esac

  return "$FOUND"
}
readonly -f is_search_engine


#  SCAN LOG FOR 400s
#
# Look up the top 10 produces of web errors in the access log, sorted
# For IP's with greater than ERROR_LIMIT_PER_HOUR errors per hour, save
# the IP to the the block list.
# ----------------------------------------------------------------------------

function scan_log_for_400s {
  declare -r ACCESS_LOG="$1"
  declare -r TMPFILE="/tmp/tmp.$$"
  declare -r TMPFILE2="/tmp/tmp2.$$"
  declare -r TMPFILE3="/tmp/tmp3.$$"
  declare BLOCK
  declare COUNT
  declare OFFENDER
  declare ATTACK_COUNT

  if [ ! -r "$ACCESS_LOG" ] ; then
     echo "$SCRIPT: $LINENO: web log '$ACCESS_LOG' does not exist or cannot be read" >&2
  else
     # Write the log entries for this hour to a temp file
     # How much to weight the suspicious pages?  For now, they count as two hits.
     # TODO: this is messy.  Is there a better way?

     nice grep "\"\ 400\ \|\"\ 401\ \|\"\ 403\ \|\"\ 404\ \|\"\ 405\ \|\"\ 413\ \|\"\ 414\ \|\"\ 500\ " "$ACCESS_LOG" | fgrep "$FILTER_TIME" > "$TMPFILE" 2>> "$LOG"
     nice fgrep -f "$SUSP_PAGES" < "$TMPFILE" | fgrep -v -f "$ATTACK_PAGE_EXCEPTIONS" | fgrep -v -f "$BLOCKED_ALREADY_LIST" >> "$TMPFILE2" 2>> "$LOG"
     nice fgrep -f "$ATTACK_PAGES" < "$TMPFILE" | fgrep -v -f "$ATTACK_PAGE_EXCEPTIONS" | fgrep -v -f "$BLOCKED_ALREADY_LIST" > "$TMPFILE3" 2>> "$LOG"
     # Anything with a backslash is also an attack vector.
     nice fgrep '\x' < "$TMPFILE" | fgrep -v -f "$BLOCKED_ALREADY_LIST" >> "$TMPFILE3" 2>> "$LOG"
     nice cat "$TMPFILE2" "$TMPFILE3" > "$TMPFILE"  2>> "$LOG"
     rm "$TMPFILE2" 2>> "$LOG"

     nice cut -d\  -f1 < "$TMPFILE" | sort | uniq -c | sort -nr | head -n $TOP_LIMIT | (while read COUNT OFFENDER ; do
        #echo  "$COUNT - $OFFENDER"

        # If the IP is a known bad IP in top results, do an automatic block
        # If the IP is using a known attack vector, do an automatic block.
        # Otherwise, if it's greater that the limit, check to see if it is
        # whitelisted.  If it's not, check to see if it's a known search
        # engine crawler.  If it's not, mark it for blocking.

        BLOCK=
        # Asian IP's are weighted double
        ATTACK_COUNT=`fgrep "$OFFENDER" "$TMPFILE3" | wc -l`
        if [ "$ATTACK_COUNT" -gt 0 ] ; then
           if valid_ip "$OFFENDER" ; then
              # for attackers, we still apply the whitelist.  Someone could have an old link
              # on their page that's in our attack list and google could come looking...we
              # don't want to risk blocking Google.
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
                 if ! is_search_engine "$NAME" ; then
                    echo `date`": ""$SCRIPT"": $ACCESS_LOG: $OFFENDER ($NAME) is using known attack vectors ($ATTACK_COUNT times)" >> "$LOG"
                    # for debugging, list the attack vector urls
                    fgrep "$OFFENDER" < "$TMPFILE3" | ( while read HIT ; do
                       echo `date`": ""$SCRIPT"": attack vector: $HIT" >> "$LOG"
                    done )
                    BLOCK=1
                 fi
                 ;;
              esac
           fi
        elif [ $COUNT -gt $ERROR_LIMIT_PER_HOUR ] ; then
           if valid_ip "$OFFENDER" ; then
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
                 if ! is_search_engine "$NAME" ; then
                    echo `date`": ""$SCRIPT"": $ACCESS_LOG: $OFFENDER ($NAME) has high HTTP error count ($COUNT weighted vs limit of $ERROR_LIMIT_PER_HOUR""/hour)" >> "$LOG"
                    BLOCK=1
                 fi
                 ;;
              esac
           fi
        fi

        if [ -n "$BLOCK" ] ; then
           echo "$OFFENDER" >> "$BLOCK_LIST"
        fi
     done )
     rm "$TMPFILE"  2>> "$LOG"
     rm "$TMPFILE3" 2>> "$LOG"
  fi
}
readonly -f scan_log_for_400s


#  SCAN LOG FOR SUSPICIOUS 200s
#
# The difficulty in working with 200s is that it is difficult to tell the
# difference between an aggressive crawler and several users behind a NAT
# IP checking the website at the same time.  We don't want to block legitimate
# users.
#
# For this reason, we'll only focus on files in our suspicious file list
# (common attack vectors).  Anyone hitting a large amount of the common
# attack vectors will be blocked.
#
# Look up the top 10 produces of large hits in the access log, sorted
# For IP's with greater than LIMIT_PER_HOUR errors per hour, save
# the IP to the the block list.
# ----------------------------------------------------------------------------

function scan_log_for_suspicious_200s {
  declare -r ACCESS_LOG="$1"
  declare -r TMPFILE="/tmp/tmp.$$"
  declare -r TMPFILE2="/tmp/tmp2.$$"
  declare BLOCK
  declare COUNT
  declare OFFENDER

  if [ ! -r "$ACCESS_LOG" ] ; then
     echo "$SCRIPT: $LINENO: web log '$ACCESS_LOG' does not exist or cannot be read" >&2
  else
     # Write the log entries for this hour to a temp file
     # How much to weight the suspicious pages?  For now, they count as two hits.
     # TODO: this is messy.  Is there a better way?
     nice grep "\"\ 200\ " "$ACCESS_LOG" | fgrep "$FILTER_TIME" > "$TMPFILE" 2>> "$LOG"
     nice fgrep -f "$SUSP_PAGES" < "$TMPFILE" >> "$TMPFILE2" 2>> "$LOG"
     nice cat < "$TMPFILE" >> "$TMPFILE2" 2>> "$LOG"
     rm "$TMPFILE2" 2>> "$LOG"

     # Write the log entries for this hour to a temp file.  Only count suspecious
     # pages.
     nice grep "\"\ 200\ " "$ACCESS_LOG" | fgrep "$FILTER_TIME" | fgrep -f "$SUSP_PAGES" | fgrep -v -f "$BLOCKED_ALREADY_LIST" > "$TMPFILE" 2>> "$LOG"

     nice cut -d\  -f1 < "$TMPFILE" | sort | uniq -c | sort -nr | head -n $TOP_LIMIT | (while read COUNT OFFENDER ; do
        #echo  "$COUNT - $OFFENDER"

        # If the IP is a known bad IP in top results, do an automatic block
        # Otherwise, if it's greater that the limit, check to see if it is
        # whitelisted.  If it's not, check to see if it's google.  If it's
        # not, mark it for blocking.
        #
        # If username is empty, it's a double quote...convert it to a dash so cut isn't confused

        BLOCK=
        # asian ip's weighted double
        if asian_ip "$OFFENDER" ; then
           if [ -n "$GEO_IP" ] ; then
              let "COUNT=COUNT*2"
           fi
        elif russian_ip "$OFFENDER" ; then
           if [ -n "$GEO_IP" ] ; then
              let "COUNT=COUNT*2"
           fi
        fi
        if [ $COUNT -gt $SUSP_LIMIT_PER_HOUR ] ; then
           if valid_ip "$OFFENDER" ; then
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
                 if ! is_search_engine "$NAME" ; then
                    echo `date`": ""$SCRIPT"": $ACCESS_LOG: $OFFENDER ($NAME) accessed many suspicious requests this hour ($COUNT weighted vs limit of $SUSP_LIMIT_PER_HOUR""/hour)" >> "$LOG"
                    # for debugging, list the attack vector urls - testing, does it work?
                    fgrep "$OFFENDER" < "$TMPFILE" | ( while read HIT ; do
                       echo `date`": ""$SCRIPT"": suspicious vector: $HIT" >> "$LOG"
                    done )
                    BLOCK=1
                 fi
                 ;;
              esac
           fi
        fi

        if [ -n "$BLOCK" ] ; then
           echo "$OFFENDER" >> "$BLOCK_LIST"
        fi
     done )
     rm "$TMPFILE"
  fi
}
readonly -f scan_log_for_suspicious_200s

function scan_log_for_200s_bytes {
  declare -r ACCESS_LOG="$1"
  declare -r TMPFILE="/tmp/tmp.$$"
  declare -r TMPFILE2="/tmp/tmp2.$$"
  declare BLOCK
  declare COUNT
  declare OFFENDER

  if [ ! -r "$ACCESS_LOG" ] ; then
     echo "$SCRIPT: $LINENO: web log '$ACCESS_LOG' does not exist or cannot be read" >&2
  else
     # Write the log entries for this hour to a temp file
     # How much to weight the suspicious pages?  For now, they count as two hits.
     # TODO: this is messy.  Is there a better way?
     nice grep "\"\ 200\ " "$ACCESS_LOG" | fgrep "$FILTER_TIME" > "$TMPFILE" 2>> "$LOG"
     nice fgrep -f "$SUSP_PAGES" < "$TMPFILE" >> "$TMPFILE2" 2>> "$LOG"
     nice cat < "$TMPFILE" >> "$TMPFILE2" 2>> "$LOG"
     rm "$TMPFILE2" 2>> "$LOG"

     # Write the log entries for this hour to a temp file.  Only count suspecious
     # pages.
     nice grep "\"\ 200\ " "$ACCESS_LOG" | fgrep "$FILTER_TIME" | fgrep -f "$SUSP_PAGES" | fgrep -v -f "$BLOCKED_ALREADY_LIST" > "$TMPFILE" 2>> "$LOG"

     nice cut -d\  -f1 < "$TMPFILE" | sort | uniq -c | sort -nr | head -n $TOP_LIMIT | (while read COUNT OFFENDER ; do
        #echo  "$COUNT - $OFFENDER"

        # If the IP is a known bad IP in top results, do an automatic block
        # Otherwise, if it's greater that the limit, check to see if it is
        # whitelisted.  If it's not, check to see if it's google.  If it's
        # not, mark it for blocking.
        #
        # If username is empty, it's a double quote...convert it to a dash so cut isn't confused

        BLOCK=
        BYTES=`fgrep "$OFFENDER" "$ACCESS_LOG" | fgrep "$FILTER_TIME" | sed 's/\"\"/-/g' | cut -d\" -f3- | cut -d\  -f3 | sed 's/-/0/g' | fgrep -v 'gaJsHost' | paste -sd+ | bc` 2>> "$LOG"
        if [ -z "$BYTES" ] ; then
           echo `date`": ""$SCRIPT"": download byte count unexpectedly empty for $OFFENDER" >> "$LOG"
           BYTES=0
        elif [ $BYTES -eq 0 ] ; then
           echo `date`": ""$SCRIPT"": download byte count unexpectedly zero for $OFFENDER" >> "$LOG"
        elif asian_ip "$OFFENDER" ; then
           if [ -n "$GEO_IP" ] ; then
              let "BYTES=BYTES*2"
           fi
        elif russian_ip "$OFFENDER" ; then
           if [ -n "$GEO_IP" ] ; then
              let "COUNT=COUNT*2"
           fi
        fi
        if [ $BYTES -gt $BYTE_LIMIT_PER_HOUR ] ; then
           if valid_ip "$OFFENDER" ; then
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
                 if ! is_search_engine "$NAME" ; then
                    echo `date`": ""$SCRIPT"": $ACCESS_LOG: $OFFENDER ($NAME) accessed large amount of bytes this hour ($BYTES weighted vs limit of $BYTE_LIMIT_PER_HOUR""/hour)" >> "$LOG"
                    BLOCK=1
                 fi
                 ;;
              esac
           fi
        fi

        if [ -n "$BLOCK" ] ; then
           echo "$OFFENDER" >> "$BLOCK_LIST"
        fi
     done )
     rm "$TMPFILE"
  fi
}
readonly -f scan_log_for_200s_bytes


#  SCAN LOG FOR 200s
#
# Check the highest successful pages hits and print notices for users higher
# than a certain threshold.  Don't block anyone unless on the blacklist or
# the system is dangerously overloaded.
# ----------------------------------------------------------------------------

function scan_log_for_200s {
  declare -r ACCESS_LOG="$1"
  declare -r TMPFILE="/tmp/tmp.$$"
  declare -r TMPFILE2="/tmp/tmp2.$$"
  declare BLOCK
  declare COUNT
  declare OFFENDER

  if [ ! -r "$ACCESS_LOG" ] ; then
     echo "$SCRIPT: $LINENO: web log '$ACCESS_LOG' does not exist or cannot be read" >&2
  else
     # Write the log entries for this hour to a temp file
     # How much to weight the suspicious pages?  For now, they count as two hits.
     # TODO: this is messy.  Is there a better way?
     nice grep "\"\ 200\ " "$ACCESS_LOG" | fgrep "$FILTER_TIME" > "$TMPFILE" 2>> "$LOG"

     # Write the log entries for this hour to a temp file.  Only count suspecious
     # pages.
     nice grep "\"\ 200\ " "$ACCESS_LOG" | fgrep "$FILTER_TIME" | fgrep -f "$SUSP_PAGES" | fgrep -v -f "$BLOCKED_ALREADY_LIST" > "$TMPFILE" 2>> "$LOG"

     nice cut -d\  -f1 < "$TMPFILE" | sort | uniq -c | sort -nr | head -n $TOP_LIMIT | (while read COUNT OFFENDER ; do
        #echo  "$COUNT - $OFFENDER"

        # If the IP is a known bad IP in top results, do an automatic block
        # Otherwise, if it's greater that the limit, check to see if it is
        # whitelisted.  If it's not, check to see if it's google.  If it's
        # not, mark it for blocking.

        BLOCK=
        if [ $COUNT -gt $GOOD_LIMIT_PER_HOUR ] ; then
           if valid_ip "$OFFENDER" ; then
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
                 if ! is_search_engine "$NAME" ; then
                    if [ -n "$SEVERE_OVERLOAD" ] ; then
                       echo `date`": ""$SCRIPT"": $ACCESS_LOG: System overloaded - blocking $OFFENDER ($NAME) who has accessed many pages this hour ($COUNT vs limit of $GOOD_LIMIT_PER_HOUR""/hour)" >> "$LOG"
                       BLOCK=1
                    else
                       echo `date`": ""$SCRIPT"": Notice: $OFFENDER ($NAME) accessed many pages this hour ($COUNT vs limit of $GOOD_LIMIT_PER_HOUR""/hour)" >> "$LOG"
                    fi
                 fi
                 ;;
              esac
           fi
        fi

        if [ -n "$BLOCK" ] ; then
           echo "$OFFENDER" >> "$BLOCK_LIST"
        fi
     done )
     rm "$TMPFILE"
  fi
}
readonly -f scan_log_for_200s


#  CLEANUP
#
# Delete any temp files.  Don't delete the lock file because we can't be sure
# our program made it.
# ----------------------------------------------------------------------------

function cleanup {
  test -f "$BLOCK_LIST"           && rm "$BLOCK_LIST" 2>> "$LOG"
  test -f "$NEW_BLOCKED_LIST"     && rm "$NEW_BLOCKED_LIST" 2>> "$LOG"
  test -f "$SUSP_PAGES"           && rm "$SUSP_PAGES" 2>> "$LOG"
  test -f "$ATTACK_PAGES"         && rm "$ATTACK_PAGES" 2>> "$LOG"
  test -f "$ATTACK_PAGE_EXCEPTIONS" && rm "$ATTACK_PAGE_EXCEPTIONS" 2>> "$LOG"
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
# Help
# ----------------------------------------------------------------------------

if [ $# -gt 0 ] ; then
   if [ "$1" = "-h" ] ; then
      echo "$SCRIPT: scan web server logs for attacker activity"
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
      cleanup
      exit 192
   fi
   let "TIMEOUT--"
done

# Cleanup and delete lockfile if we are interrupted
trap "cleanup; test -f $LOCK_FILE && rm $LOCK_FILE" SIGINT SIGQUIT SIGTERM

# Write the PID of this script to the lockfile
echo "$$" > "$LOCK_FILE"

# ----------------------------------------------------------------------------
#  Tune parameters
# ----------------------------------------------------------------------------


let "SUSP_LIMIT_PER_HOUR=DEFAULT_SUSP_LIMIT_PER_HOUR"
let "ERROR_LIMIT_PER_HOUR=DEFAULT_ERROR_LIMIT_PER_HOUR"

# Determine System Load
#
# If the system is overloaded, drop the limit for HTTP 200's by 20%.
# Without period, the load average 100 times larger (2 decimal places).
# That is, be aggressive if the site is overloaded. "1000" means a load
# average of 10.00, or 10 processes starved in the run queue.

LOAD_AVG_5MIN=`cut -d\  -f2 < /proc/loadavg | tr -d .`
if [ "$LOAD_AVG_5MIN" -ge 1000 ] ; then
   let "ADJUSTMENT=DEFAULT_SUSP_LIMIT_PER_HOUR*10/50"
   let "SUSP_LIMIT_PER_HOUR=SUSP_LIMIT_PER_HOUR-ADJUSTMENT"
   echo `date`": ""$SCRIPT"": HTTP 200 limit set to a more aggressive $SUSP_LIMIT_PER_HOUR due to system load" >> "$LOG"
   let "ADJUSTMENT=DEFAULT_ERROR_LIMIT_PER_HOUR*10/50"
   let "ERROR_LIMIT_PER_HOUR=ERROR_LIMIT_PER_HOUR-ADJUSTMENT"
   echo `date`": ""$SCRIPT"": HTTP 4xx limit set to a more aggressive $ERROR_LIMIT_PER_HOUR due to system load" >> "$LOG"
   if [ "$LOAD_AVG_5MIN" -ge 2000 ] ; then
      SEVERE_OVERLOAD=1
   fi
fi

# Determine time
#
# During the late night, drop the limit for HTTP 200's by an additional
# 10% of the default.  That is, be a little more aggressive overnight.
# This adds to the load average adjustment if it's applied above.

HOUR=`date '+%H'`
case $HOUR in
1 | 2 | 3 | 4 | 5 )
   let "ADJUSTMENT=DEFAULT_SUSP_LIMIT_PER_HOUR*10/100"
   let "SUSP_LIMIT_PER_HOUR=SUSP_LIMIT_PER_HOUR-ADJUSTMENT"
   echo `date`": ""$SCRIPT"": HTTP 200 limit set to a more aggressive $SUSP_LIMIT_PER_HOUR due of the hour" >> "$LOG"
   let "ADJUSTMENT=DEFAULT_ERROR_LIMIT_PER_HOUR*10/100"
   let "ERROR_LIMIT_PER_HOUR=ERROR_LIMIT_PER_HOUR-ADJUSTMENT"
   echo `date`": ""$SCRIPT"": HTTP 4xx limit set to a more aggressive $ERROR_LIMIT_PER_HOUR due of the hour" >> "$LOG"
;;
esac


# ----------------------------------------------------------------------------
#  Run Checks
# ----------------------------------------------------------------------------

# These are the scans and the web logs that are checked.

for WEB_LOG in ${WEB_LOG_PATHS[@]} ; do
  if [ ! -f "$WEB_LOG" ] ; then
     echo `date`": ""$SCRIPT"": log file '$WEB_LOG' does not exist" >> "$LOG"
  elif [ ! -r "$WEB_LOG" ] ; then
     echo `date`": ""$SCRIPT"": log file '$WEB_LOG' is not readable" >> "$LOG"
  fi
  scan_log_for_400s            "$WEB_LOG"
  scan_log_for_suspicious_200s "$WEB_LOG"
  scan_log_for_200s_bytes      "$WEB_LOG"
  scan_log_for_200s            "$WEB_LOG"
done

# ----------------------------------------------------------------------------
# Apply blocking
# ----------------------------------------------------------------------------

if [ -f "$BLOCK_LIST" ] ; then

   # Take the list of IP numbers to block and remove any duplicates.

   nice sort -u -o "$BLOCK_LIST" < "$BLOCK_LIST" 2>> "$LOG"

   # Don't add IP's that are already blocked.  If the blocked list is missing
   # (i.e. a first run of this script), create an empty one.

   touch "$NEW_BLOCKED_LIST"
   chmod 640 "$NEW_BLOCKED_LIST"
   if [ ! -f "$BLOCKED_ALREADY_LIST" ] ; then
      touch "$BLOCKED_ALREADY_LIST"
      chmod 640 "$BLOCKED_ALREADY_LIST"
   else
     # /sbin/iptables -L -n | grep "^DROP" | tr -s ' ' | cut -d\  -f4 > "$BLOCKED_ALREADY_LIST" 2>> "$LOG"
     nice fgrep -v -f "$BLOCKED_ALREADY_LIST" < "$BLOCK_LIST" > "$NEW_BLOCKED_LIST" 2>> "$LOG"
   fi

   # Add rules to block the new offenders

   ( while read OFFENDER ; do
     # Append on the input chain the offender IP, asking that it be dropped.
     # This also assumes the default policy is to accept connections.
     if [ -n "$MONITOR_ONLY" ] ; then
        echo `date`": ""$SCRIPT"": would block ""$OFFENDER" >> "$LOG"
     elif valid_ip "$OFFENDER" -ne 0 ; then
        echo `date`": ""$SCRIPT"": blocked ""$OFFENDER" >> "$LOG"
        # /sbin/iptables -A INPUT -s "$OFFENDER" -j DROP 2>> "$LOG"
        "$IPTABLES_CMD" -I INPUT 1 -s "$OFFENDER" -j DROP 2>> "$LOG"
        # block output for now as well, in case there was a traffic burst
        "$IPTABLES_CMD" -I OUTPUT 1 -d "$OFFENDER" -j REJECT 2>> "$LOG"
        echo "$OFFENDER" >> "$BLOCKED_ALREADY_LIST"
     else
        echo `date`": ""$SCRIPT"": cannot block ""$OFFENDER"" - not a valid ip number" >> "$LOG"
     fi
   done ) < "$NEW_BLOCKED_LIST"

fi

# ----------------------------------------------------------------------------
# Cleanup
# ----------------------------------------------------------------------------

cleanup

# Release the lock after cleanup because some files are reused by the other
# blockers.

rm "$LOCK_FILE" 2>> "$LOG"

exit $?

