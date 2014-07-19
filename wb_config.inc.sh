# General Configuration
#
# This file contains general configuration settings common to all scripts.
# There are additional configuration files that should be examined for
# a new installation, including wb_whitelist, wb_blacklist and
# attack_vectors.


# Test Mode
# ----------------------------------------------------------------------------
# blank to enable blocking, non-blank (e.g. =1) to disable blocking for test
# purposes.

declare -r  MONITOR_ONLY=


# Thresholds
# ----------------------------------------------------------------------------
# It is very important that we don't block any legitimate users.  The limits
# must be set to catch extreme offenders.  What limits are appropriate depend
# on the web site.  These limits are base numbers which are modified by the
# script, and they are only applied if an IP isn't white or black listed.
#
# The ERROR_LIMIT_PER_HOUR is the maximum number of HTTP 4xx errors.  A large number
# indicate something that's searching for weaknesses.  14 catches all
# crawlers but catches some legitimate users.  Unfortunately, frustrated users
# may try repeatly clicking on a dead link...otherwise we could set this
# lower.  30 seems to work OK.
#
# The SUSP_LIMIT_PER_HOUR is the maximum number of HTTP 200 successes.  A
# large number suggests a high load from an automated crawl.  We don't want to
# block real users.  Most people download less than 100 items from the web
# site but some IP's will represent multiple users (NAT).
#
# GOOD_LIMIT_PER_HOUR is for printing the notices of high hit activity.
# Does not block.
#
# BYTE_LIMIT_PER_HOUR is the maximum number of bytes from HTTP 200 successes
# before a user is blocked.  Keep in mind jquery is 250K.  Photos collection
# is nearly 700K.
#
# TCP_LIMIT is the maximum number of TCP connections per IP.
#
# For TOP_LIMIT, the top offender will usually be the top of the list.  This
# script runs often enough that nabbing the top one all that you need.
# Setting it to 3 will account for active whitelisted ips.  It's probably
# safe to set it higher...say 10...but you increase the risk of blocking
# a legitimate user if your other limits are too aggressive.
#
# SSHD_LIMIT_PER_HOUR - number of connection attempts allowed per hour (e.g.
# 15)
#
# MAIL_LIMIT_PER_MIN  - number of connection attempts allowed per minute (e.g.
# 15)
#
# GEO_IP - guess at the country and weigh certain countries more heavily

declare -ir DEFAULT_ERROR_LIMIT_PER_HOUR=15               # HTTP errors per hour
declare -ir DEFAULT_SUSP_LIMIT_PER_HOUR=25                  # HTTP hits per hour
declare -ir GOOD_LIMIT_PER_HOUR=250                         # HTTP hits per hour
declare -ir BYTE_LIMIT_PER_HOUR=50000000                   # HTTP bytes per hour
declare -ir TOP_LIMIT=5                                          # top n to test
declare -ir TCP_LIMIT=100                              # TCP/IP connection limit
declare -ir SSHD_LIMIT_PER_HOUR=15
declare -i  SUSP_LIMIT_PER_HOUR                           # effective good limit
declare -i  ERROR_LIMIT_PER_HOUR                         # effective error limit
declare -ri MAIL_LIMIT_PER_MIN=15                   # login attempts per minute
declare -r  GEO_IP=1                                       # non-blank to enable

# Enable Blockers
# ----------------------------------------------------------------------------
# Leave blank to disable, or set to non-blank (e.g. 1) to enable
# HAS_MAIL - check a postfix mail server for attackers
# HAS_SSH  - check the ssh activity for attackers
# HAS_WEB  - check the web server for attackers
# DOS (Denial-of-service) blocker always runs

declare -r HAS_MAIL=1
declare -r HAS_SSH=1
declare -r HAS_WEB=1


# Web logs
# ----------------------------------------------------------------------------
# A shell array.  List the access logs to scan for each of your virtual hosts.

declare -a WEB_LOG_PATHS
WEB_LOG_PATHS[0]="/var/log/apache2/pegasoft-access_log"
WEB_LOG_PATHS[1]="/var/log/apache2/sparforte-access_log"
WEB_LOG_PATHS[2]="/var/log/apache2/willow-access_log"


# Operating System
# ----------------------------------------------------------------------------
# Settings that may differ across different versions of Linux.
# PREFIX         the installation prefix (e.g. /root, /usr/local, etc.)
# LOG_PREFIX     where log files are stored (e.g. /var/log)
# OS_NAME        used to locate certain commands, etc.
#  - red hat
#  - suse
# FIREWALL_TYPE  
#  - custom - a custom Linux iptables firewall maintained by the user
#  - initd_iptables - a init.d service called "iptables"
#  - suse - SuSE Linux firewall, SuSEfirewall2
# SSHD_LOG_FILE  where sshd stores the access logs
#  - Red Hat may be /var/log/secure.  SuSE /var/log/messages
# MAILLOG        the current mail log
# IPTABLES_CMD   full path to iptables command
#  - Red Hat may be /sbin/iptables, SuSE /usr/sbin/iptables

declare -rx PREFIX="/root"
declare -rx LOG_PREFIX="/var/log"
declare -rx FIREWALL_TYPE="suse"
declare -rx OS_NAME="suse"
# These should probably be determined from the OS_NAME but for now you must
# supply them.
declare -rx SSHD_LOG_FILE="/var/log/messages"
declare -r   MAILLOG="/var/log/mail"
declare -rx IPTABLES_CMD="/usr/sbin/iptables"


# Standard Script variables
# ----------------------------------------------------------------------------
# These can normally be left to their default values.
# SCRIPT               the name of the script
# BLOCK_LIST           list of candidate ip's to block
# BLOCKED_ALREADY_LIST list of ip's currently blocked
# NEW_BLOCKED_LIST     new currently blocked list when lists are weekly cleared
# BLOCKED_WEEKLY_LIST  list of frequent offender ip's
# LOCK_FILE            the lock file for this project
# LOG                  the log file for this project

declare -rx SCRIPT=${0##*/}
declare -rx BLOCK_LIST="$PREFIX/data/web_block_list.txt"
declare -rx BLOCKED_ALREADY_LIST="$PREFIX/data/web_blk_already.txt"
declare -rx NEW_BLOCKED_LIST="$PREFIX/data/web_new_blocked.txt"
declare -rx BLOCKED_WEEKLY_LIST="$PREFIX/data/web_blk_weekly.txt"
declare -rx LOCK_FILE="$PREFIX/data/blocker.lck"
declare -rx LOG="$LOG_PREFIX/blocker.log"


# ----------------------------------------------------------------------------
# Shared Functions
# ----------------------------------------------------------------------------


# VALID IP
#
# From LinuxJournal.
# http://www.linuxjournal.com/content/validating-ip-address-bash-script
# The regular expression in =~ requires double quotes in some older Linux's
# (e.g. Red Hat 5).
# ----------------------------------------------------------------------------

function valid_ip()
{
    local  ip=$1
    local  stat=1

    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
            && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}
readonly -f valid_ip


# ASIAN IP
#
# True if IP number is in ranges handled by APNIC (Asia-Pacific NIC)
# http://collaboration.cmc.ec.gc.ca/science/rpn/biblio/ddj/Website/articles/SA/v14/i11/a3.htm
# ----------------------------------------------------------------------------

function asian_ip {

  local IP3=${1:0:3}
  local IP4=${1:0:4}
  local IP8=${1:0:8}
  local APNIC=1

  if   [ "$IP3" = "58." ] ; then
    APNIC=0
  elif [ "$IP3" = "61." ] ; then
    APNIC=0
  elif [ "$IP4" = "126." ] ; then
    APNIC=0
  elif [ "$IP8" = "168.208." ] ; then
    APNIC=0
  elif [ "$IP8" = "196.192." ] ; then
    APNIC=0
  elif [ "$IP4" = "202." ] ; then
    APNIC=0
  elif [ "$IP4" = "210." ] ; then
    APNIC=0
  elif [ "$IP4" = "218." ] ; then
    APNIC=0
  elif [ "$IP4" = "220." ] ; then
    APNIC=0
  elif [ "$IP4" = "222." ] ; then
    APNIC=0
  fi

  return $APNIC

}
readonly -f asian_ip


# RUSSIAN IP
#
# True if IP number is in ranges handled by RIPE (Russia, Hungary, etc. NIC)
# http://collaboration.cmc.ec.gc.ca/science/rpn/biblio/ddj/Website/articles/SA/v14/i11/a3.htm
# ----------------------------------------------------------------------------

function russian_ip {

  local IP3=${1:0:3}
  local IP4=${1:0:4}
  local RIPE=1

  if   [ "$IP3" = "80." ] ; then
    RIPE=0
  elif [ "$IP3" = "81." ] ; then
    RIPE=0
  elif [ "$IP3" = "82." ] ; then
    RIPE=0
  elif [ "$IP3" = "83." ] ; then
    RIPE=0
  elif [ "$IP3" = "84." ] ; then
    RIPE=0
  elif [ "$IP3" = "85." ] ; then
    RIPE=0
  elif [ "$IP3" = "86." ] ; then
    RIPE=0
  elif [ "$IP3" = "87." ] ; then
    RIPE=0
  elif [ "$IP3" = "88." ] ; then
    RIPE=0
  elif [ "$IP3" = "89." ] ; then
    RIPE=0
  elif [ "$IP3" = "90." ] ; then
    RIPE=0
  elif [ "$IP3" = "91." ] ; then
    RIPE=0
  elif [ "$IP4" = "193." ] ; then
    RIPE=0
  elif [ "$IP4" = "194." ] ; then
    RIPE=0
  elif [ "$IP4" = "195." ] ; then
    RIPE=0
  elif [ "$IP4" = "212." ] ; then
    RIPE=0
  elif [ "$IP4" = "213." ] ; then
    RIPE=0
  elif [ "$IP4" = "217." ] ; then
    RIPE=0
  fi

  return $RIPE

}
readonly -f russian_ip


# SAMERICAN IP
#
# True if IP number is in ranges handled by LACNIC (Latin American and Caribbean NIC)
# Includes Brazil, Argentina but also Mexico, etc.
# http://collaboration.cmc.ec.gc.ca/science/rpn/biblio/ddj/Website/articles/SA/v14/i11/a3.htm
# ----------------------------------------------------------------------------

function samerican_ip {

  local IP4=${1:0:4}
  local LACNIC=1

  if   [ "$IP4" = "189." ] ; then
    LACNIC=0
  elif [ "$IP4" = "190." ] ; then
    LACNIC=0
  elif [ "$IP4" = "200." ] ; then
    LACNIC=0
  elif [ "$IP4" = "201." ] ; then
    LACNIC=0
  fi

  return $LACNIC

}
readonly -f samerican_ip

