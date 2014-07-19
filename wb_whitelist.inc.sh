# Whitelisted IP's
# ----------------------------------------------------------------------------
# This is loaded by web_blocker.sh
#
# Whitelisted IP's include localhost, local network machines, your office,
# etc

declare IP_WHITELIST=""

IP_WHITELIST="$IP_WHITELIST 127.0.0.1"        # Localhost IPV4
IP_WHITELIST="$IP_WHITELIST ::1"              # Localhost IPV6
IP_WHITELIST="$IP_WHITELIST "                 # Final Space
readonly IP_WHITELIST

# A list of known customer IP's.  This list could, of course, change at any
# time.  Still, we don't want to block obvious good IP's of heavy site users.
# We hope the limits are set so we never block them, but this is a fail-safe.

declare IP_CUSTOMERS=""

IP_CUSTOMERS="$IP_CUSTOMERS 69.95.181.76"    # Ada search engine
IP_CUSTOMERS="$IP_CUSTOMERS "                # Final space
readonly IP_CUSTOMERS

