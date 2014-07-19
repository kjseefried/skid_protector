skid_protector
==============

Linux firewall shell scripts to protect web servers from intrusion.

Skid Protector disrupts website vulnerability scans and denial-of-service (DOS)
attacks.  The project is written entirely in Bash shell scripts and
uses the Linux firewall.

Skid Protector is similar to other tools such as Fail2Ban and DenyHosts.  It
is easier to set up and use for simple websites.


How It Works
------------

SP contains several "blocker" scripts that examine specific systems

- mail_blocker - a Postfix mail
- sshd_blocker - SSHD
- web_blocker  - Apache

Each of these blockers can be enabled or disabled, except for the DOS
blocker which is always on.

Each blocker greps log files for strings indicating an obvious
scan or abusive behaviour and blocks the IP number.  The IP remains
blocked until the list is cleared.  Repeated violations result in a
long-term ban.

There is also "dos_blocker", a denial-of-service blocker.  It runs
continually and blocks any IP number opening a large number of
connections to your computer.

This has been tested on Red Hat and SuSE Linux, and should work on
other Linux's with minor changes.


Setup and Installation
----------------------

SP cannot be simply be downloaded and installed.  Because SP
blocks by IP, you will need to do some configuration, including
whitelisting IP numbers that should never be blocked.


1. Install the Scripts

These scripts are installed by default in the directory /root/bin
and expect a data directory called /root/data.  However, this can
be changed in the main configuration file.


2. The Main Configuration

The main configuration file  is wb_config.inc.sh.  Review the
settings and change the values to match your system.  Comments in the
file describe each setting.

3. Whitelist and Blacklist IP's

Review wb_whitelist.inc.sh and add all IP numbers that you
want never to be blocked.

Review wb_blacklist.inc.sh and add any IP numbers that you want
permanently blocked.

4. Edit the Web Attack Vectors

The file attack_vectors.inc.sh contains the list of strings that SP
will search for in the web server logs.  There are two categories of
strings: (1) attacks, which are strings in URL's for web pages that
do not exist (HTTP 404) representing an obvious attempt to probe for
weaknesses, or (2) suspicious pages, which are strings for pages that
actually exist (HTTP 200) but repeated attempts to access these pages
suggest that someone is trying to attack your website.

Run clean_attack_vectors.  This will check the attack strings
against your current log to see if they may refer to actual web
pages.  If an attack string matches an actual page, you can either
list an exception string in the ATTACK_PAGE_EXCEPTIONS section and
it will be ignored, or move the string from the ATTACK_PAGES section
and put it in the SUSP_PAGES (suspicious pages) instead where
repeated references to the page will result in an IP block.

5. Check with MONITOR_ONLY

In MONITOR_ONLY mode, SP will report the IP's that it would block
without actually blocking the IP number.  This is useful for testing
your configuration.  Set MONITOR_ONLY to a non-blank value (e.g.
"1").

Run run_blockers.sh.  Check the log file for errors.


6. Schedule SP in Cron

Add SP to your cron tasks:
1. Add a cron entry to run run_blockers every few minutes.
2. Add a daily entry to run blockers_daily_clear.sh.
3. Add a weekly entry to run blockers_weekly_clear.sh.

Set MONITOR_ONLY to blank to enable blocking.


