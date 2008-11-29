#
# Regular cron jobs for the gad package
#
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

*/15 *   * * *   root    [ -x /usr/sbin/gad ] && /usr/sbin/gad /etc/gad.conf
