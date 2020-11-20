#!/bin/sh


# progs variables
PROGNAME=`basename "$0"`
VERSION="1.0.1"
IPTABLES=`which iptables`
WGET=`which wget`
ALL_COUNTRIES="ad ae af ag ai al am ao ap ar as at au aw az ba bb bd be bf bg bh bi bj bl bm bn bo bq br bs bt bw by bz ca cd cf cg ch ci ck cl cm cn co cr cu cv cw cy cz de dj dk dm do dz ec ee eg er es et eu fi fj fm fo fr ga gb gd ge gf gg gh gi gl gm gn gp gq gr gt gu gw gy hk hn hr ht hu id ie il im in io iq ir is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mf mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg si sk sl sm sn so sr ss st sv sx sy sz tc td tg th tj tk tl tm tn to tr tt tv tw tz ua ug us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw"


# default options
VERBOSE=0
KNOWN_ATTACKERS=0
FLUSH=0
ICMP=0
TOR=0
BLOCK_COUNTRIES=""
WHITELIST=""
ALLOW_COUNTRIES=""
BLOCK_ALL=0


# default URI
ATTACKERS_URI="http://report.rutgers.edu/DROP/attackers"
ATTACKERS_URI="${ATTACKERS_URI} https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
ATTACKERS_URI="${ATTACKERS_URI} https://www.openbl.org/lists/base.txt"

TOR_URI="https://check.torproject.org/torbulkexitlist"

#COUNTRIES_URI="http://www.ipdeny.com/ipblocks/data/countries/"
COUNTRIES_URI="http://www.ipdeny.com/ipblocks/data/aggregated/"


usage()
{
	echo "usage: ${PROGNAME} [options]"
	echo "options:"
	echo "    -h             : display this and exit"
	echo "    -V             : display version number and exit"
	echo "    -v             : verbose mode"
	echo "    -k             : block KNOWN attackers"
	echo "    -i             : block ICMP packet"
	echo "    -t             : block TOR exit nodes"
	echo "    -f             : flush all the rules before applying the new ones"
	echo "    -a             : flush and block ALL (above)"
	echo "    -l             : list country code"
	echo "    -c c1,c2,...   : block all IP from countries c1,c2,..."
	echo "    -w ip1,ip2,... : allow all ip1,ip2,..."
	echo "    -C c1,c2,...   : allow all IP from countries c1,c2,..."
	echo "    -B             : finish the rules by a \"block all\""
	echo "example:"
	echo "    ${PROGNAME} -f -C fr,be -w 192.168.1.0/24 -k -i -t -B -v"
}


version()
{
	echo "${PROGNAME} ${VERSION}"
}


warning()
{
	echo "$@" >&2
}


verbose()
{
	[ ${VERBOSE} -gt 0 ] && warning "$@"
}


xappend()
{
	local file="$1"
	shift

	echo "$@" >> "${file}"
}


check_country()
{
	local	val="$1"
	local	country

	for country in ${ALL_COUNTRIES};
	do
		[ "${country}" = "${val}" ] && {
			return 0
		}
	done

	return 1
}


list_country_code()
{
	local country

	for country in $ALL_COUNTRIES;
	do
		echo ${country}
	done
}


flush_all()
{
	${IPTABLES} -F
	echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_all
}


list_rules()
{
	local table="$1"

	[ -z "${table}" ] && table="filter"

	${IPTABLES} -S -t "${table}"
}


parse_options()
{
	local	opt

	while getopts "h?Vvkiftalc:w:C:B" opt; do
		case "${opt}" in
		h|\?)
		usage
		exit 0
		;;

		V)
		version
		exit 0
		;;

		v)
		VERBOSE=1
		;;

		k)
		KNOWN_ATTACKERS=1
		;;

		i)
		ICMP=1
		;;

		f)
		FLUSH=1
		;;

		t)
		TOR=1
		;;

		a)
		KNOWN_ATTACKERS=1
		ICMP=1
		FLUSH=1
		TOR=1
		;;

		l)
		list_country_code
		exit 0
		;;

		c)
		BLOCK_COUNTRIES="${OPTARG}"
		;;

		w)
		WHITELIST="${OPTARG}"
		;;

		C)
		ALLOW_COUNTRIES="${OPTARG}"
		;;

		B)
		BLOCK_ALL=1
		;;

		esac
	done
}


add_ip_from_uri()
{
	local	uri="$1"
	local	list="$2"

	${WGET} -qO- "${uri}" | sort | uniq | grep -Ev '^(#|$|;)' >> "${list}"
}


add_all_ip_from_list()
{
	local	list="$1"
	local	alluri="$2"

	for uri in ${alluri};
	do
		add_ip_from_uri "${uri}" "${list}"
	done
}


add_known_attackers()
{
	local	list="$1"

	verbose "Adding rule for blocking known attackers"

	add_all_ip_from_list "$list" "$ATTACKERS_URI"
}


add_tor_exit_nodes()
{
	local	list="$1"

	verbose "Adding rule for blocking tor exit nodes"

	add_all_ip_from_list "${list}" "${TOR_URI}"
}


add_block_countries()
{
	local	list="$1"
	local	country

	for country in `echo ${BLOCK_COUNTRIES} | tr ',' ' '`;
	do
		verbose "Adding rule for blocking country ${country}"
		check_country "${country}" || {
			warning "${country} is not a valid code"
			continue
		}
		add_ip_from_uri "${COUNTRIES_URI}/${country}-aggregated.zone" "${list}"
	done
}


add_allow_country()
{
	local	list="$1"
	local	country

	for country in `echo ${ALLOW_COUNTRIES} | tr ',' ' '`;
	do
		verbose "Adding rule for allowing country ${country}"
		check_country "${country}" || {
			warning "${country} is not a valid code"
			continue
		}
		add_ip_from_uri "${COUNTRIES_URI}/${country}-aggregated.zone" "${list}"
	done
}


create_block_list()
{
	local	tmplist=`mktemp $PROGNAME-XXXXXX`
	local	tmplist2=`mktemp $PROGNAME-XXXXXX`

	[ ${KNOWN_ATTACKERS} -gt 0 ] && add_known_attackers "${tmplist}"
	[ ${TOR} -gt 0 ] && add_tor_exit_nodes "${tmplist}"
	[ -n "${BLOCK_COUNTRIES}" ] && add_block_countries "${tmplist}"

	# Avoid duplicated items
	cat ${tmplist} | sort | uniq | grep -Ev '^(#|$|;)' > "${tmplist2}"
	rm -f "${tmplist}"

	echo ${tmplist2}
}


create_white_list()
{
	local	tmplist=`mktemp $PROGNAME-XXXXXX`
	local	tmplist2=`mktemp $PROGNAME-XXXXXX`

	[ -n "${WHITELIST}" ] && {
		local	white
		verbose "Adding rule for whitelist"
		for white in `echo $WHITELIST | tr ',' ' '`; do
			xappend "${tmplist}" "${white}"
		done
	}

	[ -n "${ALLOW_COUNTRIES}" ] && add_allow_country "${tmplist}"

	# Avoid duplicated items
	cat ${tmplist} | sort | uniq | grep -Ev '^(#|$|;)' > "${tmplist2}"
	rm -f "${tmplist}"

	echo ${tmplist2}
}


set_block_list()
{
	local	list="$1"
	local	ip

	for ip in `cat "${list}"`;
	do
		${IPTABLES} -A INPUT -s "${ip}" -j DROP
	done
}


set_white_list()
{
	local	list="$1"
	local	ip

	for ip in `cat "${list}"`;
	do
		${IPTABLES} -A INPUT -s "${ip}" -j ACCEPT
	done
}


block_icmp()
{
	verbose "Adding rule for blocking ICMP packet"
	${IPTABLES} -A INPUT -p icmp -j DROP
	echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all
}


check_root()
{
	[ "`id -u`" != "0" ] && {
		warning "This script must be run as root"
		exit 1
	}
}


check_var()
{
	[ -z "${IPTABLES}" -o -z "${WGET}" ] && {
		warning "This script needs iptables and wget"
		exit 1
	}
}


block_all()
{
	${IPTABLES} -A INPUT -j DROP
}


main()
{
	local	blocklist
	local	whitelist

	parse_options "$@"

	check_root
	check_var

	whitelist=`create_white_list`
	blocklist=`create_block_list`
	[ ${FLUSH} -gt 0 ] && flush_all
	[ ${ICMP} -gt 0 ] && block_icmp
	[ `wc -l ${whitelist} | cut -d ' ' -f 1` -gt 0 ] && set_white_list "${whitelist}"
	[ `wc -l ${blocklist} | cut -d ' ' -f 1` -gt 0 ] && set_block_list "${blocklist}"
	[ $BLOCK_ALL -gt 0 ] && block_all
	[ $VERBOSE -gt 0 ] && list_rules

	rm -f "${blocklist}"
	rm -f "${whitelist}"
}


main "$@"
