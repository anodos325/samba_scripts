#!/bin/sh
#
for arg; do
    case "$arg" in
	-v) VERBOSE=1; shift;;
	-w) WARN=1; shift;;
	*) ;;
    esac
done

awk '
    function res(host, smart, age, error, warn) {
	if(host && (error || (WARN && warn) || VERBOSE)) {
	    # Age is in hours
	    age = int(age/24);
	    if(age < 365) { age = age "d"; }
	    else {
		years = int(age/365);
		days = int(age - years*365);
		age = years "y" days "d";
	    }
	    if(segment) {
		warn = sprintf("%sSegment: %d; ", warn, segment);
	    }
	    print host, smart, dev, age, error, warn;
	}
    }
    /^Host:/ {
	res(host, smart, age, error, warn);
	host = $0;
	error = "";
	warn = "";
	dev = "";
	age = 0;
	segment = 0;
	smart = "SMART=none";
    }
    /Vendor:/ { dev = $2; }
    /Product:/ { dev = dev " " $2; }
    /Revision:/ { dev = dev "(" $2 ")"; }
    /Device:/ { dev = $2 " " $3 "(" $5 ")"; }
    /Device Model:/ { $1 = ""; $2 = ""; dev = $0; }
    # SMART Health Status: HARDWARE IMPENDING FAILURE GENERAL HARD DRIVE FAILURE [asc=5d, ascq=10]
    /SMART Health Status:/ {
	if($4 != "OK") {
	    error = sprintf("%sDisk failed by SMART; ", error);
	    $1=""; $2=""; $3="";
	    warn = sprintf("%s%s; ", warn, $0);
	}
    }
    /^(read|write|verify):/ {
	sub(":", "", $1);
	if($7 == 0) { warn = sprintf("%sEmpty %s; ", warn, $1); }
	if($8 > 0) { error = sprintf("%sUCE %s %d; ", error, $1, $8); }
    }
    /Elements in grown defect list:/ {
	if($6 > 0) { error = sprintf("%sDefect: %d; ", error, $6); }
    }
    /Non-medium error count:/ {
	if($4 > 0) {
	    m = sprintf("Non-medium: %d; ", $4);
	    if($4 > 100) { error = error m; }
	    else { warn = warn m; }
	}
    }
    /number of hours powered up/ {
	age = int($7);
    }
    /Manufactured in week [0-9]+ of year [0-9]+/ {
	w = $4; y = $7;
    }
    !age && /# [0-9]+[ ]+.*offline/ && /Completed without error/ {
	age = $9;
    }
    !age && /# [0-9]+[ ]+Background/ && !/in progress/ {
	age = $7;
    }
    /Failed in segment -->/ { segment++; }
    /Device supports SMART and is/ {
	if($6 == "Enabled") { smart = "SMART=on  "; }
	else { smart = "SMART=OFF "; }
    }
    /SMART support is:/ {
	if($4 == "Enabled") { smart = "SMART=on  "; }
	else { smart = "SMART=OFF "; }
    }
    END { res(host, smart, age, error, warn); }
' WARN=$WARN VERBOSE=$VERBOSE "$1"
