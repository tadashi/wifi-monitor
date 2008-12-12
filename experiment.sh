#!/bin/sh

date 121000002008

for a in 10 15 20 25 30
do
	echo "python /root/wifi-monitor/py_monitoring.py -t ${1} -m ${2} -x ${a}"
	python /root/wifi-monitor/py_monitoring.py -t ${1} -m ${2} -x ${a}
	mv 12*.csv ${a}.csv
done
