#!/bin/sh

pid=1565

filepath=`ls /dump/$pid* | wc -w`
echo $filepath
