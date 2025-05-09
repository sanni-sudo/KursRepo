#! /bin/bash
#echo "The process ID of current shell is: $$"
#echo "The exit status of last executed command was: $?"
#echo "The name of this script is: $0"
#echo "First argument passed to this script is: $1"
#echo "Second argument passed to this script is: $2"
#echo "Total number of arguments passed to this script is: $#"
#echo "His full name is: $1 $2"
#count=10
#if [ $count -eq 10 ]
#then
#	echo "true"
#else
#	echo "false"
#fi
#value="guessme"
#guess=$1
#if [ "$value" = "$guess" ]
#then
#echo "They are equal"
#else
#echo "They are not equal"
#fi

filename=$1

if [ -f "$filename" ] && [-w "$filename" ]
then
	echo "hello" > $filename
else
	touch "$filename"
	echo "hello" > $filename
fi

