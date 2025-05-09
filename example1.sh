#! /bin/bash
# declare a variable which will store all the values of our arguments, 
# in doing so we will made use of the special variable "$@". 
# Alternatively, "$*"can also be used.
#myvar=("$@")
# Lets store the length of the number of arguments (currently unknown)
# in another variable. Here we can make use of the special variable '$#'
#le="$#"
#echo $le
# let us now print the arguments that user passed by looping
# through the length of the number of arguments.
#for (( i=0; i<le; i++ ))
#do
#	echo "Argument $((i+1)) is => ${myvar[i]}"
#done 
name=$1
age=$2
jobb=$3
homeaddress=$4
sambo=$5

echo $name

echo Enter your name
read name
echo "Your name is $name"

echo $age
echo Enter your age
read age
echo "Your age is $age"

echo $jobb
echo Enter your jobb
read jobb
echo "Your jobb is $jobb"

echo $address
echo Enter your homeaddress
read homeaddress
echo "Your homeaddress is $homeaddress"





















