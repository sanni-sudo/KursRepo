#!/bin/bash
#defining, new variable and assigning it a value
#myvar=Geeks
#echo "$myvar"
#newvar=myvar
#echo "$newvar"
#Above code will give an error
#newvar=$myvar
#echo "$newvar"
#myvar=Hello
#newvar="welcome to gfg"
#echo "$myvar, $newvar"
#variables are case sensitive
#Myvar="Hi again!"
#echo "$Myvar"
#str1='welcome'
#str2="to"
#str3="GeeksForGeeks"
#str4="Programming"
#arr1=("$str1" "$str2" "$str3")
#arr2=("$str4" "is" "fun" 10 20 30)
#echo "length of arr1: ${#arr1[@]}"
#echo "length of arr2: ${#arr2[@]}"
#echo "element of arr1[2]: ${arr1[2]}"
#echo "element of arr2[2]: ${arr2[2]}"
#echo "length of arr1[2]: ${#arr1[2]}"
#echo "length of arr2[2]: ${#arr2[2]}"
#echo "This gets printed if index is OutOfBound: ${arr1[10]:-N/A}"
#arr1:  
#echo arr2:  Programming is fun 10 20 30
#length of arr1:  0
#echo length of arr2:  6
#element of arr1[2]:  0
#element of arr2[2]:  3
#This gets printed if index is OutOfBound: 
#str="welcome to GeeksForGeeks"
#echo ${str:-100}
#echo ${str:7}
#echo ${str:0:10}
#match="Welcome.to.GeeksForGeeks"
#echo "This will delete the shortest substring that matches *. from front: " ${match#*.}
#echo "This will delete the shortest substring that matches *. from back: " ${match%.*}
#echo "This will delete the longest substring that matches *. from front: " ${match##*.}
#echo "This will delete the longest substring that matches *. from back: " ${match%%.*}
#Initializing two variables
#a=10
#b=20
#Check whether they are equal
#if [ $a == $b ]
#then
#echo "a is equal to b"
#fi
#Check whether they are not equal
#if [ $a != $b ]
#then
#echo "a is not equal to b"
#fi
#Initializing two variables
#a=20
#b=20
#if [ $a == $b ]
#then
#If they are equal then print this
#echo "a is equal to b"
#else
#else print this
#echo "a is note equal to b"
#fi

CARS="bmw"

#Pass the variable in string
case "$CARS" in
	#case 1
	"mercedes") echo "Headquarters - Affalterbach, Germany" ;;
	#case 2
	"audi") echo "Headquarters - Ingolstadt, Germany" ;;
	#case 3
	"bmw") echo "Headquarters - Chennai, Tamil Nadu, India" ;;
esac






























