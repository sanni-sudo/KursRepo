#! /bin/bash
var1=5
Add () {
   var1=$(($var1+10))
   echo $var1

}
Add
#Assigning the output of function Add to another variable 'var2'.
var2=$var1
echo $var2

