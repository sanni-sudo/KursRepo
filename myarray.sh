#! /bin/bash
# declare an array with pre-defined values
#declare -a my_data=(Learning "Bash variables" from GFG);
# get length of the array
#arrLength=${#my_data[@]}
# print total number of elements in the array
#echo "Total number of elements in array is: $arrLength"
# iterate through the array and print length of each element and their values
#echo "Below are the elements and their respective lengths:"
#for (( i=0; i<arrLength; i++ ));
#do
#	echo "Element $((i+1)) is=> '${my_data[$i]}'; and its length is ${#my_data[i]}"
#done
# print the whole array at once
#echo "All the elements in array : '${my_data[@]}'"
# declare array
#declare -A newArray=([Ron]=10 [Johan]=30 [Ram]=70 [Shyam]=100)
# iterate through the array
#for key in "${!newArray[@]}";
#do
#	echo "$key scored : ${newArray[$key]} in Math test";
#done
#transport=('car' 'train' 'bike' 'bus')
#transport[1]='trainride'
#echo "${transport[@]}"
#unset transport[1]

USERS=('Utvecklare' 'HR' 'Säkerhetsavdelningen')
USERS[1]='IT-avdelningen'
echo "${USERS[@]}"
unset USERS[1]

