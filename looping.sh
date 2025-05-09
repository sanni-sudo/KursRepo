#! /bin/bash
#a=0
#lt är mindre än operatorn
#ltrate slingan tills en mindre än 10
#while [ $a -lt 10 ]
#do
	#Print the values
#	echo $a
	#increment the value
#	a=$(expr $a + 1)
#done
#Start of for loop
#for a in 1 2 3 4 5 6 7 8 9 10
#do
	#if a is equal to 5 break the loop
#	if [ $a == 5 ]
#	then
#	 break
#	fi
#Print the value
#echo "Iteration no $a"
#done
#for a in 1 2 3 4 5 6 7 8 9 10
#do
	#if a = 5 then continue the loop and don't move to line 8
#	if [ $a == 5 ]
#	then
#	 continue
#	fi
#	echo "Iteraion no $a"
#done
#a=0
# -gt is greater than operator 
#lterate the loop until a is greater than 10
#until [ $a -gt 10 ]
#do
	#Print the values
#	echo $a
	# increment the value
#	a=$(expr $a + 1 )
#done
#COLORS="röd grön blå"
#for-loopen fortsätter tills den läser alla värden från COLORS
#for COLOR in $COLORS
#do
#	echo "COLOR:$COLOR"
#done
#while true
#do
	#Command to be executed
	#sleep 1 indicates it sleeps for 1 sec
#	echo "Hi, I am infinity loop"
#	sleep 1
#done

CORRECT=n
while [ "$CORRECT" == "n" ]
do
	#loop discontinues when you enter y i.e., when your name is correct
	# -p stands for prompt asking for the input

	read -p "Enter your name:" NAME
	read -p "Is ${NAME} correct?" CORRECT
done
























