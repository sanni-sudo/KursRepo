#! /bin/bash

myvar=5

function calc(){

	# use keyword 'local' to define a local variable Definiera en lokal variabel
	local myvar=5
	((  myvar=myvar*5 ))

	# print the value of local variable Skriver ut värdet av den lokala variabeln
	echo "Lokalt myvar i funktionen: $myvar"
}

# call the function calc Anropa funktionen
calc


# print the value of global variable and observe that it is unchanged. Skriver ut det globala variabelvärdet (oförändrat)
echo "Globalt myvar utanför funktionen: $myvar"
