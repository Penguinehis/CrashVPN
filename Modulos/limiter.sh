#!/bin/bash
database="/root/usuarios.db"
echo $$ > /tmp/pids
if [ ! -f "$database" ]
then
	echo "Arquivo /root/usuarios.db não encontrado"
	exit 1
fi
while true
do
tput setaf 7 ; tput setab 4 ; tput bold ; printf '%30s%s%-10s\n' " SSH Limiter 2.0 " ; tput sgr0 ; echo ""
tput setaf 7 ; tput setab 4 ; tput bold ; printf '%30s%s%-10s\n' " Usuario | Onlines / Limite de logins " ; tput sgr0 ; echo ""
	while read usline
	do
		user="$(echo $usline | cut -d' ' -f1)"
		s2ssh="$(echo $usline | cut -d' ' -f2)"
		if [ -z "$user" ] ; then
			echo "" > /dev/null
		else
			ps x | grep [[:space:]]$user[[:space:]] | grep -v grep | grep -v pts > /tmp/tmp2
			s1ssh="$(cat /tmp/tmp2 | wc -l)"
			tput setaf 6 ; tput bold ; printf '  %-35s%s\n' $user $s1ssh/$s2ssh ; tput sgr0
			if [ "$s1ssh" -gt "$s2ssh" ]; then
			tput setaf 7 ; tput setab 4 ; tput bold ; printf '%30s%s%-10s\n' " Usuario Desconectado por ultrapassar o limite!!! " ; tput sgr0
				while read line
				do
					tmp="$(echo $line | cut -d' ' -f1)"
					kill $tmp
				done < /tmp/tmp2
				rm /tmp/tmp2
			fi
		fi
	done < "$database"
	sleep 5
	clear
done