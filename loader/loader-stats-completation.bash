#!/usr/bin/env bash


_loader_stats_completions(){
	if [ "${#COMP_WORDS[@]}" != "2" ]; then
		return
  fi


	local cur
    cur="${COMP_WORDS[COMP_CWORD]}"
	local suggestions=()
	local IFS=$'\n'

	echo $cur 
    case "$cur" in
         -i)
            suggestions=($(compgen -W "$(find /sys/class/net -printf "%f\n" | tail -n +2)" -- "${COMP_WORDS[1]}"))
			echo "Suggestions: ${suggestions[@]}"
            ;;
		-f)
			suggestions=( $(compgen -W "$(find ./ -maxdepth 1 -type f -not -name "*.[c|h]" -printf "%f\n" | tail -n +2)" -- $cur) )
			;;
        *)
            COMPREPLY=()
            ;;
    esac


	if [ "${#suggestions[@]}" == "1" ]; then
		COMPREPLY=("${suggestions[0]}")
	  else
		for i in "${!suggestions[@]}"; do
		  suggestions[$i]="$(printf '%*s' "-$COLUMNS"  "${suggestions[$i]}")"
		done

		COMPREPLY=("${suggestions[@]}")
	fi
    return 0
}

complete -F _loader_stats_completions loader-stats
