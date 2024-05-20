

input="keys-reduced.txt"
while IFS= read -r line
do
	echo "$line"
	sh -c '$line'
done < "$input"
