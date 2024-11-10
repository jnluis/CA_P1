for (( i=0; i<100000; i++ ))
do

   #16 character alphanumeric keys from /dev/urandom
   key=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)
   skey=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)
   #echo "Key: $key"
   #echo "Secondary Key: $skey"
   
   #My AES
   dd if=/dev/urandom bs=1 count=4K status=none | base64 | python3 encrypt.py $key | python3 decrypt.py $key > /dev/null

   #My SAES
   dd if=/dev/urandom bs=1 count=4K status=none | base64 | python3 encrypt.py $key $skey | python3 decrypt.py $key $skey > /dev/null

   #Python Cryptography AES
   dd if=/dev/urandom bs=1 count=4K status=none| base64 | python3 AES_library_implementation.py $key > /dev/null

   (cd AES-NI && dd if=/dev/urandom bs=1 count=4K status=none | base64 | ./ecb_exe $key $skey > /dev/null && cd ..) 
done

# Find the minimum speeds
for file in time/*_times.txt;
do
    min=100
    type=$(echo $file | cut -d'/' -f 2 | cut -d'_' -f 1-2)
    while IFS= read -r line
    do
        if [[ "$(echo "$line < $min" | bc)" -eq "1" ]]
        then
            min=$line
        fi
    done < "$file"
    echo -e "${type}\t${min}"
done