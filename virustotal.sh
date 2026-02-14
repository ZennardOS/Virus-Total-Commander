#!/bin/bash 

APIKEY="YOUR_API_KEY"

show_logo() {
    echo -e "\e[36m"
    cat << 'EOF'
/$$    /$$ /$$                                /$$$$$$                                                                  /$$                    
| $$   | $$|__/                               /$$__  $$                                                                | $$                    
| $$   | $$ /$$  /$$$$$$  /$$   /$$  /$$$$$$$| $$  \__/  /$$$$$$  /$$$$$$/$$$$  /$$$$$$/$$$$   /$$$$$$  /$$$$$$$   /$$$$$$$  /$$$$$$   /$$$$$$ 
|  $$ / $$/| $$ /$$__  $$| $$  | $$ /$$_____/| $$       /$$__  $$| $$_  $$_  $$| $$_  $$_  $$ |____  $$| $$__  $$ /$$__  $$ /$$__  $$ /$$__  $$
 \  $$ $$/ | $$| $$  \__/| $$  | $$|  $$$$$$ | $$      | $$  \ $$| $$ \ $$ \ $$| $$ \ $$ \ $$  /$$$$$$$| $$  \ $$| $$  | $$| $$$$$$$$| $$  \__/
  \  $$$/  | $$| $$      | $$  | $$ \____  $$| $$    $$| $$  | $$| $$ | $$ | $$| $$ | $$ | $$ /$$__  $$| $$  | $$| $$  | $$| $$_____/| $$      
   \  $/   | $$| $$      |  $$$$$$/ /$$$$$$$/|  $$$$$$/|  $$$$$$/| $$ | $$ | $$| $$ | $$ | $$|  $$$$$$$| $$  | $$|  $$$$$$$|  $$$$$$$| $$      
    \_/    |__/|__/       \______/ |_______/  \______/  \______/ |__/ |__/ |__/|__/ |__/ |__/ \_______/|__/  |__/ \_______/ \_______/|__/  
EOF
    echo -e "\e[0m"
}

show_logo
sleep 2

function HashChecker() {
  local heading="$2"
  if [ "$heading" != "all" ]; then 
      let "heading*=8"
  fi

  RES=$(curl -s -X GET -H "x-apikey: $APIKEY" "https://www.virustotal.com/api/v3/files/$1")
  naming=$(echo "$RES" | jq '.data.attributes.meaningful_name' | tr -d '"')
  echo "Name: $naming"
  total=$(echo "$RES" | jq -r '.data.attributes.last_analysis_stats | to_entries[] | "  \(.key): \(.value)"')
  echo "statistics: "
  if [ "$heading" = "all" ]; then 
      stats=$(echo "$RES" | jq '.data.attributes.last_analysis_results' | sed 's/[{}",]//g' | sed 's/^[[:space:]]*//')
    else 
      stats=$(echo "$RES" | jq '.data.attributes.last_analysis_results' | sed 's/[{}",]//g' | sed 's/^[[:space:]]*//' | head -n "$heading")
  fi 

  echo "$stats" | awk '{
     gsub(/^[[:space:]]+/, "", $0)
    split($0, parts, ":")
    
    if (length(parts) >= 2 && parts[2] ~ /^[[:space:]]*$/) {
        print parts[1] ":"
    } 
    else {
        if ($0 ~ /category: malicious/) {
          print "  " $1 " \033[0;31m" $2 "\033[0m" 
        } else {
        print "  " $0
        }
    }
}'
  echo -e "\nAll stats:"
  echo "$total"
  echo " "
}

function URLchecker() {
  local heading="$2"
  if [ "$heading" != "all" ]; then 
      let "heading*=6"
  fi

    ID=$(curl -s --request POST \
  --url https://www.virustotal.com/api/v3/urls \
  --header "x-apikey: $APIKEY" \
  --form "url=$1" | cut -d ' ' -f5 | tr -d '",')
    sleep 5
    RES=$(curl -s --request GET \
  --url https://www.virustotal.com/api/v3/analyses/$ID \
  --header "x-apikey: $APIKEY")

    if [ "$heading" = "all" ]; then 
      raw=$(echo "$RES" | jq '.data.attributes.results' | sed 's/[{}",]//g' | sed 's/^[[:space:]]*//') 
    else 
      raw=$(echo "$RES" | jq '.data.attributes.results' | sed 's/[{}",]//g' | sed 's/^[[:space:]]*//' | head -n "$heading")
    fi 


    echo "$raw" | awk '{
    gsub(/^[[:space:]]+/, "", $0)
    split($0, parts, ":")
    
    if (length(parts) >= 2 && parts[2] ~ /^[[:space:]]*$/) {
        print parts[1] ":"
    } 
    else {
        if ($0 ~ /category: harmless/) {
          print "  " $1 " \033[0;32m" $2 "\033[0m" 
        } else if ($0 ~ /category: malicious/) {
          print "  " $1 " \033[0;31m" $2 "\033[0m" 
        } else {
        print "  " $0
        }
    }
}'
    echo -e "\nAll stats:"
    echo "$RES" | jq -r '.data.attributes.stats | to_entries[] | "  \(.key): \(.value)"'
    echo " "
}

declare filename
crypto="sha256sum"
header="all"
declare path 
while getopts "U:H:s:c:F:h:" opt; do 
    case $opt in 
        h) header="$OPTARG" ;;
        U) URLchecker "$OPTARG" "$header";; 
        H) HashChecker "$OPTARG" "$header";;
        s) filename="$OPTARG"; exec > >(tee -a "$filename") ;;
        c) crypto="$OPTARG" ;;
        F) path="$OPTARG" ;;
        *) echo "Usage: $0 [-U URL] [-H хеш] [-s файл_лога] [-c алгоритм] [-p путь] [-h заголовок]"
    esac 
done  

if [ -n "$path" ]; then 
  hash_value=$($crypto $path | awk '{print $1}')
  HashChecker "$hash_value" "$header"
fi