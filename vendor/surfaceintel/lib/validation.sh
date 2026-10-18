# shellcheck shell=bash
# shellcheck disable=SC2034 # Shared module globals and positional schema fields form the library interface.
host_valid() {
    local h=$1 label
    [[ ! $h =~ ^([0-9]+|0x[0-9a-f]+)(\.([0-9]+|0x[0-9a-f]+))*$ ]] || return 1
    [[ ${#h} -le 253 && $h == "${h,,}" && $h != *..* && $h == *.* && $h != .* && $h != *. && $h != *[^a-z0-9.-]* ]] || return 1
    local -a labels=(); IFS=. read -r -a labels <<< "$h"
    for label in "${labels[@]}"; do [[ ${#label} -le 63 && $label =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || return 1; done
}
ip_expand() {
    local ip=$1 item left right missing i
    IP_BITS=''; IP_FAMILY=''
    local -a parts=() lhs=() rhs=() out=()
    if [[ $ip == *.* && $ip != *:* ]]; then
        [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
        IFS=. read -r -a parts <<< "$ip"
        [[ ${#parts[@]} == 4 ]] || return 1
        for item in "${parts[@]}"; do
            [[ $item =~ ^(0|[1-9][0-9]{0,2})$ ]] && ((10#$item<=255)) || return 1
            printf -v item '%02x' "$((10#$item))"; IP_BITS+=$item
        done
        IP_FAMILY=4; return 0
    fi
    [[ $ip == *:* && $ip != *[^a-fA-F0-9:]* && $ip != *:::* ]] || return 1
    [[ $ip != :* || $ip == ::* ]] || return 1
    [[ $ip != *: || $ip == *:: ]] || return 1
    if [[ $ip == *::* ]]; then
        left=${ip%%::*}; right=${ip#*::}; [[ $right != *::* ]] || return 1
        [[ -z $left ]] || IFS=: read -r -a lhs <<< "$left"
        [[ -z $right ]] || IFS=: read -r -a rhs <<< "$right"
        missing=$((8-${#lhs[@]}-${#rhs[@]})); ((missing>=1)) || return 1
        out=("${lhs[@]}"); for ((i=0;i<missing;i++)); do out+=(0); done; out+=("${rhs[@]}")
    else
        [[ $ip != :* && $ip != *: ]] || return 1
        IFS=: read -r -a out <<< "$ip"; [[ ${#out[@]} == 8 ]] || return 1
    fi
    for item in "${out[@]}"; do
        [[ $item =~ ^[a-fA-F0-9]{1,4}$ ]] || return 1
        printf -v item '%04x' "$((16#$item))"; IP_BITS+=$item
    done
    # Mapped/compatible IPv4 forms are intentionally rejected, not reinterpreted.
    [[ $IP_BITS != 00000000000000000000ffff* ]] || return 1
    IP_FAMILY=6
}
cidr_valid() {
    local ip=${1%/*} prefix=${1##*/} family
    [[ $1 == */* ]] && ip_expand "$ip" || return 1
    family=$IP_FAMILY
    [[ $prefix =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
    (( prefix <= (family==4?32:128) )) || return 1
    local full=$((prefix/4)) rem=$((prefix%4)) nibble mask
    if ((rem)); then
        nibble=${IP_BITS:full:1}; mask=$(((1 << (4-rem))-1))
        (( (16#$nibble & mask)==0 )) || return 1
        ((full+=1))
    fi
    [[ ${IP_BITS:full} != *[!0]* ]]
}
in_cidr() {
    local address=$1 cidr=$2 bits family network prefix count rem a b mask
    ip_expand "$address" || return 1; bits=$IP_BITS; family=$IP_FAMILY
    cidr_valid "$cidr" || return 1; network=$IP_BITS; [[ $family == "$IP_FAMILY" ]] || return 1
    prefix=${cidr##*/}; count=$((prefix/4)); rem=$((prefix%4))
    [[ ${bits:0:count} == "${network:0:count}" ]] || return 1
    if ((rem)); then
        a=${bits:count:1}; b=${network:count:1}; mask=$((15 << (4-rem) & 15))
        (( (16#$a & mask) == (16#$b & mask) )) || return 1
    fi
}
ip_allowed() {
    local address=$1 literal=${2:-false} cidr explicit=false private=false
    ip_expand "$address" || return 1
    if [[ $IP_FAMILY == 6 ]] && ! in_cidr "$address" 2000::/3; then private=true; fi
    for cidr in "${EXCLUDE_CIDRS[@]}"; do in_cidr "$address" "$cidr" && return 1; done
    # Metadata destinations never permitted, even by broad customer CIDRs.
    for cidr in 0.0.0.0/8 224.0.0.0/4 240.0.0.0/4 ff00::/8 64:ff9b::/96 64:ff9b:1::/48 2002::/16 2001::/32 169.254.169.254/32 169.254.170.0/24 169.254.0.23/32 168.63.129.16/32 100.100.100.200/32 fd00:ec2::/32; do in_cidr "$address" "$cidr" && return 1; done
    for cidr in "${CIDRS[@]}"; do in_cidr "$address" "$cidr" && explicit=true; done
    for cidr in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.88.99.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4 ::/96 ::1/128 fc00::/7 fe80::/10 ff00::/8 2001:db8::/32 2001::/23 2001::/32 2002::/16 64:ff9b::/96; do
        in_cidr "$address" "$cidr" && private=true
    done
    if [[ $private == true ]]; then [[ $explicit == true && $ALLOW_NONPUBLIC == true ]]; return; fi
    if [[ $literal == true ]]; then [[ $explicit == true ]]; else [[ $explicit == true || $ALLOW_PUBLIC_DNS == true ]]; fi
}
host_scope() {
    local host=$1 item
    if ip_expand "$host"; then ip_allowed "$host" true; return; fi
    host_valid "$host" || return 1
    for item in "${EXCLUDES[@]}"; do [[ $host == "$item" ]] && return 1; done
    for item in "${EXCLUDE_TREES[@]}"; do [[ $host == "$item" || $host == *."$item" ]] && return 1; done
    for item in "${HOSTS[@]}"; do [[ $host == "$item" ]] && return 0; done
    for item in "${ROOTS[@]}"; do [[ $host == "$item" || $host == *."$item" ]] && return 0; done
    return 1
}
parse_url() {
    local url=$1 authority portpart
    URL_SCHEME=''; URL_HOST=''; URL_PORT=''; URL_PATH=''; URL_ORIGIN=''
    [[ ${#url} -le 2048 && $url =~ ^(https?)://([^/]+)(/.*)?$ ]] || return 1
    URL_SCHEME=${BASH_REMATCH[1]}; authority=${BASH_REMATCH[2]}; URL_PATH=${BASH_REMATCH[3]:-/}
    [[ $authority != *[@?#%\\]* && $URL_PATH =~ ^/[a-zA-Z0-9._~/-]*$ && $URL_PATH != *'//'* ]] || return 1
    [[ $URL_PATH != */../* && $URL_PATH != */./* && $URL_PATH != */.. && $URL_PATH != */. ]] || return 1
    URL_PORT=80; [[ $URL_SCHEME != https ]] || URL_PORT=443
    if [[ $authority =~ ^\[([a-fA-F0-9:]+)\](:([0-9]+))?$ ]]; then
        URL_HOST=${BASH_REMATCH[1]}; portpart=${BASH_REMATCH[3]-}; ip_expand "$URL_HOST" || return 1
    else
        [[ $authority != *:*:* ]] || return 1
        URL_HOST=${authority%%:*}; portpart=''; [[ $authority != *:* ]] || portpart=${authority#*:}
        host_valid "$URL_HOST" || ip_expand "$URL_HOST" || return 1
    fi
    if [[ -n $portpart ]]; then number "$portpart" 1 65535 || return 1; URL_PORT=$((10#$portpart)); fi
    [[ $authority != *: || $authority == *']' ]] || return 1
    URL_ORIGIN="$URL_SCHEME://$authority"
}
url_scope() { parse_url "$1" && host_scope "$URL_HOST"; }
role_scope() {
    local host=$1 role=$2 url=${3:-} entry provider kind resource
    case $role in
        asset) host_scope "$host";;
        discovery) [[ $CT_ENABLED == true && $host == crt.sh ]];;
        alert) contains "$host" "${ALERT_HOSTS[@]}";;
        cloud)
            for entry in "${CLOUDS[@]}"; do IFS='|' read -r provider kind resource <<< "$entry"; [[ $resource == "$url" ]] && return 0; done
            return 1;;
        *) return 1;;
    esac
}
