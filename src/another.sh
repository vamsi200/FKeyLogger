id=$(cat /proc/$(pgrep -f test.py)/maps | grep libpython | head -n 1 | cut -d'-' -f 1)
s=$(nm -D $(ldd $(which python) | grep libpython | awk '{print $3}') | grep PyImport_GetModuleDict | awk '{print $1}')

printf "0x%x\n" $((0x$id + 0x$s))
