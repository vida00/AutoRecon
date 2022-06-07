echo "[+] Performing /etc/sysctl.conf"

# To initialize Open Distro
sudo sysctl -w vm.max_map_count=262144

# Swap will only be activated when the CPU reaches 90%
sudo sysctl -w vm.swappiness=10

# Controls how often the kernel fetches cache
sudo sysctl -w vm.vsf_cache_pressure=50

echo "[+] Starting docker"
docker-compose up -d

sleep 30

echo "[+] Performing max node in Open Distro"
# Increase per node to 5000
curl -XPUT --insecure -u 'admin:d201ed10-df15-11ec-8f7a-00155d3b53bf' https://localhost:9200/_cluster/settings -H 'Content-Type: application/json' -d @- <<EOF
{
	"persistent": {
		"cluster.max_shards_per_node": "5000"
	}
}
EOF
return=$?

if [ $return -eq 0 ];then
	echo
	echo "[+] Docker initialized with success"
else
	echo
	echo "[!] Docker initliazed fail"
fi
