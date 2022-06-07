curl -XPUT --insecure --user admin:'d201ed10-df15-11ec-8f7a-00155d3b53bf' https://localhost:9200/$1-subdomain-temp -H "Content-Type: application/json" -d @- <<EOF
{
        "mappings":{
                "properties":{
                "@timestamp":{"type":"date"},
                "server.address": {"type":"keyword"},
                "server.domain": {"type":"keyword"},
                "server.nameserver": {"type":"keyword"},
                "server.ip": {"type":"ip"},
                "server.ipblock": {"type":"keyword"},
                "vulnerability.scanner.vendor": {"type":"keyword"}
                }
        }
}
EOF
