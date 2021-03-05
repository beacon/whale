# 部署

报错: 

```
max virtual memory areas vm.max_map_count [65530] is too low, increase to at least [262144]
```

```
sudo sysctl -w vm.max_map_count=262144
```

# 运行扫描

```bash
SONARQUBE_URL=sonar:9000
SONAR_TOKEN=da360061f7144ce19ae7f8059916728f64be0dfa
SONAR_PROJECT_KEY=myproject
docker run --rm  --net deploy_default \
    -e SONAR_HOST_URL="http://${SONARQUBE_URL}" \
    -e SONAR_LOGIN="${SONAR_TOKEN}" \
    -v "$PWD:/usr/src"  \
    sonarsource/sonar-scanner-cli \
    -Dsonar.projectKey="${SONAR_PROJECT}"
```

Get issues from sonar website:
```bash
curl 'http://localhost:19000/api/issues/search?componentKeys=--&s=FILE_LINE&resolved=false&ps=100&facets=owaspTop10%2CsansTop25%2Cseverities%2CsonarsourceSecurity%2Ctypes&additionalFields=_all&timeZone=Asia%2FShanghai' \
  -H 'Connection: keep-alive' \
  -H 'sec-ch-ua: "Chromium";v="88", "Google Chrome";v="88", ";Not A Brand";v="99"' \
  -H 'Accept: application/json' \
  -H 'X-XSRF-TOKEN: f4285si3sbbg920d3b4mo955ba' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.182 Safari/537.36' \
  -H 'Sec-Fetch-Site: same-origin' \
  -H 'Sec-Fetch-Mode: cors' \
  -H 'Sec-Fetch-Dest: empty' \
  -H 'Referer: http://localhost:19000/project/issues?id=--&resolved=false' \
  -H 'Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7' \
  -H $'Cookie: pga4_session=bf743b37-6f25-4912-a426-48739398e4a6\u00216eq8ds1XdxT5sb7+ws3Mws9A7fg=; PGADMIN_LANGUAGE=en; XSRF-TOKEN=f4285si3sbbg920d3b4mo955ba; JWT-SESSION=eyJhbGciOiJIUzI1NiJ9.eyJsYXN0UmVmcmVzaFRpbWUiOjE2MTQ5Mjk4MTc3OTEsInhzcmZUb2tlbiI6ImY0Mjg1c2kzc2JiZzkyMGQzYjRtbzk1NWJhIiwianRpIjoiQVhnQkVZR2ZUQlR1Q2NCR3c4dmgiLCJzdWIiOiJBWGdBX2NKWENtVEtXZFZ0WmYwVSIsImlhdCI6MTYxNDkyNTYyNywiZXhwIjoxNjE1MTg5MDE3fQ.5BADBxhRMeTdY2cwrTRx255QDuY85-1faWSB71PXoF0' \
  --compressed
  ```