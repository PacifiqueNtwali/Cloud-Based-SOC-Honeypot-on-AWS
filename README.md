# AWS Honeypot & Threat Monitoring Lab

> **Live brute-force attack monitoring using a Windows honeypot, CloudWatch, Lambda, and OpenSearch Dashboards**


![Attack Map](https://i.imgur.com/YvLB2oM.png)

---

## Scenario

A small company suspects they are being targeted by automated brute-force attacks on their remote desktop infrastructure. As the security analyst, I was tasked with deploying a honeypot environment to observe, log, and visualize real-world attack patterns — without risking production systems.

This project simulates that mission using a fully exposed Windows VM on AWS, a real-time log pipeline, and a geolocation attack map built from live threat data.

---

## Architecture


<img width="995" height="680" alt="image" src="https://github.com/user-attachments/assets/be6cfee2-351c-41fe-8f3e-683405eee47d" />



## Tools & Services Used

| Tool | Purpose |
|---|---|
| AWS EC2 (Windows Server) | Honeypot virtual machine |
| AWS CloudWatch Agent | Log collection and forwarding |
| AWS Lambda (Python 3.12) | Log enrichment and pipeline |
| AWS OpenSearch Service | SIEM and visualization |
| ip-api.com | Free IP geolocation API |
| OpenSearch Dashboards | Attack map visualization |

---

## Setup

### Phase 1 — Deploy the Honeypot VM

1. Launch an EC2 instance **(Windows Server 2022, t3.medium)**
2. Enable Auto-assign public IP
3. Create a Security Group with these inbound rules:
   - RDP / Port 3389 / Source: `Anywhere`
   - All Traffic / All Ports / Source: `Anywhere`
4. Create and download a key pair `.pem` file to decrypt the login password
5. RDP into the instance using the decrypted Administrator password
6. Inside the VM open `wf.msc` and set Firewall state to **Off** on all three profiles (Domain, Private, Public)
7. Create an IAM Role with `CloudWatchAgentServerPolicy` and attach it to the EC2 instance

> **EC2 instance**
>
> ![EC2 Instance](https://i.imgur.com/noArFZQ.png)

> **Security Group inbound rules showing all traffic open**
>
> ![Security Group](https://i.imgur.com/UDJXTRD.png)

> **Windows Firewall disabled on all profiles**
>
> ![Firewall Off](https://i.imgur.com/k2QQ4r9.png)
> ![Firewall Off](https://i.imgur.com/KPnDbDx.png)
> ![Firewall Off](https://i.imgur.com/hAcUACE.png)

**Confirm your instance is reachable using your local machine**
>
> ![ping the instance](https://i.imgur.com/6iAOucH.png)

### Phase 2 — Configure Log Collection

RDP into the VM and open **PowerShell as Administrator**.

**Install the CloudWatch Agent:**

```powershell
Invoke-WebRequest -Uri https://s3.amazonaws.com/amazoncloudwatch-agent/windows/amd64/latest/amazon-cloudwatch-agent.msi -OutFile C:\cw-agent.msi
Start-Process msiexec.exe -ArgumentList '/i C:\cw-agent.msi /quiet' -Wait
Write-Host "Agent installed."
```

**Create the config file:**

```powershell
$config = @'
{"logs":{"logs_collected":{"windows_events":{"collect_list":[{"event_name":"Security","event_levels":["ERROR","WARNING","INFORMATION"],"log_group_name":"honeypot-security-logs","log_stream_name":"{instance_id}"}]}}}}
'@
$config | Out-File -FilePath C:\cloudwatch-config.json -Encoding ASCII
Write-Host "Config created."
```

**Start the agent:**

```powershell
& "C:\Program Files\Amazon\AmazonCloudWatchAgent\amazon-cloudwatch-agent-ctl.ps1" -a fetch-config -m ec2 -s -c file:C:\cloudwatch-config.json
```

**Verify it is running:**

```powershell
& "C:\Program Files\Amazon\AmazonCloudWatchAgent\amazon-cloudwatch-agent-ctl.ps1" -a status
```

Expected output: `"status": "running"`

> **CloudWatch Log Group**
>
> ![CloudWatch Log Group](https://i.imgur.com/40ld1Le.png)

> **4625 failed login events in the log stream**
>
> ![4625 Events](https://i.imgur.com/QuUT23g.png)

---

### Phase 3 — Deploy the Enrichment Lambda

**Create the Lambda function:**
- Name: `honeypot-enricher`
- Runtime: Python 3.12
- IAM Role: attach a role with `CloudWatchLogsFullAccess` and `AmazonOpenSearchServiceFullAccess`

**Paste this as the function code:**

```python
import json
import gzip
import base64
import urllib.request
import re
from datetime import datetime

# ============================================================
# UPDATE THESE VALUES
OPENSEARCH_ENDPOINT = "https://your-opensearch-endpoint.us-east-1.on.aws"
OS_PASSWORD         = "your-opensearch-password"
MY_IP               = "your-home-public-ip"  # from whatismyip.com
# ============================================================

OS_USERNAME = "admin"


def get_geo(ip):
    try:
        url = f"http://ip-api.com/json/{ip}?fields=country,regionName,city,lat,lon,isp"
        req = urllib.request.urlopen(url, timeout=3)
        return json.loads(req.read())
    except:
        return {}


def send_to_opensearch(doc):
    try:
        url = f"{OPENSEARCH_ENDPOINT}/attacks/_doc"
        data = json.dumps(doc).encode()
        req = urllib.request.Request(url, data=data, method='POST')
        req.add_header('Content-Type', 'application/json')
        credentials = base64.b64encode(f"{OS_USERNAME}:{OS_PASSWORD}".encode()).decode()
        req.add_header('Authorization', f'Basic {credentials}')
        urllib.request.urlopen(req, timeout=5)
        print(f"Sent to OpenSearch: {doc['ip']} from {doc['country']} / {doc['city']}")
    except Exception as e:
        print(f"OpenSearch error: {e}")


def process_ip(ip):
    if ip.startswith(('10.', '1.', '1.1.', '127.')):
        return
    if ip == MY_IP:
        return
    geo = get_geo(ip)
    if not geo.get('lat'):
        print(f"Could not geolocate: {ip}")
        return
    doc = {
        "timestamp": datetime.utcnow().isoformat(),
        "ip":        ip,
        "country":   geo.get('country', 'Unknown'),
        "city":      geo.get('city', 'Unknown'),
        "region":    geo.get('regionName', 'Unknown'),
        "isp":       geo.get('isp', 'Unknown'),
        "location": {
            "lat": geo.get('lat'),
            "lon": geo.get('lon')
        }
    }
    print(f"Attack from {doc['country']} / {doc['city']} - IP: {ip}")
    send_to_opensearch(doc)


def lambda_handler(event, context):
    if 'test_ip' in event:
        process_ip(event['test_ip'])
        return {'statusCode': 200, 'message': 'Test complete'}

    compressed = base64.b64decode(event['awslogs']['data'])
    log_data   = json.loads(gzip.decompress(compressed))

    print(f"Processing {len(log_data['logEvents'])} log events")

    for log_event in log_data['logEvents']:
        message = log_event['message']
        if '4625' not in message:
            continue
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', message)
        for ip in ips:
            process_ip(ip)

    return {'statusCode': 200}
```

**Test the function** with this test event:

```json
{
  "test_ip": "185.220.101.50"
}
```

Expected output:
```
Attack from Germany / Frankfurt - IP: 185.220.101.50
Sent to OpenSearch: 185.220.101.50 from Germany / Frankfurt
```

**Connect Lambda to CloudWatch logs:**
- CloudWatch → Log Groups → `honeypot-security-logs` → Subscription filters
- Create Lambda subscription filter → select `honeypot-enricher`
- Filter name: `attacks` — Filter pattern: *(leave blank)*
- Click **Start streaming**

> **Lambda Function**
>
> ![Lambda Function](https://i.imgur.com/5Sf2WkC.png)

> **Lambda roles**
>
> ![Lambda roles](https://i.imgur.com/JhKvu8l.png)

> **Subscription filter connected to Lambda**
>
> ![Subscription Filter](https://i.imgur.com/ZF3GUcu.png)

---

### Phase 4 — Configure OpenSearch

**Create the domain (Standard create):**
- Network: **Public access**
- Deployment: **Development and testing**
- Instance type: `r8g.medium.search`
- Data nodes: `1` — EBS storage: `10` GiB
- Dedicated master node: **disabled**
- Fine-grained access control: **enabled** — master user `admin`
- Access policy: **Only use fine-grained access control**

**Create index with geo_point mapping in Dev Tools:**

```json
PUT /attacks
{
  "mappings": {
    "properties": {
      "timestamp": { "type": "date" },
      "ip":        { "type": "keyword" },
      "country":   { "type": "keyword" },
      "city":      { "type": "keyword" },
      "region":    { "type": "keyword" },
      "isp":       { "type": "keyword" },
      "location":  { "type": "geo_point" }
    }
  }
}
```

** On opensearch Create index pattern:**
- Dashboards Management → Index patterns → Create index pattern
- Name: `attacks*` — Time field: `timestamp`
> Dashboards Management
> ![Index patterns](https://i.imgur.com/7siEXmy.png)
> ![Time field](https://i.imgur.com/5zOOaN1.png)

**Build the attack map:**
- Visualize → Create visualization → Maps
- Add layer → Clusters and grids → Index: `attacks*`
- Geospatial field: `location` → Save

**OpenSearch attack map**
>
> ![Visualize](https://i.imgur.com/Jlau74a.png)
>
> ![Select maps](https://i.imgur.com/b7kQUks.png)

---

## Results

After 24 hours the honeypot logged **7,116 brute force attempts** from 6 countries:

| Country | Attack Count |
|---|---|
| 🇧🇷 Brazil | 3,953 |
| 🇲🇽 Mexico | 2,577 |
| 🇹🇼 Taiwan | 561 |
| 🇨🇳 China | 20 |
| 🇩🇪 Germany | 3 |
| 🇺🇦 Ukraine | 2 |

All attempts targeted the `Administrator` account via RDP port 3389, consistent with automated credential stuffing botnets scanning the public internet for exposed Windows machines.

> **Attack map showing global attacker origins**
>
> ![Attack Map](https://i.imgur.com/Sk2rJxZ.png)

---

## Key Findings

- **An exposed RDP port is found within hours.** The first external brute force attempt arrived within 2 hours of deployment, confirming that internet-facing RDP is actively targeted around the clock.

- **Brazil and Mexico accounted for 92% of all attempts.** These sources are commonly associated with botnet infrastructure. The geographic origin reflects where the bots are hosted, not necessarily where the attacker operates from.

- **Every single attack targeted the Administrator account.** This confirms fully automated tooling. Renaming or disabling the default Administrator account would block 100% of these attempts.

- **ISP-level clustering indicates coordinated botnet activity.** Multiple attacks arriving within seconds from the same ISP and city indicate botnet nodes rather than individual attackers.

---

## Troubleshooting

### CloudWatch log group not appearing
- Verify `CloudWatchAgentRole` is attached to the EC2 instance under the Security tab
- Confirm agent status inside the VM:
```powershell
& "C:\Program Files\Amazon\AmazonCloudWatchAgent\amazon-cloudwatch-agent-ctl.ps1" -a status
```
- Verify config file: `type C:\cloudwatch-config.json`

### Lambda not triggering from real logs
- Subscription filter must be on `honeypot-security-logs` not on `/aws/lambda/honeypot-enricher`
- Attaching it to the Lambda's own log group causes an error — no data will flow
- Always test manually first with `{"test_ip": "185.220.101.50"}`

### Geospatial field missing in Maps layer
- `location` must be mapped as `geo_point` before any data is inserted
- Fix by deleting and recreating the index with the correct mapping, then resending data

### Map empty despite data in OpenSearch
- Change time range to **Last 7 days** — default is 15 minutes
- Confirm map layer index is `attacks*` not the sample data index
- Refresh index pattern in Dashboards Management

### All map entries show my own location
- Your home IP is public and passes the private IP filter
- Add your IP from [whatismyip.com](https://whatismyip.com) to the Lambda filter:
```python
if ip == "YOUR.PUBLIC.IP":
    continue
```
- Clean existing self-entries:
```json
POST /attacks/_delete_by_query
{
  "query": {
    "term": { "ip": "YOUR.PUBLIC.IP" }
  }
}
```

### Duplicate entries on the map
- Two subscription filters on the same log group sends every event twice
- Keep only one filter on `honeypot-security-logs`

### OpenSearch domain failed — IPv6 validation error
- Caused by Dual-stack mode on a subnet without IPv6
- Use **Standard create** and select **Public access** under Network

### Only a few dots on the map despite thousands of records
- Attacks from the same location stack as one dot — this is correct behavior
- Use Clusters and grids layer to show attack volume
- Check country breakdown in Dev Tools:
```json
GET /attacks/_search
{
  "size": 0,
  "aggs": {
    "countries": {
      "terms": { "field": "country", "size": 50 }
    }
  }
}
```

---

## Cleanup

Run in **AWS CloudShell**:

```bash
REGION="us-east-1"

aws ec2 terminate-instances --region $REGION \
  --instance-ids $(aws ec2 describe-instances --region $REGION \
  --filters "Name=instance-state-name,Values=running,stopped" \
  --query "Reservations[].Instances[].InstanceId" --output text)

aws opensearch delete-domain --region $REGION --domain-name soc-lab

aws lambda delete-function --region $REGION --function-name honeypot-enricher

aws logs delete-log-group --region $REGION --log-group-name "honeypot-security-logs"
aws logs delete-log-group --region $REGION --log-group-name "/aws/lambda/honeypot-enricher"

for id in $(aws ec2 describe-addresses --region $REGION \
  --query "Addresses[?AssociationId==null].AllocationId" --output text); do
  aws ec2 release-address --region $REGION --allocation-id $id
done

echo "Done. All lab resources removed."
```

Also check EC2 → Elastic IPs and EC2 → Volumes for any remaining resources.

---

## Cost Estimate

| Service | Type | Approx Cost |
|---|---|---|
| EC2 | t3.medium Windows | ~$0.05/hr |
| OpenSearch | r8g.medium.search | ~$0.15/hr |
| Lambda | First 1M requests | Free |
| CloudWatch Logs | Low volume | ~$0.01/hr |

> **Note:** Delete the OpenSearch domain immediately after the lab. A 24-hour run costs approximately $5–6 for OpenSearch alone.

---

## References

- [AWS CloudWatch Agent Documentation](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Install-CloudWatch-Agent.html)
- [AWS OpenSearch Service Documentation](https://docs.aws.amazon.com/opensearch-service/latest/developerguide)
- [ip-api.com Geolocation API](https://ip-api.com)
- Inspired by [Josh Madakor's Azure SOC Honeypot Lab](https://www.youtube.com/watch?v=RoZeVbbZ0o0)
