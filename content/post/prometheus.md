+++
date = "2019-12-21T09:32:45-04:00"
draft = false
title = "Hello, Prometheus"
tags = ["Monitoring"]
+++

## Prometheus

Prometheus collects metrics from monitored targets by scraping 
metrics HTTP endpoints.

Prometheus provides alerting & metrics. In prometheus we deal with dimensional data
time series are identified by metric name and set of key/value pairs.

### Prometheus Installation

You can download the full distriution from
https://github.com/prometheus/prometheus/releases

After extracting you will get a prometheus executable (prometheus.exe for windows), which 
you can use to run prometheus, for example:

```./prometheus --config.file /path/to/prometheus.yaml```

### Install prometheus with this script

```
#!/bin/bash
PROMETHEUS_VERSION="2.2.1"
wget https://github.com/prometheus/prometheus/releases/download/v${PROMETHEUS_VERSION}/prometheus-${PROMETHEUS_VERSION}.linux-amd64.tar.gz
tar -xzvf prometheus-${PROMETHEUS_VERSION}.linux-amd64.tar.gz
cd prometheus-${PROMETHEUS_VERSION}.linux-amd64/
# if you just want to start prometheus as root
#./prometheus --config.file=prometheus.yml

# create user
useradd --no-create-home --shell /bin/false prometheus 

# create directories
mkdir -p /etc/prometheus
mkdir -p /var/lib/prometheus

# set ownership
chown prometheus:prometheus /etc/prometheus
chown prometheus:prometheus /var/lib/prometheus

# copy binaries
cp prometheus /usr/local/bin/
cp promtool /usr/local/bin/

chown prometheus:prometheus /usr/local/bin/prometheus
chown prometheus:prometheus /usr/local/bin/promtool

# copy config
cp -r consoles /etc/prometheus
cp -r console_libraries /etc/prometheus
cp prometheus.yml /etc/prometheus/prometheus.yml

chown -R prometheus:prometheus /etc/prometheus/consoles
chown -R prometheus:prometheus /etc/prometheus/console_libraries
```

### Installing Grafana

```
#!/bin/bash
echo 'deb https://packages.grafana.com/oss/deb stable main' >> /etc/apt/sources.list
curl https://packages.grafana.com/gpg.key | sudo apt-key add -
sudo apt-get update
sudo apt-get -y install grafana

systemctl daemon-reload
systemctl start grafana-server
systemctl enable grafana-server.service
```

### setup systemd

```
echo '[Unit]
Description=Prometheus
Wants=network-online.target
After=network-online.target

[Service]
User=prometheus
Group=prometheus
Type=simple
ExecStart=/usr/local/bin/prometheus \
    --config.file /etc/prometheus/prometheus.yml \
    --storage.tsdb.path /var/lib/prometheus/ \
    --web.console.templates=/etc/prometheus/consoles \
    --web.console.libraries=/etc/prometheus/console_libraries

[Install]
WantedBy=multi-user.target' > /etc/systemd/system/prometheus.service

systemctl daemon-reload
systemctl enable prometheus
systemctl start prometheus
```

All data is stored in time series format.
The notation of time series is often

```<metric-name>[<label name>=<label value>,...]```

### Prometheus configuration

- The default configuration looks like this:

```
# my global config
global:
  scrape_inerval: 15s # scrape interval for every 15 seconds. Default is every 1 minute.
  evaluation_interval: 15s # evaluate rules every 15 seconds. The default is every 1 minute.
  # scrape_timeout is set to the global default (10s).

# Alertmanager configuration
alerting:
  alertmanagers:
  - static_configs:
    - targets:
      # - alertmanager:9093

# Load rules once and periodically evaluate them according to the gobal 'evaluation_interval'.
rules_files:
  # - "first_rules.yml"
  # - "second_rules.yml"

# A scrape configuration containing exactly one endpoint to scrape:
# Here it's Prometheus itself.
scrape_configs:
  # The job name is added as a label `job=<job_name>` to any timeseries scraped from this config.
  - job_name: 'prometheus'

  # metrics_path defaults to '/metrics'
  # scheme defaults to 'http'

  static_configs:
  - targets: ['localhost:9090']
```

### Monitor nodes

- To montor nodes, you need to install the node-exporter 
- The node eexporter wll expose machine metrics of linux/*Nix machines
  - For example: cpu usage, memory usage
- The node exporter can be used to monitor machines and later on you can create alerts
  based on these ingested metrics.


### Installing node exporters

```
#!/bin/bash
NODE_EXPORTER_VERSION="0.16.0"
wget https://github.com/prometheus/node_exporter/releases/download/v${NODE_EXPORTER_VERSION}/node_exporter-${NODE_EXPORTER_VERSION}.linux-amd64.tar.gz
tar -xzvf node_exporter-${NODE_EXPORTER_VERSION}.linux-amd64.tar.gz
cd node_exporter-${NODE_EXPORTER_VERSION}.linux-amd64
cp node_exporter /usr/local/bin

# create user
useradd --no-create-home --shell /bin/false node_exporter

chown node_exporter:node_exporter /usr/local/bin/node_exporter

echo '[Unit]
Description=Node Exporter
Wants=network-online.target
After=network-online.target

[Service]
User=node_exporter
Group=node_exporter
Type=simple
ExecStart=/usr/local/bin/node_exporter

[Install]
WantedBy=multi-user.target' > /etc/systemd/system/node_exporter.service

# enable node_exporter in systemctl
systemctl daemon-reload
systemctl start node_exporter
systemctl enable node_exporter


echo "Setup complete.
Add the following lines to /etc/prometheus/prometheus.yml:

  - job_name: 'node_exporter'
    scrape_interval: 5s
    static_configs:
      - targets: ['localhost:9100']
"
```

After installng node exporter successfully we need to configure node-exporter
job in prometheus.yml and reload promethus to confiure the the job added.


### Types of metrics

- **Counter**:    A value that only goes up (e.g. Viists to a website)
- **Gauge**:      Single numeric value hat can go up and down (e.g. CPU load, temperature)
- **Histogram**:  Samples observations (e.g. request durations or response sizes) and
  these observations get counted into buckets. Includes (_count and _sum). Main purpose is
  calculating quantities.
- **Summary**:    Similar to a histogram a summary samples observations (e.g. request ddurations
  or response sizes). A summary also provides a total count of observations and a sum of all
  observed values, it calculates configurable quantities over a sliding time window.

  Example: You need 2 counter for calculaing latency
  1) total request(_count)
  2) total latency of the those requests (_sum)

  Take the rate() and divide = average latency

### Client libraries

In order to fetch the metrics of the applications. We need to instrument the app to expose
metrics. There are bunch of officially supported client libraries for Go, Pythn, Java etc..
and also tens of unofficial client libraries.

Golang Example

- https://github.com/prometheus/client_golang
- Officially supported language
- Easy to implement:

```
package main

import (
  "github.com/prometheus/client_golang/prometheus/promhttp"
  "net/http"
)

func main() {
  http.Handle("/metrics",promhttp.Handler())
  panic(http.ListenAndServe(":8080", nil))
}
```

- Supported metrics: Counter, Gauge, Histogram & Summary

Gauge

```
import "github.com/prometheus/client_golang/prometheus"

var jobsQueued = prometheus.NewGaugeVec(
   prometheus.GaugeOpts{
     Name: "jobs_queued",
     Help: "current number of jobs in the queue",
   },
   []string{"job_type"},
)

func init() {
  prometheus.MustRegister(jobsQueued)
}

func enqueueJob(job Job) {
    queue.Add(job)
    jobsQueued.withLabelValues(job.Type().Inc())
}

func runNextJob() {
  job := queue.Dequeue()
  jobsQueued.withLabelValues(job.Type()).Dec()

  job.Run()
}
```

Histogram

```
import "github.com/prometheus/client_golang/promethes"

var jobsDurationHistogram = prometheus.NewHistogramVec(
  prometheus.HistogramOpts{
    Name: "jobs_duration_seconds",
    Help: "Jobs duration distribution",
    Buckets: []float64{1, 2, 5, 10, 20, 60},
  },
  []string{"job_type"},
)

start := time.Now()
job.Run()
duration := time.Since(start)
jobsDurationHistogram.withLabelValues(job.Type()).Observe(duration.Seconds())
```

Summary

```
prometehus.NewSummary()
```

### Pushing Metrics - Introduction

- https://github.com/prometheus/pushgateways

   App ---> Push Gateway <------> Prometheus

- Sometimes metrics cannt be scraped.
  example: batch jobs, servers are not reachable due to NAT, firewall

- pushgateways is used as an intermediary service which allow you to push metrics.
- Pitfalls
  1. Most of the times this is a single instance so this results in a SPOF.
  2. Prometheus's automatic instance health monitoring is not possible.
  3. The pushgateway never forgets the metrics unless they are deleted.

Go Example:
```
package main

import (
  "flag"
  "log"
  "net/http"
  "github.com/prometheus/client_golang/prometheus/promhttp"
  "github.com/prometheus/client_golang/prometehus/push"
)

gatewayUrl:="http://localhost:9091/"

throughputGUage := prometheus.NewGuage(prometheus.GaugeOpts{
  Name: "throughput",
  Help: "Throughput in Mbps",
})
throughputGuage.Set(800)

if err := push.Collectors(
  "throughput_job",push.HostnameGroupingKey(),gatewayUrl, throughputGuage);
  err != ni {
    fmt.Println("Could not push completion time to pushgateway:",err)
  }

```

### Querying Metrics

- Prometehus provides a functional expression language called "PromQL"
- PromQL is read only.

1. Instant vector - A set of time series containing a single sample for each time series,
all sharing the same timestamp.
Example: node_cpu_seconds_total

2. Range vector - A set of time series containing a range of data points over time for 
each time series.

3. Scalar - A simple numeric floating point value.
Example: -3.14

4. String - A simple string value, currently unsued
Example: foobar

PromQl has different operators for Querying

- Arithmetic binary operators
- Comparison binary operators
- Logical/set binary operators
- Aggregation operators

Example query
http_requests_total{code!~"4.."} #This gives the requests which are not 400

A single Prometheus server is able to ingest up to one million
samples per second as several million time series.

prometheus.yml file will have all targets to scrape and alert manager
configurations and also pushgateways endpoints.

As prometheus deals wih time series database. To handle such data and
to suport semantics specific to that data. We have PromQL which is used
to query prometheus database. It has capabilities like arithmetic, 
logical and aggregation operations.


### ALERT MANAGER:

Alert manager runs has a service and we define alerting rules in 
prometheus. when rule criteria is fulfilled we send alerting request to
alerting manager. Which then routes to mail or slack.

- Alertmanager handles the alerts fired by the prometheus server
- Handles deduplication, grouping and routing of alerts
- Routes alerts to receivers (Pagerduty, Opsgenie, email, SLack,..)

This alerting rules and alert manager configuration needs to configured
in prometheus.yml

The best practice is to have alert.rules file and maintain all the rules in
this and this file needs to included in prometheus config.

#### ALERT FORMAT
```
ALERT <alert name>
IF <expression>
[ FOR <duration> ]
[ LABELS <label set> ]
[ ANNOTATIONS <label set> ]
```

**ALERT EXAMPLE** 

```
groups:
  - name: example
    rules:
    - alert: cpuUsage
      expr: 100- (avg by (instance) (irate(node_cpu_seconds_total{job='node_exporter',mode="idle"}[5ml]))*100) > 95
      for: 1m
      labels:
        severity: critical
      anntations:
         summary: Machine under heavy load
```