{
  "title": "Auditing in Kubernetes",
  "date": "2020-08-21T01:32:45-04:00",
  "image": "",
  "description": "",
  "tags": ["Kubernetes"],
  "fact": "",
  "featured":true
}

<br>

As Kubernetes clusters runs different resources at desired scale. We need to have full control over the cluster with all lifecycle of events and audits which helps us to trace out the source. Also, it would be great to get notified when something abnormal happens in the cluster.

Now let's look at the details we need from api-server when an event occurs.

1. **When to log?**
2. **What to log?**


### Stages in lifecyle of request in api-server:

**RequestReceived**: This is when api-server received the request but request is not processed yet by the api-server.

**ResponseStarted**: The response headers are sent out but the response body isn't sent out. This stage only occurs for long running requests like watch.

**ResponseComplete**: The response is sent out and the request is completed.

**Panic**: When ever a panic occurs while processing the request.

Request flow in the api-server:

![](https://i.imgur.com/Do0oI1D.png)
 
 
### Levels in logging the audits:
 
 1. **None**: don't log the requests.
 2. **Metadata**: Only metadata. (i.e. requesting user, timestamp, resource, verb, etc.)
 3. **Request**: metadata and request body.
 4. **RequestResponse**: metadata, request body, response body.


The general rule for auditing:

1. Log at atleast Metadata level for all resources.
2. Log at RequestResponse level for critical resources. As this helps us to know the processed event at the response level for critical resources.

**The audits rules needs to be configured using ```--audit-policy-file```
on api-server startup.**

Below is the audit policy file with configuration as log metdata when request is received on secrets resources.


```
apiVersion: audit.k8s.io/v1
kind: Policy
# Don't generate audit events for all requests in RequestReceived stage.
omitStages:
  - "RequestReceived"
rules:
  # Log pod changes at RequestResponse level
  - level: RequestResponse
    resources:
    - group: ""
      # Resource "pods" doesn't match requests to any subresource of pods,
      # which is consistent with the RBAC policy.
      resources: ["pods"]
```

To audit all requests at metadata level the policy will be:

```
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: metadata
```

The rules are evaluated in top-down order

```
rules:
  - level: RequestResponse
    resources:
    - group: ""
    resources: ["pods"]
  - level: Metadata
    resources:
    - group: ""
    resources: ["pods/log", "pods/status"]
```

The audits can be captured in two ways:

1. **Log**: Writes the audits to disk. The log file path is provided using ```--audit-log-path```
2. **Webhook**: Send the audits to external API. The details for external endpoint needs to be configured using ```--audit-webhook-config-file```

You can capture the audits in different ways for webhook use ```audit-webhook-mode``` and for local filesystem logging use ```audit-log-mode```.

By default, batching is enabled in webhook and disabled in log. Similarly, by default throttling is enabled in webhook and disabled in log.


**Batch**: Buffers events & processes in batches.

**Blocking**: Blocks API server responses to process individual events.

**Blocking-strict**: Failures at RequestReceived stage leads to failure of whole call.

### Enabling Dynamic Audit Configuration


As api-server does all this auditing the configuration needs to be set while starting up the api-server. Updating the audit policy needs restart of api-server. which isn't recommended or an easy thing to do. To avoid this we can use **Dynamic Audit configuration** this lets us to update the audit policy just as updating k8s resource using **kubectl apply**.

As this feature is still alpha you need to enable the feature gates of api-server to leverage this feature by appending this flags to the on api-server startup.

```
--audit-dynamic-configuration
--feature-gates=DynamicAuditing=true
--runtime-config=auditregistration.k8s.io/v1alpha1=true
```


**Log backend**:

Configuring the api-server to write audits in a file. 

1. Specify the log file path that log backend uses to write audit events. Not specifying this flag disables log backend. Confuguring it as ```-``` means standard out ```--audit-log-path```
2. Define the maximum number of days to retain old audit logs ```--audit-log-maxage```
3. Define the maximum number of audit log files to retain ```--audit-log-maxbackup```
4.  Define the maximum size in megabytes of the audit log file before it gets rotated ```--audit-log-maxsize``` 

**Dynamic audit configuration:**

```
apiVersion: auditregistration.k8s.io/v1alpha1
kind: AuditSink
metadata:
  name: mysink
spec:
  policy:
    level: Metadata
    stages:
    - ResponseComplete
  webhook:
    throttle:
      qps: 10
      burst: 15
    clientConfig:
      url: "https://xyz.com"
```

To configure auditing we need cluster admin privileges. 

Also, using too many sinks will increase in cpu and memory usage of api-server. 


**Auditing in Kubernetes can be integrated with:**

1. Audit log file + fluentd.
2. Audit webhook file + logstash.
3. Audit webhook file + falco.


Cheers!



