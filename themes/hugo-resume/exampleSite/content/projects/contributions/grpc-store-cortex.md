
{
  "title": "gRPC store for Cortex",
  "date": "2020-05-02T09:32:45-04:00",
  "image": "/img/cortex.png",
  "description": "A distributed, multi-tenant and long term storage system for metrics.Developed a feature to support the get your own database use-case, allowing users to bring any storage solution as the back-end store for Cortex using gRPC client/server plugin mechanism",
  "link": "https://cortexmetrics.io/",
  "tags": ["Monitoring", "Distributed Systems"],
  "fact": "",
  "featured": true
}

Cortex, being a Distributed, Multi-Tenant Prometheus off-loads the storage to battle-tested databases like Cassandra, BigTable, etc. All the time-series data is converted into chunks. The chunk store essentially contains two parts i.e Index Store, where index to the chunks are stored & KV Store for the chunks itself for direct access. For Index store, There are multiple types of schemas supported by passing the relevant config through `chunk.SchemaConfig`. Right now, there are only some storage backends supported but as we are seeing more and more users adopting Cortex in their companies,iIt’s important that there is a way for them to extend Cortex to make it use their existing back-ends for storage.


* Provide a way for users to write out-of-tree Chunk Store Implementations.
* Use standard protocols like gRPC for communication.
* Provide a new client which talks to the new storage systems.
* Provide easily configurable storage plugins.
