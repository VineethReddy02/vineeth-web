{
  "title": "Scaling Cortex & Loki with ease",
  "date": "2020-06-28T09:32:45-04:00",
  "image": "",
  "description": "",
  "tags": ["Monitoring"],
  "fact": "",
  "featured":true
}

<br>

### Cortex provides horizontally scalable, highly available, multi-tenant, long term storage for Prometheus.

### Loki is a horizontally-scalable, highly-available, multi-tenant log aggregation system inspired by Prometheus.

Cortex & Loki are designed in same lines but they differ in the data that flows through this systems i.e metrics vs logs

Recently, I have been working on implementing a gRPC based storage system for cortex. which offers plugin your own database add-on feature for storing the metrics. All you need is to implement a gRPC based server that can read/write metrics to your desired database. The specification to support this feature is already in cortex upstream. Either use an existing gRPC based cortex store I.e. MYSQL or MONGO store else implement your own gRPC based cortex store for deisred database and help cortex in supporting multiple backend stores out of the cortex tree. 

As a part of my work, I implemented the gRPC based MYSQL store & MONGO store to store metrics in MYSQL & MONGO database. This let's you store both indexes and chunks.

For a usecase like you need to achieve Multitenancy, Global view, Long term storage & not interested in spending money for managed databases like S3, DynamoDB, Bigtable. You can definitely consider MYSQL or MONGO database as backend store for metrics. This let's you ease in managing backend storage of cortex. If you already have an experience with MYSQL or MONGO.

You can also use gRPC based storage system for Loki but for now you can only store indexes. This really adds value as indexes in loki are smaller compared to indexes in cortex. Using a backend store like Bigtable & DynamoDB might be an overkill for indexes instead you can definitely consider using the MYSQL or MONGO to store indexes. 

Adding the below configuration to schema & storage in cortex config file will enable you to configure gRPC based storage backend.

```
# Use gRPC based storage backend -for both index store and chunks store.
schema:
  configs:
  - from: 2019-07-29
    store: grpc-store
    object_store: grpc-store
    schema: v10
    index:
      prefix: index_
      period: 168h
    chunks:
      prefix: chunk_
      period: 168h

storage:
  grpc-store: 
    address: localhost:9966 # Address of the gRPC backend store
```

The config file in gRPC based storage server will be like:

```
cfg:
  http_listen_port: 9966 #This is port gRPC server exposes
  addresses: localhost
  database: cortex
  username: root
  password: root
  port: 3306  # This is exposed port of database.
```

This is can be altered based on your store implementation. 

Now you can use any database of your choice without any changes to cortex by just implementing the gRPC store for desired database. For now we have implemented gRPC based MYSQL & MONGO stores as backend stores for both indexes & chunks.

Link to MYSQL store: https://github.com/VineethReddy02/cortex-mysql-store

Link to MONGO store: https://github.com/VineethReddy02/cortex-mongo-store

Cheers!


