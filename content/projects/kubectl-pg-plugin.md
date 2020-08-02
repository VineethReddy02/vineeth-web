
{
  "title": "kubectl pg plugin for Zalando's Postgres Operator",
  "date": "2019-09-02T09:32:45-04:00",
  "image": "/img/k8s-pg.png",
  "fact": "",
  "featured": true
}

<br/><br/>

### kubectl pg plugin helps in managing postgres clusters efficiently and by decreasing the efforts in working with postgresql resources.

## Project Abstract
The Postgres Operator is a project to create an open-sourced managed Postgres service for Kubernetes. 
The Postgres operator manages Postgres clusters on Kubernetes. kubectl plugins enable extending the Kubernetes command-line client kubectl with commands to manage custom resources. The task is to design and implement a plugin for the kubectl 
postgres command. My project aims to simplify and ease the usage of postgres clusters using the kubectl plugin. 
As the postgres operator is capable of many features having a kubectl plugin will ease in running the clusters and u
nderstanding the resources way better.

### Description

The developed kubectl pg plugin helps in managing the postgres clusters efficiently and by decreasing the efforts in working with postgresql resources. Usually dealing with custom resource definations is a bit complicated as everythng needs to verfied and updated manually by changing the manifest file. kubectl pg plugin helps in managing the postgres clusters with ease. We can check whether the postgresql CRD is registered in the cluster or not. By this we can go ahead in creating CRD resources without any manual verfication such as state of postgres operator and CRD created by it. Dealing the postgres-operator is challenging when we have multiple operators in different namespaces. I developed a command which shows the current version of postgres-operator in current namespace and also in specified namespace. Though the usual way of creating postgres resources is using kubectl apply command for ease in managing postgres cluster individually we created kubectl pg create cmd specific to postgres resources. The same has been implemented for update as kubectl pg update and for delete as kubectl pg delete. 

### Demo

[![asciicast](https://asciinema.org/a/YD0zVQnesSy6Tw2LIRIrghwW6.svg)](https://asciinema.org/a/YD0zVQnesSy6Tw2LIRIrghwW6)

### Developed Features:
<br>
#### Check whether the postgres CRD is registered.

This makes sure CRD is installed in the kubernetes cluster. which helps us in creating ```postgresql``` resources

```
kubectl pg check
```

#### Create postgres cluster using manifest file

This is an alternative to ```kubectl apply``` but built specifically to handle creation of kind postgresql resources. 

```
kubectl pg create -f manifest.yaml
```

#### Update postgres cluster using manifest file

This is an alternative to ```kubectl apply``` but built specifically to handle updation of kind postgresql resources. 

```
kubectl pg update -f manifest.yaml
```

#### Delete postgres cluster using manifest file

This is an alternative to ```kubectl delete``` but built specifically to handle deletion of kind postgresql resources and verifies the deletion with confirmation. 

```
kubectl pg delete -f manifest.yaml
```

#### Delete postgres cluster using cluster name

This is built specifically to delete postgresql cluster using it's name in the current namespace.

```
kubectl pg delete cluster
```

#### Delete postgres cluster using cluster name in specified namespace

This is built specifically to delete postgresql cluster using it's name in the provided namespace.

```
kubectl pg delete cluster -n namespace
```

#### List postgres cluster from current namespace

This feature helps in listing the postgres clusters in the current namespace.

```
kubectl pg list
```

#### List postgres clusters from all namespaces

This feature helps in listing the postgres clusters from all the namespaces.

```
kubectl pg list -A
```

#### Extend volume of an existing cluster

This feature let's you extend the size of the volume.

```
kubectl pg ext-volume 2Gi -c cluster
```

#### Scale the number of instances of postgres cluster

This feature let's to scale up and down by providing the desired instances.

```
kubectl pg scale 10 -c cluster
```

#### Add a database and it's owner to a postgres cluster

This feature let's you add new database and associated owner.

```
kubectl pg add-db DB01 -o OWNER -c cluster
```

#### Add a user and set of privileges to a postgres-cluster

This feature let's you add new user and privileges such as superuser, inherit ,login, nologin, createrole, createdb, replication, bypassrls.

```
kubectl pg add-user USER01 -p login,createdb -c cluster
```

#### Fetch the logs of the postgres operator

Get the logs of postgres-operator pod.

```
kubectl pg logs -o
```

#### Fetch the logs of the postgres cluster

- Get the logs of random replica from the provided cluster.

```
kubectl pg logs -c cluster
```

- Get the logs of master pod from the provided cluster.

```
kubectl pg logs -c cluster -m
```

- Get the logs of specified replica from the provided cluster.

```
kubectl pg logs -c cluster -r 3
```

#### Connect to shell prompt 

- Connect to the shell prompt of random replica.

```
kubectl pg connect -c cluster
```

- Connect to the shell prompt of master pod in the provided cluster.

```
kubectl pg connect -c cluster -m
```

- Connect to shell prompt of specified replica for the provided postgres cluster.

```
kubectl pg connect -c cluster -r 2
```

#### Connect to psql prompt of random replica 

- Connect to the psql prompt of random replica with db-name as current user and db-user as current user.

```
kubectl pg connect -c cluster -p
```

- Connect to the psql prompt of random replica with db-user as specified user and db-name as specified user.

```
kubectl pg connect -c cluster -p -u user01
```

- Connect to psql prompt of random replica with provided postgres cluster, db-user as specified user and db-name as specified db-name.

```
kubectl pg connect -c cluster -p -u user01 -d db01
```

- Connect to psql prompt of specified replica for the provided postgres cluster, db-user as current user and db-name as current username.

```
kubectl pg connect -c cluster -p -r 4
```

- Connect to psql prompt of specified replica with provided postgres cluster, db-user as specified user and db-name as specified user.

```
kubectl pg connect -c cluster -p -r 3 -u user01
```

- Connect to psql prompt of specified replica with provided postgres cluster, db-user as specified user and db-name as specified db-name.

```
kubectl pg connect -c cluster -p -r 3 -u user01 -d db01
```

- Connect to psql prompt of master for the provided postgres cluster, db-user as current user and db-name as current username.

```
kubectl pg connect -c cluster -p -m
```

- Connect to psql prompt of master with provided postgres cluster, db-user as specified user and db-name as specified user.

```
kubectl pg connect -c cluster -p -m -u user01
```

- Connect to psql prompt of master with provided postgres cluster, db-user as specified user and db-name as specified db-name.

```
kubectl pg connect -c cluster -p -m -u user01 -d db01
```



#### Version details of kubectl pg plugin and postgres-operator

- Get the version of kubectl pg plugin and postgres-operator in default namespace.

```
kubectl pg version
```

- Get the version of kubectl pg plugin and postgres-operator in specified namespace.

```
kubectl pg version -n namespace
```

Link to the Google Summer of Code tracker: https://github.com/VineethReddy02/GSoC-Kubectl-Plugin-for-Postgres-Operator-tracker

Link to the kubectl-pg plugin: https://github.com/zalando/postgres-operator/tree/master/kubectl-pg
