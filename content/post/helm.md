+++
date = "2020-05-08T09:32:45-04:00"
draft = false
title = "Helming"
tags = ["kubernetes"]
+++

<br>

Helm is a package manager for Kubernetes. A Chart is a Helm package. It contains all of the resource definitions necessary to run an application, tool, or service inside of a Kubernetes cluster. Think of it like the Kubernetes equivalent of a Homebrew formula, an Apt dpkg, or a Yum RPM file.

A Release is an instance of a chart running in a Kubernetes cluster. One chart can often be installed many times into the same cluster. And each time it is installed, a new release is created. 

## Why we need helm?

1. Ship prepackaged software.
2. Easily install packages into any Kubernetes cluster.
3. Easily create & host your own software as helm charts.
4. Visibility in cluster to see what packages are installed & running.
5. Update, delete, rollback, or view the history of installed packages. 


## Helm 2 vs Helm 3

1. **No more tiller**: Initially when helm was developed there was no strong access control model is Kubernetes. From Kubernetes 1.6 release Role Based Access Control (RBAC) has become default acess control. In helm 3 the access control is handed over to RBAC and we don't need tiller anymore. 
2. **Two-way to Three-way strategic merge patch**: In helm 2 if we come across the scenario like we deployed an application using helm chart and we made changes on configuration in live cluster using ```kubectl edit``` and for some reason we decide to rollback. we don't consider the live state of cluster we compare the previous charts and new charts.
3. **Release info will be stored as secrets not anymore as configmaps**: In helm 2 all the helm installed related release information was stored in configmaps which needs additional encryption & decryption to avoid complexity around storing this information in helm 3 release information will be stored in secrets.
4. **Release name is required or use --generate-name flag**: Helm 2 has by default random release name generation if user doesn't provide one. But helm 3 release name is required if not provided helm throws an error. If you want helm to generate the name use ```--generate-name``` flag.   
5. **Local chart repository is removed i.e helm serve**: For local development purposes in helm 2 there was ```helm serve``` which was used to run a local Chart Repository on your machine in helm 3 this has been removed but available as a plugin. 
6. **Namespaces are not created automatically**: In helm 2 if values.yaml contains a namespace which doesn't exist in the cluster it used to create namespace automatically before creating the resources. But in helm 3 this will cause an error before installing the helm chart we need to create namespace if it doesn't exist.
7. **JSON Schema Chart Validation**: In helm 3 you can validate the values provided by the user with the schema created by the chart maintainer. This provides better error reporting when we mess up with values.


## Helm Hub

Helm hub is a centralized location where all the communtiy developed helm charts are maintained. We do have other helm chart respositories like bitnami https://github.com/bitnami/charts etc...

You can also host your own helm chart repository for your helm charts example helm chart repository chartmuseum https://chartmuseum.com/

## How to maintain your own charts repository.

## Directory structure of a helm chart

```
└── helm-demo
    ├── charts
    ├── Chart.yaml
    ├── templates
    │   ├── deployment.yaml
    │   ├── _helpers.tpl
    │   ├── hpa.yaml
    │   ├── ingress.yaml
    │   ├── NOTES.txt
    │   ├── serviceaccount.yaml
    │   ├── service.yaml
    │   └── tests
    │       └── test-connection.yaml
    ├── values.yaml
    └── values.schema.json
```
**Charts**: Charts directory contains all the charts upon which this chart depends.

**Chart.yaml**: A yaml file containing information about the chart.

**templates**: When the temaplte files are combined with values the generated manifest files are stored in templates directory.

**values.schema.json**: A json schema for imposing the structure and validations on the values.yaml file. (optional)

In helm all the magic works using templating the two main files we should care about are values.yaml and all manifests files under templates directory. Define all the values in values.yaml files and using yaml templating for referencing the values and for re-using the values across template files. You can also overirde the flags while installing the helm chart by using flags such as ```--set```, ```--set-string``` and ```-f``` for passing your own values.yaml file.

## Available CLI commands

```
  completion  generate autocompletions script for the specified shell (bash or zsh)
  create      create a new chart with the given name
  dependency  manage a chart's dependencies
  env         helm client environment information
  get         download extended information of a named release
  help        Help about any command
  history     fetch release history
  install     install a chart
  lint        examines a chart for possible issues
  list        list releases
  package     package a chart directory into a chart archive
  plugin      install, list, or uninstall Helm plugins
  pull        download a chart from a repository and (optionally) unpack it in local directory
  repo        add, list, remove, update, and index chart repositories
  rollback    roll back a release to a previous revision
  search      search for a keyword in charts
  show        show information of a chart
  status      displays the status of the named release
  template    locally render templates
  test        run tests for a release
  uninstall   uninstall a release
  upgrade     upgrade a release
  verify      verify that a chart at the given path has been signed and is valid
  version     print the client version information
```

## Creating your first helm chart

The below command creates the helm chart with all the basic templating. 

```
helm create <chart_name>
```

## Installing your first helm chart

The below command installs the helm chart. 

```
helm install <release_name> <chart_name>
```

## Installing an helm chart from helm hub

Example:

Inititalising a helm chart repo

```
helm repo add stable https://kubernetes-charts.storage.googleapis.com/
```

Search for the desired chart

```
helm search repo stable/cassandra
```

Installing the helm chart

```
helm install cassandra01 stable/cassandra
```


## Uninstalling a helm chart

The helm uninstall commands helps you to delete all the kubernetes resources deployed by installing a specific chart

```
helm uninstall <chart_release_name>
```

## Upgrade & Rollback a release using a helm chart

After making necessary chnages to helm chart please update app version if image tag has been updated or if there any chnages around helm chart configuration update the chart version.

Upgrading a release

```
helm upgrade <release_name> <chart_name>
```

Rolling back an upgrade 

```
helm rollback <release_name> <revision_number>
```

## To view manifest files

```
helm template <chart_name>
```

Here is an basic helm chart which has templating for a deployment to one of my project called mocklet https://github.com/VineethReddy02/mocklet-helm

Cheers & Happy Helming!