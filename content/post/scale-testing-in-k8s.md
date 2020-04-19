+++
date = "2020-04-19T09:32:45-04:00"
draft = false
title = "Benchmarking your Controllers & Operators at Scale"
tags = ["kubernetes"]
+++

<br/>

The most common problem the controllers and operators developers face today is to benchmark their tools in large environments with 1000's workloads running it. As controllers & operators come with custom logic to perform an action when a specific event has been occured in the cluster to achieve the intended state.

Creating 100 node cluster for benchmarking the Kubernetes tools is definitely expensive, creation, maintainance & deletion is also a tiring job. What if we can create a mock kubelet for scale tests by just running a deployment in your cluster? Yes, This is possible and you can leverage out of this tool in benchmarking your kubernetes tools.

All we need is to simulate loaded environments to perform scale test on our tools. Creating loaded environemnts comes with cost. And we don't want to spend that huge figures in benchmarking our tools.

When I refer to Kubernetes tools, I mean the Kubernetes Controllers, Operators, kubectl plugins, etc.. which interact with api-server for events and perform kubernetes resource scheduling.

### [mocklet](https://github.com/VineethReddy02/mocklet)

So I will be explaining about how to simulate a mocklet that can hold 1000's pods in it's inmemory and this mock kubelet can be connected to your existing cluster by just running a deployment in your cluster.

Running the below command will create a new mocklet node in your cluster

```
kubectl create -f https://github.com/VineethReddy02/mocklet/blob/master/k8s-deployment.yaml
```
Now you can notice mocklet is added into your cluster
```
NAME                                     STATUS   ROLES    AGE     VERSION
gke-gke5684-default-pool-1y5e7l53-kphx   Ready    <none>   4h23m   v1.14.10-gke.27
gke-gke5684-default-pool-1y5e7l53-x5kj   Ready    <none>   4h23m   v1.14.10-gke.27
mocklet                                  Ready    agent    2m32s   v1.15.2-vk-N/A
```


Creating multiple deployments will create multiple mocklets in your cluster to run desired number of kubernetes resources and scheduling resources specific to a mocklet.

Now you can deploy 1000's pods by providing the node selector value as mocklet and mocklet toleration. This will make sure all the test data you are creating is scheduled on the desired mocklet.

The mocklet project is completely inspired from Virtual Kubelet mock provider. Thanks to the the **[Virtual Kubelet community](https://github.com/virtual-kubelet/virtual-kubelet).**

The bigger challenge is how do I create 1000's of pods, Deployments, Replicasets, ReplicationControllers, StatefulSets, Jobs and Cronjobs?

### [k8s-scaler](https://github.com/VineethReddy02/k8s-scaler)

To create the Kubernetes resources at scale in a single shot. I have implemented tool called **k8s-scaler**. This tool is highly configurable and helps you to create Kubernetes resources. which runs pods in the down stream with higly configurable properties such as number of containers, inclusion & exlusion of namespaces during resource creation, number of instances per Kubernetes resource, number of replicas per Kubernetes controller.  

Creating 5000 deployments with replica count as 5 per instance and number of containers per pod as 3 in scale namespace with node-selector & toleration is as simple as 

```
./k8s-scaler create deployments --scale 5000 --replicas 5 --containers 3 --namespace scale --node-selector type=mocklet --toleration mocklet.io/provider=mock
```

**Note:** Using k8s-scaler you can also create/delete namespaces, daemonsets, statefulsets, replicationcontrollers, replicasets, jobs and cronjobs

k8s-scaler also helps you in listing number of kubernetes resources per namespace as shown below.

```yaml
vineeth@vineeth-Latitude-7490 /bin (master) $ ./k8s-scaler list
NAMESPACE    DEPLOYMENTS     REPLICASETS     DAEMONSETS      STATEFULSETS    PODS        JOBS        CRONJOBS    REPLICATION-CONTROLLERS
test         3000            3000            1000            500             7486        30          10          30               
default      1300            1300            456             250             5642        10          5           5                  
kube-system  8               11              4               0               15          0           0           0               
mocklet      3500            4000            1200            400             9348        50          30          35     
```

Using the **mocklet** and **k8s-scaler** you can create the large environments with ease. Running mocklet will provide the mock kubelet to run the desired number of resorces and using k8s-scaler you can create desired number of kubernetes resources by running a single command in any kubernetes cluster.

I hope these tools will help you in scale testing the tools built around kubernetes.

Cheers!




