{
    "title":"k8s-scaler to create k8s resources at scale",
    "image":"/img/Kubernetes.png",
    "tags":["Kubernetes"],
    "fact":"",
    "date": "2020-03-31T12:41:05-05:00",
    "featured": true
}


### This project is a kubernetes resource scaler. The main objective of this project is to create 10's/100's/100's of kubernetes resources with ease. Infact by just using a single command.

&nbsp;
&nbsp;

Using the below cmd will let you create 5000 deployments, with replica count as 25 and each pod with 5 containers in namespace scale. 

```
./k8s-scaler create deployments --scale 5000 --replicas 25 --containers 5 --namespace scale
```

Using the below cmd will create & delete 100 deployments with replica count as 50 in scale namespace for every 10 seconds. This let's you to create excessive requests on Kubernetes api-server and to benchmark your Kubernetes controllers & operators by creating & deleting resources.

```
./k8s-scaler chaos deployments --scale 100 -replicas 50 --time 10 -n scale
```

&nbsp;
&nbsp;

Link to the project: https://github.com/VineethReddy02/k8s-scaler
