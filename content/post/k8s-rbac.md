+++
date = "2019-09-21T09:32:45-04:00"
draft = false
title = "Limiting Privileges In Kubernetes"
tags = ["kubernetes"]
+++

<br/>

## Role Based Access Control in Kubernetes

As we all know role based access control plays a vital role. when we have multiple people using the same resources for different purposes. We need to handle this scenarios by providing the users unique identification mechanism and privileges required for that particular user.

**RBAC in kubernetes adheres to least privilege principle.**

### Need for RBAC 

- As Kubernetes has tens of resources with many functionalities. Different users use them for different use cases. Unnecessary privileges leads to increasing the attack surface.

- Like every other role based access control system kubernetes also deals with authentication and authorization.

**Authentication** deals with does a specific user, group or a service from a machine can authenticate or access this system.

**Authorization** deals with does a specific user have an required privileges to perform a particular action on a specific resource or subresource or group of resources.

RBAC mainly deals with three entities

1. **subject**: Users(i.e humans & services)
2. **verb**:    Action a subject can perform
3. **object**:  Victim for an action from a subject

**Can mike(subject) get(verb) pods(object)?**

Kubernetes provides following resources to manage RBAC:


1. Role
2. ClusterRole
3. RoleBinding
4. ClusterRoleBinding
5. ServiceAccount


**Role**: Roles defines the set of privileges allowed on specific resource by it's name or on group of resources or set of subresourcesand this is confined to a specific namespace.

**ClusterRole**: ClusterRole defines the set of privileges allowed on specific resource by it's name or on group of resources or set of subresources and this is applicable on cluster as a whole.

**RoleBinding**: Rolebinding binds the user or group or serviceaccount to a role. This makes sure the subject provided in rolebinding has all the privileges provided within a role.

**ClusterRoleBinding**: ClusterRolebinding binds the user or group or serviceaccount to a role. This makes sure the subject provided in clusterrolebinding has all the privileges provided within a clusterrole.

**ServiceAccount**: Serviceaccount authorizes account to perform specific action based on the rolebinding or clusterrolebinding it is associated with.

In this blog we will be looking at two ways of creating KUBECONFIG file they are

1. Certificate based
2. Token based

### Certificate based authentication

Generate the private key file.

```
openssl genrsa -out new-user.key 2048
```

Create a certificate sign request new-user.csr using the private key you just created (new-user.key in this
example). Make sure you specify your username and group in the -subj section (CN is for the username and O for
the group). As previously mentioned, we will use new-user as the name and bitnami as the group:

```
openssl req -new -key employee.key -out new-user.csr -subj "/CN=new-user/O=aqua"
```

```
openssl x509 -req -in new-user.csr -CA CA_LOCATION/ca.crt -CAkey CA_LOCATION/ca.key -CAcreateserial -out new-user.crt -days 500
```

```
kubectl config set-credentials new-user --client-certificate=/home/new-user/.certs/new-user.crt --client-key=/home/new-user/.certs/new-user.key
```

```
kubectl config set-context new-context --cluster=minikube --namespace=test --user=new-user
```

After running the above steps we have successfully created a user with name as new-user belonging to aqua group. But this user doesn't have any previleges by defaults nil privileges will be assigned to the user. We need to explicitly grant the access privilges required by the user.

```
kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: test-user-full-access
  namespace: test
rules:
- apiGroups: ["", "apps","extensions"]
  resources: ["pods","pods/log","deployments"]
  #resourceNames: ["nginx-deployment"] #Confines privileges to specified resource name
  verbs: ["get","list"]
- apiGroups: ["batch"]
  resources:
  - jobs
  - cronjobs
  verbs: ["*"]
```

```
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: test-rolebinding
  namespace: test
subjects:
- kind: ServiceAccount
  name: new-user
  namespace: test
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: test-user-full-access
```


### Token based authentication

Token based authentication deals with service account. Firstly we create a service account which has internal RoleBinding or ClusterRoleBinding based on the requirement. And this has a secret token encoded in base64 and also a certificate. We need secret token and certificate to authenticate with cluster. We rovide this values in KUBEONFIG file.

- Creating a serviceaccount in test namespace.

```
apiVersion: v1
kind: ServiceAccount
metadata:
  name: test-user
  namespace: test
```

- Creating a clusterrole with privileges

```
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: test-user-full-access
rules:
- apiGroups: ["", "apps","extensions"]
  resources: ["pods","pods/log","deployments"]
  verbs: ["get","list"]
- apiGroups: ["batch"]
  resources:
  - jobs
  - cronjobs
  verbs: ["*"]
```

- Creating a clusterrolebinding by binding a serviceaccount to it.

```
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: test-rolebinding
subjects:
- kind: ServiceAccount
  name: test-user
  namespace: test
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: test-user-full-access
```

- Get the service account secret for the provided namespace

```
kubectl describe sa test-user -n test
```

- Get the service account token 

```
kubectl get secret test-user-token-xxxxx -n test -o "jsonpath={.data.token}" | base64 -d
```

- Get the certificate authority

```
kubectl get secret test-user-token-xxxxx -n test -o "jsonpath={.data['ca\.crt']}"
```

**Template for KUBECONFIG file.**

Add the kubernetes api endpoint, certificate and token in the below KUBECONFIG file.

```
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: PLACE CERTIFICATE HERE
    server: https://YOUR_KUBERNETES_API_ENDPOINT
  name: kind
contexts:
- context:
    cluster: kind
    namespace: test
    user: test-user
  name: test
current-context: test
kind: Config
preferences: {}
users:
- name: test-user
  user:
    client-key-data: PLACE CERTIFICATE HERE
    token: PLACE USER TOKEN HERE
```

We have successfully created a KUBECONFIG file for a new user.


### Other way of understanding RBAC is to install helm in your kubernetes cluster

First install helm by following helm official docs https://helm.sh/docs/using_helm/#installing-helm

We are creating ServiceAccount with name tiller

```
apiVersion: v1
kind: ServiceAccount
metadata:
  name: tiller
  namespace: kube-system
```
We are binding the cluster admin privileges tiller service account

```
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: tiller
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: tiller
    namespace: kube-system
```

After creating the above ServiceAccount and ClusterRoleBinding

Run the tiller

```
helm init --service-account tiller
```

Check the helm installation and validate ServiceAccount by running following command

```
helm install stable/mysql
```

By this you have successfully configured helm in your cluster which needs special privileges to communicate with API-SERVER.


**Note:**

1. By default when a new namespace is created a default ServiceAccount specific to that namespace is created but this serviceaccount has no authorization privileges all the resources running in this namespace will use the default ServiceAccount, Unless we need any privileges specific to a resource we need to specify it in resource.yaml as mentioned in below example.

```
apiVersion: v1
kind: Pod
metadata:
  name: nginx-creator
  namespace: test
spec:
  serviceAccountName: nginx-creator     #This resource has special privileges binded in this ServiceAccount
  containers:
  - name: nginx-creator
    image: vineeth97/nginx-pod-creator
```

2. We can also bind a ClusterRole to a RoleBinding which provides privileges to subject provided in RoleBinding but the scope is specific to namespace mentioned in the RoleBinding. 

Slides prepared fors my talk on RBAC can be found [here](https://drive.google.com/file/d/1FGjjYQDRdoB1geNh4D_gRuZutCha8LdW/view)

*Cheers!*
