{
  "title": "Distributed Tracing - Part 1",
  "date": "2021-07-07T01:32:45-04:00",
  "image": "",
  "description": "",
  "tags": ["Observability", "Tracing"],
  "fact": "",
  "featured":true
}

<br>


Welcome to series of write-ups on my learnings, findings on distributed tracing...

## What is Distributed Tracing?

![](https://i.imgur.com/9T2Rr2L.png)


Distributed tracing is the capability to track and observe service requests as the flow through distributed systems by collecting data as the requests go from one service to another and helps you to perform the root cause analysis for a specifc request.

A distributed trace is a directed acyclic graph of spans, where the edges of these spans are defined in parent, child relationship.

In a request lifecycle a trace travserses using RPCs between services. The relationship is propagated using trace context, some data that uniquely identifies a trace and each individual span within it. The span data that be emitted by each service is then forwarded to external service, where the spans are aggregated into a trace, analyzed for further insights, and stored for further analysis.   

## The Problem with Distributed Tracing

In todays world most of the observability is achieved using metrics and logs. But the increase in adoption of micro-services, containerisation, kubernetes requires more observability into your services as now the services are spread across different hosts, regions. Now to understand the request life-cycle across all the services we need distributed tracing.

### Why is distributed tracing hard?

The main problem with distributed tracing is instrumentation. You will be using different frameworks, languages per service and few services might even be complex legacy monoliths which aren't modified in the recent times. Even after collecting the trace data where will you store these data? Your services will emit traces all the requests being processed this can be too many traces to store and analyse. After we store these traces how do we analyse them? How do you derive value from them outside engineering org? All these questions might confuse many who are trying to get started with distributed tracing. 

### The Pieces of distributed tracing

To discuss above mentioned problems and to help you in getting started with distributed tracing lets divide tracing into three parts:

#### Instrumentation

To get the traces out of your services we need to instrument your services to emit trace data. These traces are formed by building blocks known as spans. In the later distributed tracing write ups. I will discuss more on state of the art instrumentation framework such as OpenTelemetry. 

#### Deployment

After instrumenting your services. Now we can receive traces from the services. But the other question where do we store trace data? What are the supporting compoenents for collecting and analysing these trace data before we store them into a database. We will discuss best practices on how do we operate these services to make most out of the deployment and how to manage tracing infrastructure for day 2 operations.  

#### Delivering Value

Now we have traces stored for deliverying value. But the other question is how do we query these traces to detct the anomolies and how do we combine them with other observability data like metrics and logs. How do we measure and what matters? How do we baseline the performance of services? All these topics will be discussed in upcoming write-ups.

### The Benefits of Tracing

* DT helps you to deliver your services with high quality and confidence as one can observe the performance and request life-cycle of their services.
* Improves the developer productivity to ship faster and to fix the issues early. In the world of micro-services there are different services and ifferent teams involved having DT in places helps to understand the problems and bottlenecks very early and helps to fix them.
* DT is agnostic to frameworks and languages so supports tracing across all your polyglot development.
* DT provides you all the visbility you need to understand what has changed or creating the problem on new deployments to easily rollback and report the issue to respective teams. This can very helpful when we do new deployment it involves frontend, multiple backend services, databases and other supporting components having the visibility into all these services can helps in improving collaboration and communication in resolving the issues with much more ease.  


In the upcoming DT write ups we will discuss more tracing concepts, operational knowledge and best practices.

*See you in upcoming write-up!* 


References:

* Book: [Distributed Tracing in Practice](https://www.oreilly.com/library/view/distributed-tracing-in/9781492056621/)