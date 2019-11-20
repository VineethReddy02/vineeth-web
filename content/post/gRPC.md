+++
date = "2019-11-20T09:32:45-04:00"
draft = false
title = "Understanding gRPC"
tags = ["Networking"]
+++

## gRPC

gRPC is a RPC platform developed by Google. The letters gRPC are a recursive acronym which means, gRPC Remote Procedure Call.

gRPC has two parts, the gRPC protocol, and the data serialization. By default gRPC utilizes Protobuf for serialization, but it is pluggable with any form of serialization you wish to use, with some caveats.

### HTTP/2

gRPC supports several built in features inherited from http2, such as compressing headers, persistent single TCP connections, cancellation and timeout contracts between client and server.

### Streams, Messages, and Frames
The introduction of the new binary framing mechanism changes how the data is exchanged between the client and server. To describe this process, let’s familiarize ourselves with the HTTP/2 terminology:

***Stream***: A bidirectional flow of bytes within an established connection, which may carry one or more messages.

***Message***: A complete sequence of frames that map to a logical request or response message.

***Frame***: The smallest unit of communication in HTTP/2, each containing a frame header, which at a minimum identifies the stream to which the frame belongs.

- All communication is performed over a single TCP connection that can carry any number of bidirectional streams.

- Each stream has a unique identifier and optional priority information that is used to carry bidirectional messages.

- Each message is a logical HTTP message, such as a request, or response, which consists of one or more frames.

- The frame is the smallest unit of communication that carries a specific type of data—e.g., HTTP headers, message payload, and so on. Frames from different streams may be interleaved and then reassembled via the embedded stream identifier in the header of each frame.

### gRPC offers:

- Request & Response Multiplexing
- Stream Prioritization
- One connection Per Origin
- Flow Control
- Server Push
- Header Compression

### HTTP/2 vs HTTP 1.1

Comparing REST and gRPC. REST, as mentioned earlier, depends heavily on HTTP (usually HTTP 1.1) and the request-response model. On the other hand, gRPC uses the newer HTTP/2 protocol.

The probelms with HTTP 1.1 that HTTP/2 fixes.

- HTTP 1.1 is too big and complicated
- The Growth of Page Size and Number of Objects
- Latency issues
- Head of Line Blocking (reduces the ability to process parallel requests) 



***Default choice - REST***

For simple services, HTTP REST is probably enough

- HTTP verbs (GET, POST, PUT, DELETE etc.) are rich enough
- REST semantics are well understood.


When not to pick REST?

For more complex services where efficiency is important, RPC can help.

***PRO's:***

- SIMPLE & IDIOMATIC
- PERFORMANT & SCALABLE
- INTEROPERABLE & EXTENSIBLE

Google uses this framework to make 10 the power 10 calls per second.

### HOL

The probelem raises in HTTP/1 with HOL (Head of line blocking) when we sent a request to the server now on the connection is useless until it returns the response. Originally the server has allowed two connections per server had reuse the connection once the reponse has received. So this bottleneck was addressed by raising the limit to 6 connections.

### Metadata

Headers repeat alot across the request. The headers that repeat are user-agents & cookies ther are long and static and they are keep being added for each and every request. This is because HTTP was designed to be completely stateless and independent from the next. And then people started using sessions and these are identified with a long UUID and they are appended to every request being sent over & over which is waste of bandwidth. Though the headers are highly compressable they cannot be gzipped as data which is a actually a miss opportunity.

HTTP/2 follows the semantics of HTTP/1 this requets contain the headers i.e key/value pairs and body conetent which doesn't need any code related changes. The changes involve in how they are encoded in wire in transit(i.e into binary level)

The scariest part is upgrade to HTTP/2 will I loose my clients ? Answer is no.

So every connections starts out as H1 and then it upgrades to H2 and if this client doesn't support H2 it will stay on H1 and everything will work as before.

What is HTTP/2 exactly? It's a single TLS encrypted connection.
So HOL blocking is addressed at protocol level by single connection.

## Limitations with HTTP/1.1

1. HTTP 1.1 opens a new TCP connection to a server at each request.
2. It does not compress headers (which are plaintext).
3. It only works with Request/Response mechanism (no server push).
4. These inefficiences add more latency and increase network packet size.

## Advantages with HTTP/2

1. The client & server can push messages in parallel over the same TCP connection
2. This greatly reduces latency.
3. Server can push streams (multiple messages) for one request from the client which will reduce the round trips between
   client and server.
4. HTTP/2 supports header compressions, This have much less impact on packet size(less bandwidth.
5. Average http request may have over 20 headers, due to cookies,content cache and application headers.
6. HTTP/2 is binary while HTTP/1 is text which is not efficient over the network.
7. Protocol buffers is a binary protocol and makes it a great match for HTTP/2
8. HTTP/2 is secure (SSL is not required but recommended by default)

## Types of API in gRPC

1. **Unary** default client to server request/response based communication.
2. **Server Streaming** client request server and server responds back with stream of responses.
3. **Client Streaming** client creates a streaming request connection with server and server sends back a single response.
4. **Bi Directional Streaming** client sends a stream of requests to server and server sends back stream of responses 
   back to client.
   
## Scalability in gRPC

1. gRPC servers are asynchronous by default.
2. This means they do not block threads on request.
3. Therefore each gRPC server can serve millions of requets in parallel.
4. gRPC Clients can be asynchronous or synchronous (blocking).
5. The client decides which model works best for the performance needs.
6. gRPC Clients can perform client side load balancing.

### gRPC vs REST

***gRPC***

1. Protocol Buffers - smaller,faster.
2. HTTP/2(lower latency).
3. Bidirectional & Async.
4. Stream Support.
5. API oriented (no constraints-free design).
6. Code Generation through Protocol Buffers in any language-1st  class citizen.
7. RPC based gRPC does the plumbing for us.

***REST***

1. JSON- text based,slower, bigger
2. HTTP1.1 (higher latency)
3. Client -> Server requets only
4. Request/Response support only
5. CRUD oriented(Create-Retrieve-Update-Delete/POST GET PUT DELETE)
6. Code generation through OpenAPI/Swagger(add-on)-2nd class citizen
7. HTTP verns based- we have to write the plumbing or use a 3rd party library

### Protobuf vs JSON

One of the biggest differences between REST & gRPC is the format of the payload. REST messages typically contain JSON. The whole REST ecosystem including tooling, best practices, and tutorials is focused on JSON. It is safe to say that, with very few exceptions, REST APIs accept and return JSON.

gRPC, on the other hand, accepts and returns Protobuf messages. I will discuss the strong typing later, but just from a performance point of view, Protobuf is a very efficient and packed format. JSON, on the other hand, is a textual format. You can compress JSON, but then you lose the benefit of a textual format that you can easily expect.


### Strong Typing vs. Serialization

The REST paradigm doesn't mandate any structure for the exchanged payload. It is typically JSON. Consumers don't have a formal mechanism to coordinate the format of requests and responses. The JSON must be serialized and converted into the target programming language both on the server side and client side. The serialization is another step in the chain that introduces the possibility of errors as well as performance overhead. 

The gRPC service contract has strongly typed messages that are converted automatically from their Protobuf representation to your programming language of choice both on the server and on the client.

JSON, on the other hand, is theoretically more flexible because you can send dynamic data and don't have to adhere to a rigid structure. 

### Server Streaming

- Server Streaming RPC API are a new kind API enabled thanks to HTTP/2
- The client will send one message to the server and will receive many responses from the server, possibly an infinite number.

Usecases:

1. When the server needs to send a lot of data (big data).
2. When the server needs to PUSH data to the client without having the client request for more.


### Client Streaming

- Client streaming RPC API are a NEW kind API enabled thanks to HTTP/2
- The client will send many message to the server and will receive one response from the server (at any time)

- Streaming client are well suited for
  1. When the client needs to send a lot of data(big data)
  2. When the server processing is expensive and should happen as the client sends data
  3. When the client needs to PUSH data to the server without really expecting a response.

- In gRPC client streaming calls are defined using the keyword "stream"
- As for each RPC call we have to define a "Request" message and a "Response" message.


### Bi Directional Streaming API

- Bi Directional Streaming RPC API are a new kind API enabked thanks to HTTP/2
- The client will send many message to the server and will receive many responses from the server.
- The number of requests and responses does not have to match

- Bi Directional Streaming RPC are well suited for
    - When the client and the server needs to send a lot of data asynronously
    - Chat protocol
    - Long running connections

- In gRPC Bi Directional Streaming API are defined using the keyword "stream", twice
- As for each RPC call we have to define a "Request" message and a "Response"
message.w

#### Below is the .proto file which contains the message definitions & stream declarations. 

```
syntax = "proto3";

package registration;
option go_package="registration";

message register_request {
    string name = 1;
    string email = 2;
}

message register_response {
    string registration_id = 1;
}


message bulk_register_response {
    repeated register_response bulk_response = 1;
}

message nothing {}

service Registration_service {
    // Unary
    rpc register(register_request) returns (register_response) {};
    // Client streaming
    rpc register_bulk(stream register_request) returns (bulk_register_response) {};
    // Server streaming
    rpc get_registered_data(nothing) returns (stream register_response) {};
    // client/server streaming
    rpc register_multiple_requests(stream register_request) returns (stream register_response) {};
}
```

In Protocol buffers to consume the ablove defined messages & services. We generate the code using the below command

```protoc registration.proto --go_out=plugins=grpc:.```

### Status Codes in gRPC

Codes in gRPC are imported from a package 

```
google.golang.org/grpc/codes
```

Example:
These are the status codes defined in ***grpc/codes***.

```
const (
	OK Code = 0
	Canceled Code = 1
	Unknown Code = 2
)
```

### Streaming with timeout

- We can set the timeout per request and cancel the request if the server is taking longer the set up timeout.
- The timeout context is applicable for chain of microservice requests. 

### SSL Encryption in gRPC

- In producrion gRPC calls should be running with encryption enabled
- This is done by generating SSL certificates.
- SSL allows communication to be secure end to end and ensuring no man in the middle attck can be performed.

### SSL Security

What is SSL?

- TLS (Transport layer security), successor of SSL, encrypts the connection between 2 endpoints for secure data exchange.

- Two ways of using SSL (gRPC can use booth):
  - One way verification e.g browser -> webserver
  - Two way verification e.g: SSL authentication

### Language Interoperatability

In gRPC interoperatability is possible go server can serve the requets to java client and vice versa.

### gRPC Reflection & evans cli

We may ask server what API's do you have? That's reflection.

We want reflection for two reasons
 - Having servers expose which endpoints are available.
 - Allowing command line interfaces (CLI) to talk to our server without preliminary .proto file.

The below code snippet allows to expose endpoints of the respective server.
```
"google.golang.org/grpc/reflection"

reflection.Register(s)
```
Evans cli for grpc helps us to see all the endpoints exposed using command line tool.

Download evans cli tool from here:

https://github.com/ktr0731/evans/releases


```
./evans -p 6666 -r // To connect to the gRPC server using evans cli

show package // Shows the package in protocol buffers

show service // shows all the available services in the gRPC server.

show message // shows all the messages defined in protocol buffers.

call register // Test the respective service in interactive mode
```

### Demo App

Let's create a server that registers the client requests and displays a message saying registration successsful.
When client sends register request to server it returns a unique id is returned, on successful registration.

Checkout the demo app on gRPC [here](https://github.com/VineethReddy02/gRPC-demo/tree/master)
