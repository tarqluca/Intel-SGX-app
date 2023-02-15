# Intel SGX application
A simple implementation of a communication protocol between two enclaves in Intel SGX.<br/>
This protocol provides proof and verification of the capability to perform a simple operation (in this specific case, sum of two integers) without disclosing any additional information.<br/>
The figure below provides an illustration of the protocol.<br/>
![protocol](https://user-images.githubusercontent.com/96884174/219003894-ee2b4e54-433d-4ed7-8833-6d654e9d8a7c.png)

Note: this protocol is definitely not suitable for a production environment: it runs in SGX simulation mode and makes use of naive techniques with respect to the CIA security properties for simplicity purposes.

## Building and running the protocol
`./run.sh`
