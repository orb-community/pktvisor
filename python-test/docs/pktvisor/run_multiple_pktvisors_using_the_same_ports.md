## Scenario: Run multiple pktvisors using the same ports 

## Steps:
- Provide 1 pktvisor using `docker run --net=host -d ns1labs/pktvisor pktvisord <net>`
- Provide 1 pktvisor using `docker run --net=host -d ns1labs/pktvisor pktvisord <net>`


## Expected Result:
- The first pktvisor provisioned must be running (one on port 10853)
- Second pktvisor container must be exited
 
