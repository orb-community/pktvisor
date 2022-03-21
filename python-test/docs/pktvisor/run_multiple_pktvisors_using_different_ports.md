## Scenario: Run multiple pktvisors using different ports 

## Steps:
- Provide 1 pktvisor using `docker run --net=host -d ns1labs/pktvisor pktvisord <net>`
- Provide 1 pktvisor using `docker run --net=host -d ns1labs/pktvisor pktvisord -p 10854 <net>`


## Expected Result:
- Both pktvisor containers must be running (one on port 10853 and one on port 10854)
- Endpoints from pktvisor API must be accessible (port 10853 and 10854)
 