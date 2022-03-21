# Pktvisor Tests
This directory contains automated tests for pktvisor


This directory is organized as described below:


```
python-test
├── README.md
├── requirements.txt
├── docs
└── features
|   ├── steps
|   └── .feature files

```

- Inside the "docs" folder is the test scenarios' documentation
- Test features are inside the "features" folder and consist of .features files. This is the gherkin language description of the scenarios you will see in the execution terminal
- The python programming of each step of the scenarios is inside the "steps" subfolder, inside "features"


<br>

Here's what you'll need to do in order to run these tests:
- Setup your python environment
- Run behave

## Setup your Python environment
Create a virtual environment: `python3 -m venv name_of_virtualenv`

Activate your virtual environment: `source name_of_virtualenv/bin/activate`

Install the required libraries: `pip install -r requirements.txt`


## Run behave
From the root of the repository simply run `behave`, optionally passing the feature file as follows:

```sh
$ behave features/pktvisor.feature
```

Output:

```
Feature: pktvisor tests # features/pktvisor.feature:1

  Scenario: pktvisor bootstrap                         # features/pktvisor.feature:3
    When run pktvisor instance on port default         # features/steps/pktvisor.py:33 0.150s
    Then the pktvisor container status must be running # features/steps/pktvisor.py:39 0.007s
    And pktvisor API must be enabled                   # features/steps/pktvisor.py:75 1.123s

  Scenario: run multiple pktvisors using different ports  # features/pktvisor.feature:8
    When run pktvisor instance on port default            # features/steps/pktvisor.py:33 0.156s
    And run pktvisor instance on port 10854               # features/steps/pktvisor.py:33 0.127s
    And run pktvisor instance on port 10855               # features/steps/pktvisor.py:33 0.146s
    Then all the pktvisor containers must be running      # features/steps/pktvisor.py:47 0.011s
    And 3 pktvisor's containers must be running           # features/steps/pktvisor.py:59 0.012s

  Scenario: run multiple pktvisors instances using the same port  # features/pktvisor.feature:15
    When run pktvisor instance on port default                    # features/steps/pktvisor.py:33 0.194s
    And run pktvisor instance on port default                     # features/steps/pktvisor.py:33 0.149s
    Then 1 pktvisor's containers must be running                  # features/steps/pktvisor.py:59 0.226s
    And 1 pktvisor's containers must be exited                    # features/steps/pktvisor.py:59 0.011s

1 feature passed, 0 failed, 0 skipped
3 scenarios passed, 0 failed, 0 skipped
12 steps passed, 0 failed, 0 skipped, 0 undefined
Took 0m2.312s


```