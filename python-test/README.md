# Integration Tests
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

  Scenario: pktvisor bootstrap                         # features/pktvisor.feature:3
    When run pktvisor on port default                  # features/steps/pktvisor.py:32 0.184s
    Then the pktvisor container status must be running # features/steps/pktvisor.py:38 0.008s
    And pktvisor API must be enabled                   # features/steps/pktvisor.py:64 1.123s

  Scenario: run multiple pktvisors using different ports  # features/pktvisor.feature:8
    When run pktvisor on port default                     # features/steps/pktvisor.py:32 0.168s
    And run pktvisor on port 10854                        # features/steps/pktvisor.py:32 0.134s
    And run pktvisor on port 10855                        # features/steps/pktvisor.py:32 0.117s
    Then all the pktvisor containers must be running      # features/steps/pktvisor.py:46 0.074s

1 feature passed, 0 failed, 0 skipped
2 scenarios passed, 0 failed, 0 skipped
7 steps passed, 0 failed, 0 skipped, 0 undefined
Took 0m1.808s

```