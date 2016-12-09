audit-aws-ec2-samples
============================



## Description
This repo is designed to work with CloudCoreo. This composite is a collection of sample EC2 definitions that have been requested by our customers and should be considered a starting point for building your own composites from.


## Hierarchy
![composite inheritance hierarchy](https://raw.githubusercontent.com/CloudCoreo/audit-aws-ec2-samples/master/images/hierarchy.png "composite inheritance hierarchy")



## Required variables with no default

### `AUDIT_AWS_EC2_TAG_EXAMPLE_ALERT_RECIPIENT`:
  * description: email recipient for notification


## Required variables with default

### `AUDIT_AWS_EC2_TAG_EXAMPLE_ALLOW_EMPTY`:
  * description: receive empty reports?
  * default: false

### `AUDIT_AWS_EC2_TAG_EXAMPLE_SEND_ON`:
  * description: always or change
  * default: change

### `AUDIT_AWS_EC2_TAG_EXAMPLE_EXPECTED_TAGS`:
  * description: the tag we want to see on instances
  * default: "EXAMPLE_TAG_1", "EXAMPLE_TAG_2"

### `AUDIT_AWS_EC2_TAG_EXAMPLE_TAG_LOGIC`:
  * description: "or" or "and"
  * default: "and"

### `AUDIT_AWS_EC2_TAG_EXAMPLE_REGIONS`:
  * description: list of AWS regions to check. Default is all regions
  * default: us-east-1, us-west-1, us-west-2

### `REGION`:
  * description: 
  * default: PLAN::region


## Optional variables with default

**None**


## Optional variables with no default

### `AWS_LINUX_AMI`:
  * description: the ami id for latest AWS Linux

## Tags
1. Audit
1. Best Practices
1. Alert
1. EC2

## Categories
1. Audit



## Diagram
![diagram](https://raw.githubusercontent.com/CloudCoreo/audit-aws-ec2-samples/master/images/diagram.png "diagram")


## Icon


