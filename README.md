audit-aws-ec2-atk
============================



## Description
This repo is designed to work with CloudCoreo.


## Hierarchy
![composite inheritance hierarchy](https://raw.githubusercontent.com/CloudCoreo/audit-aws-ec2-samples/master/images/hierarchy.png "composite inheritance hierarchy")



## Required variables with no default

### `AUDIT_AWS_EC2_ATK_ALERT_TO_KILL_RECIPIENT`:
  * description: 


## Required variables with default

### `AUDIT_AWS_EC2_ATK_ALLOW_EMPTY`:
  * description: receive empty reports?
  * default: false

### `AUDIT_AWS_EC2_ATK_SEND_ON`:
  * description: always or change
  * default: change

### `AUDIT_AWS_EC2_ATK_EXPECTED_TAGS`:
  * description: the tag we want to see on instances
  * default: "EXAMPLE_TAG_1", "EXAMPLE_TAG_2"

### `AUDIT_AWS_EC2_ATK_TAG_LOGIC`:
  * description: "or" or "and"
  * default: "and"

### `AUDIT_AWS_EC2_ATK_REGIONS`:
  * description: list of AWS regions to check. Default is all regions
  * default: us-east-1, us-east-2, us-west-1, us-west-2, eu-west-1


## Optional variables with default

### `AUDIT_AWS_EC2_ATK_OWNER_TAG`:
  * description: Enter an AWS tag whose value is an email address of owner of the ELB object. (Optional)
  * default: NOT_A_TAG


## Optional variables with no default

**None**

## Tags
1. Audit
1. Best Practices
1. Alert
1. EC2

## Categories
1. Audit



## Diagram
![diagram](https://raw.githubusercontent.com/CloudCoreo/audit-aws-ec2-atk/master/images/diagram.png "diagram")


## Icon
![icon](https://raw.githubusercontent.com/CloudCoreo/audit-aws-ec2-atk/master/images/icon.png "icon")

