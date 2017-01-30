audit-aws-ec2-atk
============================



## Description
This repo is designed to work with CloudCoreo.


## Hierarchy
![composite inheritance hierarchy](https://raw.githubusercontent.com/CloudCoreo/audit-aws-ec2-samples/master/images/hierarchy.png "composite inheritance hierarchy")



## Required variables with no default

**None**


## Required variables with default

### `AUDIT_AWS_EC2_ATK_ALLOW_EMPTY`:
  * description: Would you like to receive empty reports? Options - true / false. Default is false.
  * default: false

### `AUDIT_AWS_EC2_ATK_SEND_ON`:
  * description: Send reports always or only when there is a change? Options - always / change. Default is change.
  * default: change

### `AUDIT_AWS_EC2_ATK_EXPECTED_TAGS`:
  * description: What tag do you want to see on instances?
  * default: "EXAMPLE_TAG_1", "EXAMPLE_TAG_2"

### `AUDIT_AWS_EC2_ATK_TAG_LOGIC`:
  * description: "or" or "and"
  * default: or

### `AUDIT_AWS_EC2_ATK_HTML_REPORT`:
  * description: Would you like to send the AWS owner tag report(s)? Options - notify / nothing. Default is nothing.
  * default: nothing

### `AUDIT_AWS_EC2_ATK_ROLLUP_REPORT`:
  * description: Would you like to send a rollup EC2 Alert-to-Kill report? This is a short email that summarizes the number of checks performed and the number of violations found. Options - notify / nothing. Default is nothing.
  * default: nothing

### `AUDIT_AWS_EC2_ATK_SHOWN_KILL_SCRIPTS`:
  * description: Would you like to send a full EC2 Alert-to-Kill report? This is an email that details any violations found and includes a list of the violating cloud objects. Options - notify / nothing. Default is notify.
  * default: notify

### `AUDIT_AWS_EC2_ATK_REGIONS`:
  * description: List of AWS regions to check. Default is us-east-1,us-east-2,us-west-1,us-west-2,eu-west-1.
  * default: us-east-1, us-east-2, us-west-1, us-west-2, eu-west-1


## Optional variables with default

### `AUDIT_AWS_EC2_ATK_OWNER_TAG`:
  * description: Enter an AWS tag whose value is an email address of the owner of the EC2 object. (Optional)
  * default: NOT_A_TAG


## Optional variables with no default

### `AUDIT_AWS_EC2_ATK_RECIPIENT`:
  * description: Enter the email address(es) that will receive notifications. If more than one, separate each with a comma.

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

