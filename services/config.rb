
# defines as the alert any EC2 instances that were launched more than 5 minutes ago
# this set will be post-processed by the jsrunner below to examine the tags - nothing is directly
# alerted on from this definition
#
coreo_aws_advisor_alert "ec2-get-all-instances-older-than" do
  action :define
  service :ec2
  display_name "Alert to Kill"
  description "EC2 instance was launched within the last 5 minutes that violates tag policy (does not have the necessary tags)."
  category "Policy"
  suggested_action "Review instance tags and terminate the instance if it does not comply to tagging policy."
  level "Warning"
  objectives ["instances"]
  audit_objects ["reservation_set.instances_set.launch_time"]
  operators ["<"]
  alert_when ["5.minutes.ago"]
end

# this resource simply executes the alert that was defined above
#
coreo_aws_advisor_ec2 "advise-ec2-atk" do
  alerts ["ec2-get-all-instances-older-than"]
  action :advise
  regions ${AUDIT_AWS_EC2_ATK_REGIONS}
end

# this is doing the owner tag parsing only - it needs to also include the kill tag logic (and/or)
#
coreo_uni_util_jsrunner "tags-to-notifiers-array-ec2-atk" do
  action :run
  data_type "json"
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.3.7"
               }       ])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "number_of_instances": COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-atk.number_violations,
                "violations": COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-atk.report}'
  function <<-EOH
  
const json = json_input;
const NO_OWNER_EMAIL = "${AUDIT_AWS_EC2_ATK_RECIPIENT}";
const OWNER_TAG = "${AUDIT_AWS_EC2_ATK_OWNER_TAG}";
const ALLOW_EMPTY = "${AUDIT_AWS_EC2_ATK_ALLOW_EMPTY}";
const SEND_ON = "${AUDIT_AWS_EC2_ATK_SEND_ON}";
const AUDIT_NAME = 'ec2-atk';


const ARE_KILL_SCRIPTS_SHOWN = true;
const EC2_LOGIC = "${AUDIT_AWS_EC2_ATK_TAG_LOGIC}"; // you can choose 'and' or 'or';
const EXPECTED_TAGS = [${AUDIT_AWS_EC2_ATK_EXPECTED_TAGS}];
const WHAT_NEED_TO_SHOWN = {
    OBJECT_ID: {
        headerName: 'AWS Object ID',
        isShown: true,
    },
    REGION: {
        headerName: 'Region',
        isShown: true,
    },
    AWS_CONSOLE: {
        headerName: 'AWS Console',
        isShown: true,
    },
    TAGS: {
        headerName: 'Tags',
        isShown: true,
    },
    AMI: {
        headerName: 'AMI',
        isShown: false,
    },
    KILL_SCRIPTS: {
        headerName: 'Kill Cmd',
        isShown: false,
    }
};

const VARIABLES = {
    NO_OWNER_EMAIL,
    OWNER_TAG,
    AUDIT_NAME,
    ARE_KILL_SCRIPTS_SHOWN,
    EC2_LOGIC,
    EXPECTED_TAGS,
    WHAT_NEED_TO_SHOWN,
    ALLOW_EMPTY,
    SEND_ON
};

const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');
const AuditEC2ATK = new CloudCoreoJSRunner(json, VARIABLES);
const notifiers = JSON.stringify(AuditEC2ATK.getNotifiers());
const HTMLKillScripts = AuditEC2ATK.getHTMLKillScripts();
const violations = AuditEC2ATK.getSortedJSON();

coreoExport('HTMLKillScripts', HTMLKillScripts);
coreoExport('notifiers', notifiers);
callback(violations);
  EOH
end

coreo_uni_util_variables "update-advisor-output" do
  action :set
  variables([
       {'COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-atk.report.violations' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-ec2-atk.return'}
      ])
end

coreo_uni_util_jsrunner "notifiers-ec2-atk" do
  action :run
  data_type "json"
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.3.7"
               }       ])
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-ec2-atk.notifiers'
  function <<-EOH
callback(json_input);
  EOH
end

# Send ec2-atk for email
coreo_uni_util_notify "advise-ec2-atk-to-tag-values" do
  action :${AUDIT_AWS_EC2_ATK_HTML_REPORT}
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.notifiers-ec2-atk.return'
end

coreo_uni_util_notify "advise-ec2-notify-no-tags-older-than-kill-all-script" do
  action :${AUDIT_AWS_EC2_ATK_SHOWN_KILL_SCRIPTS}
  type 'email'
  allow_empty ${AUDIT_AWS_EC2_ATK_ALLOW_EMPTY}
  send_on "${AUDIT_AWS_EC2_ATK_SEND_ON}"
  payload 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-ec2-atk.HTMLKillScripts'
  payload_type "html"
  endpoint ({
      :to => '${AUDIT_AWS_EC2_ATK_RECIPIENT}', :subject => 'Untagged EC2 Instances kill script: PLAN::stack_name :: PLAN::name'
  })
end

coreo_uni_util_jsrunner "tags-rollup" do
  action :run
  data_type "text"
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.notifiers-ec2-atk.return'
  function <<-EOH
var rollup_string = "";
let emailText = '';
let numberOfViolations = 0;
let numberOfInstances = 0;
for (var entry=0; entry < json_input.length; entry++) {
    if (json_input[entry]['endpoint']['to'].length) {
        numberOfInstances += parseInt(json_input[entry]['num_instances']);
        numberOfViolations += parseInt(json_input[entry]['num_violations']);
        emailText += "recipient: " + json_input[entry]['endpoint']['to'] + " - " + "nViolations: " + json_input[entry]['num_violations'] + "\\n";
    }
}

let rollup = 'number of Instances: ' + numberOfInstances + "\\n";
rollup += 'number of Violations: ' + numberOfViolations + "\\n";
rollup += emailText;

rollup_string = rollup;
callback(rollup_string);
  EOH
end

coreo_uni_util_notify "advise-atk-rollup" do
  action :${AUDIT_AWS_EC2_ATK_ROLLUP_REPORT}
  type 'email'
  allow_empty ${AUDIT_AWS_EC2_ATK_ALLOW_EMPTY}
  send_on "${AUDIT_AWS_EC2_ATK_SEND_ON}"
  payload '
composite name: PLAN::stack_name
plan name: PLAN::name
number_of_checks: COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-atk.number_checks
number_violations_ignored: COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-atk.number_ignored_violations
COMPOSITE::coreo_uni_util_jsrunner.tags-rollup.return
  '
  payload_type 'text'
  endpoint ({
      :to => '${AUDIT_AWS_EC2_ATK_RECIPIENT}', :subject => 'CloudCoreo ec2 advisor alerts on PLAN::stack_name :: PLAN::name'
  })
end
