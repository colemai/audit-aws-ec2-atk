###########################################
# User Visible Rule Definitions
###########################################

# defines as the alert any EC2 instances that were launched more than 5 minutes ago
# this set will be post-processed by the jsrunner below to examine the tags - nothing is directly
# alerted on from this definition
#
coreo_aws_rule "ec2-get-all-instances-older-than" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/mydoc_ec2-alert-to-kill.html"
  display_name "Alert to Kill"
  description "EC2 instance was launched within the last 5 minutes that violates tag policy (does not have the necessary tags)."
  category "Policy"
  suggested_action "Review instance tags and terminate the instance if it does not comply to tagging policy."
  level "Warning"
  objectives ["instances"]
  audit_objects ["reservation_set.instances_set.launch_time"]
  operators ["<"]
  raise_when ["5.minutes.ago"]
  id_map "object.reservation_set.instances_set.instance_id"
end

###########################################
# Compsite-Internal Resources follow until end
#   (Resources used by the system for execution and display processing)
###########################################

# this resource simply executes the alert that was defined above
#
coreo_aws_rule_runner_ec2 "advise-ec2-atk" do
  rules ["ec2-get-all-instances-older-than"]
  action :run
  regions ${AUDIT_AWS_EC2_ATK_REGIONS}
end


coreo_uni_util_jsrunner "jsrunner-process-suppression" do
  action :run
  provide_composite_access true
  json_input '{"violations":COMPOSITE::coreo_aws_rule_runner_ec2.advise-ec2-atk.report}'
  packages([
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }       ])
  function <<-EOH
  const fs = require('fs');
  const yaml = require('js-yaml');
  let suppression;
  try {
      suppression = yaml.safeLoad(fs.readFileSync('./suppression.yaml', 'utf8'));
  } catch (e) {
  }
  coreoExport('suppression', JSON.stringify(suppression));
  const violations = json_input.violations;
  const result = {};
  let file_date = null;
  const regionKeys = Object.keys(violations);
  regionKeys.forEach(region => {
      result[region] = {};
      const violationKeys = Object.keys(violations[region]);
      violationKeys.forEach(violator_id => {
          result[region][violator_id] = {};
          result[region][violator_id].tags = violations[region][violator_id].tags;
          result[region][violator_id].violations = {};
          const ruleKeys = Object.keys(violations[region][violator_id].violations);
          ruleKeys.forEach(rule_id => {
              let is_violation = true;
              result[region][violator_id].violations[rule_id] = violations[region][violator_id].violations[rule_id];
              const suppressionRuleKeys = Object.keys(suppression);
              suppressionRuleKeys.forEach(suppress_rule_id => {
                  const suppressionViolatorNum = Object.keys(suppression[suppress_rule_id]);
                  suppressionViolatorNum.forEach(suppress_violator_num => {
                      const suppressViolatorIdKeys = Object.keys(suppression[suppress_rule_id][suppress_violator_num]);
                      suppressViolatorIdKeys.forEach(suppress_violator_id => {
                          file_date = null;
                          let suppress_obj_id_time = suppression[suppress_rule_id][suppress_violator_num][suppress_violator_id];
                          if (rule_id === suppress_rule_id) {
  
                              if (violator_id === suppress_violator_id) {
                                  const now_date = new Date();
  
                                  if (suppress_obj_id_time === "") {
                                      suppress_obj_id_time = new Date();
                                  } else {
                                      file_date = suppress_obj_id_time;
                                      suppress_obj_id_time = file_date;
                                  }
                                  let rule_date = new Date(suppress_obj_id_time);
                                  if (isNaN(rule_date.getTime())) {
                                      rule_date = new Date(0);
                                  }
  
                                  if (now_date <= rule_date) {
  
                                      is_violation = false;
  
                                      result[region][violator_id].violations[rule_id]["suppressed"] = true;
                                      if (file_date != null) {
                                          result[region][violator_id].violations[rule_id]["suppressed_until"] = file_date;
                                          result[region][violator_id].violations[rule_id]["suppression_expired"] = false;
                                      }
                                  }
                              }
                          }
                      });
                  });
              });
              if (is_violation) {
  
                  if (file_date !== null) {
                      result[region][violator_id].violations[rule_id]["suppressed_until"] = file_date;
                      result[region][violator_id].violations[rule_id]["suppression_expired"] = true;
                  } else {
                      result[region][violator_id].violations[rule_id]["suppression_expired"] = false;
                  }
                  result[region][violator_id].violations[rule_id]["suppressed"] = false;
              }
          });
      });
  });
  
  callback(result);
  EOH
end

coreo_uni_util_jsrunner "jsrunner-process-table" do
  action :run
  provide_composite_access true
  json_input '{"violations":COMPOSITE::coreo_aws_rule_runner_ec2.advise-ec2-atk.report}'
  packages([
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }       ])
  function <<-EOH
    var fs = require('fs');
    var yaml = require('js-yaml');
    try {
        var table = yaml.safeLoad(fs.readFileSync('./table.yaml', 'utf8'));
    } catch (e) {
    }
    coreoExport('table', JSON.stringify(table));
    callback(table);
  EOH
end


# this is doing the owner tag parsing only - it needs to also include the kill tag logic (and/or)
#
coreo_uni_util_jsrunner "tags-to-notifiers-array-ec2-atk" do
  action :run
  data_type "json"
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.7.0"
               }       ])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "table": COMPOSITE::coreo_uni_util_jsrunner.jsrunner-process-table.return,
                "violations": COMPOSITE::coreo_uni_util_jsrunner.jsrunner-process-suppression.return}'
  function <<-EOH
  
function setTagsLengthFromEc2Logic(EC2_LOGIC, EXPECTED_TAGS) {
    let tagLength = EXPECTED_TAGS.length;
    if(EC2_LOGIC === 'or') {
        tagLength = 1;
    }
    return tagLength;
}

function getSimilarNumber(tags, EXPECTED_TAGS) {
    let similarNumber = 0;
    EXPECTED_TAGS.forEach(EXPECTED_TAG => {
        EXPECTED_TAG = EXPECTED_TAG.toLowerCase();
        tags.forEach(tagElem => {
            if(tagElem.hasOwnProperty('tag')) {
                const tagToLowerCase = tagElem.tag['key'].toLowerCase();
                if(tagToLowerCase == EXPECTED_TAG) {
                    similarNumber++;
                }
            } else {
                const tagToLowerCase = tagElem['key'].toLowerCase();
                if(tagToLowerCase == EXPECTED_TAG) {
                    similarNumber++;
                }
            }
        });
    });
    console.log(similarNumber);
    if(EXPECTED_TAGS.length === 0) {
        similarNumber = 0;
    }
    return similarNumber;
}

const JSON_INPUT = json_input;
const NO_OWNER_EMAIL = "${AUDIT_AWS_EC2_ATK_RECIPIENT}";
const OWNER_TAG = "${AUDIT_AWS_EC2_ATK_OWNER_TAG}";
const ALLOW_EMPTY = "${AUDIT_AWS_EC2_ATK_ALLOW_EMPTY}";
const SEND_ON = "${AUDIT_AWS_EC2_ATK_SEND_ON}";
const SHOWN_NOT_SORTED_VIOLATIONS_COUNTER = true;


const EXPECTED_TAGS = [${AUDIT_AWS_EC2_ATK_EXPECTED_TAGS}];
const EC2_LOGIC_LENGTH = setTagsLengthFromEc2Logic("${AUDIT_AWS_EC2_ATK_TAG_LOGIC}", EXPECTED_TAGS);


const sortFuncForViolationAuditPanel = function sortViolationFunc(JSON_INPUT) {
    let regions = JSON_INPUT['violations'];
    let counterForViolations = 0;
    let counterForSortedViolations = 0;
    const regionKeys = Object.keys(regions);
    regionKeys.forEach(regionKey => {
      const violationKeys = Object.keys(regions[regionKey]);
      violationKeys.forEach(violationKey => {
          const alertKeys = Object.keys(regions[regionKey][violationKey].violations);
          const tags = regions[regionKey][violationKey].tags;
          const similarNumber = getSimilarNumber(tags, EXPECTED_TAGS)
          alertKeys.forEach(alertKey => {
              if(similarNumber >= EC2_LOGIC_LENGTH) {
                  delete regions[regionKey][violationKey]['violations'][alertKey];
                  counterForSortedViolations--;
                  if (Object.keys(regions[regionKey][violationKey]['violations']).length === 0) {
                      delete regions[regionKey][violationKey];
                  }
              }
              counterForViolations++;
              counterForSortedViolations++;
          });
      });
    });
      

    JSON_INPUT['counterForViolations'] = counterForViolations.toString();
    JSON_INPUT['counterForSortedViolations'] = counterForSortedViolations.toString();
    console.log(JSON_INPUT);
    return JSON_INPUT;
};

const sortFuncForHTMLReport = function htmlSortFunc(JSON_INPUT) {
    let regions = JSON_INPUT['violations'];
    let counterForViolations = 0;
    let counterForSortedViolations = 0;
    const regionKeys = Object.keys(regions);
    regionKeys.forEach(regionKey => {
      const violationKeys = Object.keys(regions[regionKey]);
      violationKeys.forEach(violationKey => {
          const alertKeys = Object.keys(regions[regionKey][violationKey].violations);
          const tags = regions[regionKey][violationKey].tags;
          const similarNumber = getSimilarNumber(tags, EXPECTED_TAGS)
          alertKeys.forEach(alertKey => {
              if(similarNumber >= EC2_LOGIC_LENGTH) {
                  delete regions[regionKey][violationKey]['violations'][alertKey];
                  counterForSortedViolations--;
                  if (Object.keys(regions[regionKey][violationKey]['violations']).length === 0) {
                      delete regions[regionKey][violationKey];
                  }
              }
              counterForViolations++;
              counterForSortedViolations++;
          });
      });
    });
    JSON_INPUT['counterForViolations'] = counterForViolations;
    JSON_INPUT['counterForSortedViolations'] = counterForSortedViolations;
    console.log(JSON_INPUT);
    return JSON_INPUT;
};

const VARIABLES = { NO_OWNER_EMAIL, OWNER_TAG, 
    ALLOW_EMPTY, SEND_ON,
    SHOWN_NOT_SORTED_VIOLATIONS_COUNTER,
    sortFuncForViolationAuditPanel, sortFuncForHTMLReport,};

const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');
const AuditEC2ATK = new CloudCoreoJSRunner(JSON_INPUT, VARIABLES);
const notifiers = AuditEC2ATK.getNotifiers();
const violations = JSON.stringify(AuditEC2ATK.getJSONForAuditPanel());
callback(notifiers);
  EOH
end

# Send ec2-atk for email
coreo_uni_util_notify "advise-ec2-atk-to-tag-values" do
  action :${AUDIT_AWS_EC2_ATK_HTML_REPORT}
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-ec2-atk.return'
end

coreo_uni_util_jsrunner "tags-rollup" do
  action :run
  data_type "text"
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-ec2-atk.return'
  function <<-EOH
var rollup_string = "";
let emailText = '';
let numberOfViolations = 0;
let numberOfInstances = 0;
for (var entry=0; entry < json_input.length; entry++) {
    if (json_input[entry]['endpoint']['to'].length) {
        numberOfInstances += parseInt(json_input[entry]['num_instances']);
        numberOfViolations += parseInt(json_input[entry]['num_violations']);
        emailText += "recipient: " + json_input[entry]['endpoint']['to'] + " - " + 'Violations: ' + json_input[entry]['num_violations'] + "\\n";
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
COMPOSITE::coreo_uni_util_jsrunner.tags-rollup.return
  '
  payload_type 'text'
  endpoint ({
      :to => '${AUDIT_AWS_EC2_ATK_RECIPIENT}', :subject => 'CloudCoreo ec2 rule results on PLAN::stack_name :: PLAN::name'
  })
end

coreo_uni_util_jsrunner "ec2-runner-advise-no-tags-older-than-kill-all-script" do
  action :run
  data_type "text"
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.7.0"
               }       ])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "table": COMPOSITE::coreo_uni_util_jsrunner.jsrunner-process-table.return,
                "violations": COMPOSITE::coreo_uni_util_jsrunner.jsrunner-process-suppression.return}'
  function <<-EOH

function setTagsLengthFromEc2Logic(EC2_LOGIC, EXPECTED_TAGS) {
    let tagLength = EXPECTED_TAGS.length;
    if(EC2_LOGIC === 'or') {
        tagLength = 1;
    }
    return tagLength;
}

function getSimilarNumber(tags, EXPECTED_TAGS) {
    let similarNumber = 0;
    EXPECTED_TAGS.forEach(EXPECTED_TAG => {
        EXPECTED_TAG = EXPECTED_TAG.toLowerCase();
        tags.forEach(tagElem => {
            if(tagElem.hasOwnProperty('tag')) {
                const tagToLowerCase = tagElem.tag['key'].toLowerCase();
                if(tagToLowerCase == EXPECTED_TAG) {
                    similarNumber++;
                }
            } else {
                const tagToLowerCase = tagElem['key'].toLowerCase();
                if(tagToLowerCase == EXPECTED_TAG) {
                    similarNumber++;
                }
            }
        });
    });
    console.log(similarNumber);
    if(EXPECTED_TAGS.length === 0) {
        similarNumber = 0;
    }
    return similarNumber;
}

const JSON_INPUT = json_input;
const NO_OWNER_EMAIL = "${AUDIT_AWS_EC2_ATK_RECIPIENT}";
const OWNER_TAG = "${AUDIT_AWS_EC2_ATK_OWNER_TAG}";
const ALLOW_EMPTY = "${AUDIT_AWS_EC2_ATK_ALLOW_EMPTY}";
const SEND_ON = "${AUDIT_AWS_EC2_ATK_SEND_ON}";
const SHOWN_NOT_SORTED_VIOLATIONS_COUNTER = true;


const EXPECTED_TAGS = [${AUDIT_AWS_EC2_ATK_EXPECTED_TAGS}];
const EC2_LOGIC_LENGTH = setTagsLengthFromEc2Logic("${AUDIT_AWS_EC2_ATK_TAG_LOGIC}", EXPECTED_TAGS);


const sortFuncForViolationAuditPanel = function sortViolationFunc(JSON_INPUT) {
    let regions = JSON_INPUT['violations'];
    let counterForViolations = 0;
    let counterForSortedViolations = 0;
    const regionKeys = Object.keys(regions);
    regionKeys.forEach(regionKey => {
      const violationKeys = Object.keys(regions[regionKey]);
      violationKeys.forEach(violationKey => {
          const alertKeys = Object.keys(regions[regionKey][violationKey].violations);
          const tags = regions[regionKey][violationKey].tags;
          const similarNumber = getSimilarNumber(tags, EXPECTED_TAGS)
          alertKeys.forEach(alertKey => {
              if(similarNumber >= EC2_LOGIC_LENGTH) {
                  delete regions[regionKey][violationKey]['violations'][alertKey];
                  counterForSortedViolations--;
                  if (Object.keys(regions[regionKey][violationKey]['violations']).length === 0) {
                      delete regions[regionKey][violationKey];
                  }
              }
              counterForViolations++;
              counterForSortedViolations++;
          });
      });
    });
      

    JSON_INPUT['counterForViolations'] = counterForViolations.toString();
    JSON_INPUT['counterForSortedViolations'] = counterForSortedViolations.toString();
    console.log(JSON_INPUT);
    return JSON_INPUT;
};

const sortFuncForHTMLReport = function htmlSortFunc(JSON_INPUT) {
    let regions = JSON_INPUT['violations'];
    let counterForViolations = 0;
    let counterForSortedViolations = 0;
    const regionKeys = Object.keys(regions);
    regionKeys.forEach(regionKey => {
      const violationKeys = Object.keys(regions[regionKey]);
      violationKeys.forEach(violationKey => {
          const alertKeys = Object.keys(regions[regionKey][violationKey].violations);
          const tags = regions[regionKey][violationKey].tags;
          const similarNumber = getSimilarNumber(tags, EXPECTED_TAGS)
          alertKeys.forEach(alertKey => {
              if(similarNumber >= EC2_LOGIC_LENGTH) {
                  delete regions[regionKey][violationKey]['violations'][alertKey];
                  counterForSortedViolations--;
                  if (Object.keys(regions[regionKey][violationKey]['violations']).length === 0) {
                      delete regions[regionKey][violationKey];
                  }
              }
              counterForViolations++;
              counterForSortedViolations++;
          });
      });
    });
    JSON_INPUT['counterForViolations'] = counterForViolations;
    JSON_INPUT['counterForSortedViolations'] = counterForSortedViolations;
    console.log(JSON_INPUT);
    return JSON_INPUT;
};

const VARIABLES = { NO_OWNER_EMAIL, OWNER_TAG, 
    ALLOW_EMPTY, SEND_ON,
    SHOWN_NOT_SORTED_VIOLATIONS_COUNTER,
    sortFuncForViolationAuditPanel, sortFuncForHTMLReport,};

const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');
const AuditEC2ATK = new CloudCoreoJSRunner(JSON_INPUT, VARIABLES);
const HTMLKillScripts = AuditEC2ATK.getHTMLKillScripts(); 
callback(HTMLKillScripts)
  EOH
end

coreo_uni_util_variables "update-rule-runner" do
  action :set
  variables([
                {'COMPOSITE::coreo_aws_rule_runner_ec2.advise-ec2-atk.report' => 'COMPOSITE::coreo_uni_util_jsrunner.ec2-runner-advise-no-tags-older-than-kill-all-script.return'}
            ])
end

coreo_uni_util_notify "advise-ec2-notify-no-tags-older-than-kill-all-script" do
  action :${AUDIT_AWS_EC2_ATK_SHOWN_KILL_SCRIPTS}
  type 'email'
  allow_empty ${AUDIT_AWS_EC2_ATK_ALLOW_EMPTY}
  send_on "${AUDIT_AWS_EC2_ATK_SEND_ON}"
  payload 'COMPOSITE::coreo_uni_util_jsrunner.ec2-runner-advise-no-tags-older-than-kill-all-script.return'
  payload_type "html"
  endpoint ({
      :to => '${AUDIT_AWS_EC2_ATK_RECIPIENT}', :subject => 'Untagged EC2 Instances kill script: PLAN::stack_name :: PLAN::name'
  })
end
