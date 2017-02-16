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


coreo_uni_util_variables "planwide" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.planwide.composite_name' => 'PLAN::stack_name'},
                {'COMPOSITE::coreo_uni_util_variables.planwide.plan_name' => 'PLAN::name'},
                {'COMPOSITE::coreo_uni_util_variables.planwide.results' => 'unset'},
                {'COMPOSITE::coreo_uni_util_variables.planwide.number_violations' => 'unset'}
            ])
end

coreo_aws_rule_runner_ec2 "advise-ec2-atk" do
  rules ["ec2-get-all-instances-older-than"]
  action :run
  regions ${AUDIT_AWS_EC2_ATK_REGIONS}
end


coreo_uni_util_variables "update-planwide-1" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.planwide.results' => 'COMPOSITE::coreo_aws_rule_runner_ec2.advise-ec2-atk.report'},
                {'COMPOSITE::coreo_uni_util_variables.planwide.number_violations' => 'COMPOSITE::coreo_aws_rule_runner_ec2.advise-ec2-atk.number_violations'},

            ])
end

coreo_uni_util_jsrunner "tags-to-notifiers-array-ec2-atk" do
  action :run
  data_type "json"
  provide_composite_access true
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.8.3"
               },
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }      ])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "violations": COMPOSITE::coreo_aws_rule_runner_ec2.advise-ec2-atk.report}'
  function <<-EOH
  

function setTableAndSuppression() {
  let table;
  let suppression;

  const fs = require('fs');
  const yaml = require('js-yaml');
  try {
      suppression = yaml.safeLoad(fs.readFileSync('./suppression.yaml', 'utf8'));
  } catch (e) {
      console.log("Error reading suppression.yaml file: " , e);
      suppression = {};
  }
  try {
      table = yaml.safeLoad(fs.readFileSync('./table.yaml', 'utf8'));
  } catch (e) {
      console.log("Error reading table.yaml file: ", e);
      table = {};
  }
  coreoExport('table', JSON.stringify(table));
  coreoExport('suppression', JSON.stringify(suppression));
  
  let alertListToJSON = "['ec2-get-all-instances-older-than']";
  let alertListArray = alertListToJSON.replace(/'/g, '"');
  json_input['alert list'] = alertListArray || [];
  json_input['suppression'] = suppression || [];
  json_input['table'] = table || {};
}


setTableAndSuppression();

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


const JSONReportAfterGeneratingSuppression = AuditEC2ATK.getJSONForAuditPanel();
const HTMLKillScripts = AuditEC2ATK.getHTMLKillScripts();

coreoExport('JSONReport', JSON.stringify(JSONReportAfterGeneratingSuppression));
coreoExport('HTMLKillScripts', JSON.stringify(HTMLKillScripts));


const notifiers = AuditEC2ATK.getNotifiers();

callback(notifiers);
  EOH
end




coreo_uni_util_variables "update-planwide-2" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.planwide.results' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-ec2-atk.JSONReport'},
                {'COMPOSITE::coreo_uni_util_variables.planwide.table' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-ec2-atk.table'}
            ])
end


coreo_uni_util_jsrunner "tags-rollup" do
  action :run
  data_type "text"
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-ec2-atk.return'
  function <<-EOH

const notifiers = json_input;

function setTextRollup() {
    let emailText = '';
    let numberOfViolations = 0;
    notifiers.forEach(notifier => {
        const hasEmail = notifier['endpoint']['to'].length;
        if(hasEmail) {
            numberOfViolations += parseInt(notifier['num_violations']);
            emailText += "recipient: " + notifier['endpoint']['to'] + " - " + "Violations: " + notifier['num_violations'] + "\\n";
        }
    });

    textRollup += 'Number of Violating Cloud Objects: ' + numberOfViolations + "\\n";
    textRollup += 'Rollup' + "\\n";
    textRollup += emailText;
}


let textRollup = '';
setTextRollup();

callback(textRollup);
  EOH
end

coreo_uni_util_notify "advise-ec2-atk-to-tag-values" do
  action((("${AUDIT_AWS_EC2_ATK_RECIPIENT}".length > 0)) ? :notify : :nothing)
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-ec2-atk.return'
end



coreo_uni_util_notify "advise-ec2-notify-no-tags-older-than-kill-all-script" do
  action((("${AUDIT_AWS_EC2_ATK_RECIPIENT}".length > 0) and ("${AUDIT_AWS_EC2_ATK_SHOWN_KILL_SCRIPTS}".eql?("notify"))) ? :notify : :nothing)
  type 'email'
  allow_empty ${AUDIT_AWS_EC2_ATK_ALLOW_EMPTY}
  send_on "${AUDIT_AWS_EC2_ATK_SEND_ON}"
  payload 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-ec2-atk.HTMLKillScripts'
  payload_type "html"
  endpoint ({
      :to => '${AUDIT_AWS_EC2_ATK_RECIPIENT}', :subject => 'Untagged EC2 Instances kill script: PLAN::stack_name :: PLAN::name'
  })
end


coreo_uni_util_notify "advise-atk-rollup" do
  action((("${AUDIT_AWS_EC2_ATK_RECIPIENT}".length > 0) and (! "${AUDIT_AWS_EC2_ATK_OWNER_TAG}".eql?("NOT_A_TAG"))) ? :notify : :nothing)
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

