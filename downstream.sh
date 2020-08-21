export SYSLOG="syslog-ng-3.28.1"
export SPLUNK_VERSION=8.0.4
export SPLUNK_PACKAGE=splunk-add-on-for-imperva-securesphere-waf
export SPLUNK_APP_ID=$(crudini --get downstream/$SPLUNK_PACKAGE/package/default/app.conf id name)
echo $SPLUNK_APP_ID
docker-compose -f docker-compose-downstream.yml build
docker-compose -f docker-compose-downstream.yml up -d splunk                
until docker-compose -f docker-compose-downstream.yml logs splunk | grep "Ansible playbook complete" ; do sleep 1; done
docker-compose -f docker-compose-downstream.yml up  --abort-on-container-exit test
docker container create --name dummy \
                    -v project_results:/work/test-results \
                    registry.access.redhat.com/ubi7/ubi
mkdir test-results || true
docker cp dummy:/work/test-results/test.xml test-results/$SPLUNK_PACKAGE.xml
