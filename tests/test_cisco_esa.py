# Copyright 2019 Splunk, Inc.
#
# Use of this source code is governed by a BSD-2-clause-style
# license that can be found in the LICENSE-BSD2 file or at
# https://opensource.org/licenses/BSD-2-Clause

from jinja2 import Environment

from .sendmessage import *
from .splunkutils import *
from .timeutils import *

import pytest
env = Environment()

# Sun Aug 25 12:37:08 2019 CEF:0|Cisco|C100V Email Security Virtual Appliance|13.0.0-283|ESA_CONSOLIDATED_LOG_EVENT|Consolidated Log Event|5|cs6Label= SDRRepScore cs6=Tainted  deviceExternalId=42157574DD75FA3BD343-C964FC856529 ESAMID=1437 startTime=Sun Aug 25 12:35:39 2019 deviceInboundInterface=Inbound ESADMARCVerdict=Skipped dvc=10.10.4.8 ESAAttachmentDetails={'MSOLE2msword.docx':   {'AMP': {'Verdict': 'FILE UNKNOWN', 'fileHash': '917a35e8ffdd121c35b47a937dd4399539f0aa5b52a60fd038e0c4fdea78d357'},  'BodyScanner': {}}} ESAFriendlyFrom=demo@test.com deviceDirection=0 ESAMailFlowPolicy=ACCEPT suser=demo@tester.com cs1Label=MailPolicy cs1=default act=QUARANTINED ESAFinalActionDetails=To POLICY cs4Label=ExternalMsgID cs4=20190729112221.42958.40626@vm21esa0075.cs21 duser=demo@test.com ESAHeloIP=10.10.4.8  cfp1Label=SBRSScore, cfp1=1.1 ESASDRDomainAge=23 years 19 days cs3Label=SDRThreatCategory cs3=mal ESASPFVerdict=Fail sourceHostName=demo.cisco.com ESASenderGroup=UNKNOWNLIST sourceAddress=10.10.4.8 ESAICID=190746 cs5Label=ESAMsgLanguage cs5=English msg=This is a sample subject cs2Label=GeoLocation cs2=India ESAMsgTooBigFromSender=false ESARateLimitedIP=10.10.2.75 ESADHASource=10.10.2.75 ESAHeloDomain=test.com ESATLSOutConnStatus=Failure ESATLSOutProtocol=TLSv1.2 ESATLSOutCipher=ECDHE-RSA-AES128-GCM-SHA256 ESATLSInConnStatus=Failure ESATLSInProtocol=TLSv1.2 ESATLSInCipher=ECDHE-RSA-AES128-GCM-SHA256 ESADKIMVerdict=Pass ESAReplyTo=demo@test.com ESAASVerdict=NOT EVALUATED ESAAMPVerdict=NOT EVALUATED ESAAVVerdict=NOT EVALUATED ESAGMVerdict=NOT EVALUATED ESACFVerdict=NOT EVALUATED ESAOFVerdict=NOT EVALUATED ESADLPVerdict=NOT EVALUATED ESAURLDetails={url1:{expanded_url:<>, category:<>, wbrs_score:<>, in_attachment:<>, Attachment_with_url:<>,},url2:{…}} ESAMARAction= {action:<>;succesful_rcpts=<>;failed _recipients=<>;filename=<>} Message Filters Verdict=NOT EVALUATED ESADCID=199 EndTime=Mon Jul 29 09:55:07 2019 ESADaneStatus=success ESADaneHost=testdomain.com
def test_cisco_esa_cef(record_property, setup_wordlist, get_host_key, setup_splunk, setup_sc4s):
    host = get_host_key

    dt = datetime.datetime.now()
    iso, bsd, time, date, tzoffset, tzname, epoch = time_operations(dt)

    # Tune time functions
    epoch = epoch[:-7]

    mt = env.from_string(
        "{{ bsd }}{{ host }} CEF:0|Cisco|C100V Email Security Virtual Appliance|13.0.0-283|ESA_CONSOLIDATED_LOG_EVENT|Consolidated Log Event|5|cs6Label= SDRRepScore cs6=Tainted  deviceExternalId=42157574DD75FA3BD343-C964FC856529 ESAMID=1437 startTime=Sun Aug 25 12:35:39 2019 deviceInboundInterface=Inbound ESADMARCVerdict=Skipped dvc=10.10.4.8 ESAAttachmentDetails={'MSOLE2msword.docx':   {'AMP': {'Verdict': 'FILE UNKNOWN', 'fileHash': '917a35e8ffdd121c35b47a937dd4399539f0aa5b52a60fd038e0c4fdea78d357'},  'BodyScanner': {}}} ESAFriendlyFrom=demo@test.com deviceDirection=0 ESAMailFlowPolicy=ACCEPT suser=demo@tester.com cs1Label=MailPolicy cs1=default act=QUARANTINED ESAFinalActionDetails=To POLICY cs4Label=ExternalMsgID cs4=20190729112221.42958.40626@vm21esa0075.cs21 duser=demo@test.com ESAHeloIP=10.10.4.8  cfp1Label=SBRSScore, cfp1=1.1 ESASDRDomainAge=23 years 19 days cs3Label=SDRThreatCategory cs3=mal ESASPFVerdict=Fail sourceHostName=demo.cisco.com ESASenderGroup=UNKNOWNLIST sourceAddress=10.10.4.8 ESAICID=190746 cs5Label=ESAMsgLanguage cs5=English msg=This is a sample subject cs2Label=GeoLocation cs2=India ESAMsgTooBigFromSender=false ESARateLimitedIP=10.10.2.75 ESADHASource=10.10.2.75 ESAHeloDomain=test.com ESATLSOutConnStatus=Failure ESATLSOutProtocol=TLSv1.2 ESATLSOutCipher=ECDHE-RSA-AES128-GCM-SHA256 ESATLSInConnStatus=Failure ESATLSInProtocol=TLSv1.2 ESATLSInCipher=ECDHE-RSA-AES128-GCM-SHA256 ESADKIMVerdict=Pass ESAReplyTo=demo@test.com ESAASVerdict=NOT EVALUATED ESAAMPVerdict=NOT EVALUATED ESAAVVerdict=NOT EVALUATED ESAGMVerdict=NOT EVALUATED ESACFVerdict=NOT EVALUATED ESAOFVerdict=NOT EVALUATED ESADLPVerdict=NOT EVALUATED ESAURLDetails={url1:{expanded_url:<>, category:<>, wbrs_score:<>, in_attachment:<>, Attachment_with_url:<>,},url2:{…}} ESAMARAction= {action:<>;succesful_rcpts=<>;failed _recipients=<>;filename=<>} Message Filters Verdict=NOT EVALUATED ESADCID=199 EndTime=Mon Jul 29 09:55:07 2019 ESADaneStatus=success ESADaneHost=testdomain.com")
    message = mt.render(bsd=bsd, host=host)

    sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])

    st = env.from_string(
        "search index=email _time={{ epoch }} sourcetype=\"cisco:esa:cef\" host=\"{{ host }}\"")
    search = st.render(epoch=epoch, host=host)

    resultCount, eventCount = splunk_single(setup_splunk, search)

    record_property("host", host)
    record_property("resultCount", resultCount)
    record_property("message", message)

    assert resultCount == 1
