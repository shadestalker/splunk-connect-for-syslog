# Copyright 2019 Splunk, Inc.
#
# Use of this source code is governed by a BSD-2-clause-style
# license that can be found in the LICENSE-BSD2 file or at
# https://opensource.org/licenses/BSD-2-Clause
import random

from jinja2 import Environment

from .sendmessage import *
from .splunkutils import *
from .timeutils import *
import pytest

env = Environment()

testdata_amp = [
    '{{mark}} {{ bsd }} {{ host }} {{ app }}: Mon Aug 10 10:04:39 2020 Info:  File uploaded for analysis. SHA256: 0172405634de890c729397377d975f059ef0becc3d072e8181d875a58eab1861, file name: Agenda_March15v3.doc',
    '{{mark}} {{ bsd }} {{ host }} {{ app }}: Mon Aug 10 09:38:44 2020 Info:  File not uploaded for analysis.  MID = 357876 File SHA256[d7e25b63dcfe76d5528188fc801b847b4a98d6ad7234a3b2d93725d94b010e77] file mime[application/pdf] Reason: Analysis request is takenup',
    '{{mark}} {{ bsd }} {{ host }} {{ app }}: Mon Aug 10 09:41:02 2020 Info:  Response received for file reputation query from Cloud. File Name = \'tqps.rtf\', MID = 166267, Disposition = MALICIOUS, Malware = W32.C78352D892-95.SBX.TG,  Reputation Score = 1, sha256 = 756a0c3fc7d82abb243795751174053f106b7b54e431778068fa7920064268e0, upload_action = 1',
    '{{mark}} {{ bsd }} {{ host }} {{ app }}: Mon Aug 10 09:45:53 2020 Info:  File reputation query initiating. File Name = \'Nursing Management Agenda.pdf\', MID = 852867, File Size = 189 bytes, File Type = application/pdf',
];

@pytest.mark.parametrize("event", testdata_amp)
def test_cisco_esa_amp(record_property, setup_wordlist, setup_splunk, setup_sc4s, event):
    host = "cisco_esa"

    dt = datetime.datetime.now()
    iso, bsd, time, date, tzoffset, tzname, epoch = time_operations(dt)

    # Tune time functions
    epoch = epoch[:-7]

    mt = env.from_string(event + "\n")
    message = mt.render(mark="<111>", bsd=bsd, host=host, app='ESA')

    sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])

    st = env.from_string(
        'search index=main _time={{ epoch }} sourcetype="cisco:esa:amp" host="{{ host }}"'
    )
    search = st.render(epoch=epoch, host=host)

    resultCount, eventCount = splunk_single(setup_splunk, search)

    record_property("host", host)
    record_property("resultCount", resultCount)
    record_property("message", message)

    assert resultCount == 4
