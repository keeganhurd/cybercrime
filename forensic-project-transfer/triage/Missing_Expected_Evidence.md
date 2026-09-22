# Missing Expected Evidence

This note distinguishes absence from the downloaded ZIP parts from absence in the full Google Takeout. Only the ZIP files listed below were scanned; the case request states the full Takeout has 142 parts.

## ZIP files scanned
- takeout-20260602T071913Z-11-001.zip
- takeout-20260602T071913Z-13-001.zip
- takeout-20260602T071913Z-15-001.zip

## Expected services
- Access Log Activity: Yes present; inventory files=2; extracted files=2; evidence hits=0; direct access hits=0. Present in inventory/extraction, but no strict evidence hit was identified in first-pass hits.
- My Activity: Yes present; inventory files=263; extracted files=39; evidence hits=621; direct access hits=0. Present with evidence hits, but no Tier 1 direct-access hit after strict triage.
- Google Account: Yes present; inventory files=2; extracted files=2; evidence hits=0; direct access hits=0. Present in inventory/extraction, but no strict evidence hit was identified in first-pass hits.
- Alerts: Yes present; inventory files=1; extracted files=1; evidence hits=0; direct access hits=0. Present in inventory/extraction, but no strict evidence hit was identified in first-pass hits.
- Drive: Yes present; inventory files=171; extracted files=29; evidence hits=1; direct access hits=0. Present with evidence hits, but no Tier 1 direct-access hit after strict triage.
- Google Business Profile: Yes present; inventory files=2948; extracted files=1545; evidence hits=0; direct access hits=0. Present in inventory/extraction, but no strict evidence hit was identified in first-pass hits.
- Android Device Configuration Service: Yes present; inventory files=1; extracted files=1; evidence hits=0; direct access hits=0. Present in inventory/extraction, but no strict evidence hit was identified in first-pass hits.
- Chrome: Yes present; inventory files=12; extracted files=11; evidence hits=0; direct access hits=0. Present in inventory/extraction, but no strict evidence hit was identified in first-pass hits.
- Google Photos metadata: Yes present; inventory files=485; extracted files=243; evidence hits=0; direct access hits=0. Present in inventory/extraction, but no strict evidence hit was identified in first-pass hits.

## Interpretation
If a service is marked absent, it should be described as not yet searched because it is not present in the downloaded parts, not as proving no evidence exists.

## Recommended next parts to inspect/download
- Download or inspect all missing ZIP parts from the 142-part Takeout sequence, especially parts not currently present: everything other than the scanned `takeout-20260602T071913Z-11-001.zip`, `takeout-20260602T071913Z-13-001.zip`, and `takeout-20260602T071913Z-15-001.zip`.
- Prioritize ZIP parts whose manifest paths contain `Access Log Activity`, `Google Account`, `Alerts`, `My Activity`, `Drive`, `Google Business Profile`, `Android Device Configuration`, `Chrome`, or `Photos` metadata.
- If Google Takeout can be regenerated, request Account Activity, Security, My Activity, Drive, Chrome, Google Business Profile, and Google Photos metadata for April 19-26, 2024.
