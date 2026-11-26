# Hosted workplace deployment review

## Responsibilities and evidence

The tenant normally determines why it processes workforce data and how long
it needs each record type. The operator runs the platform under the agreed
instructions. Confirm the actual controller and processor roles and any
independent processing purposes in the deployment agreement. Keep the signed
processor agreement and the approved instructions with the deployment review.
Record processing periods, data categories, security duties, rights assistance,
return and deletion duties, incident contacts and audit arrangements.
[GDPR Article 5](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng#art_5) · [GDPR Article 28](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng#art_28)

The operator maintains a record for each site and external service. Use the
inventory below to identify all locations where tenant data can be handled.
For each entry, record site and country, operator, authorized pools, named
subprocessor where applicable, replication destinations, retention, encryption
and key custodian. Record remote support origins, jump hosts, account owners
and escalation contacts. Attach the tenant's authorizations for subprocessors
and the notice and objection process when general written authorization is
used. Review onward transfers, including remote access, and document the
applicable transfer mechanism and location restrictions before enabling a path.
[GDPR Article 28](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng#art_28) · [GDPR Chapter V](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng#art_44)

| Component or path | Evidence to record |
| --- | --- |
| ARM, regional etcd, Keycloak and its database | Replica sites, failover destinations, authenticated endpoints, transport settings and disk encryption |
| Samba controllers and SYSVOL, compute and SMB members | Hosted profile, approved inventory and site proof, subscription policy, authorized and rejected assignments and fenced failover |
| Ceph and key services | OSD and replica placement, storage client ACLs, tested use of the encrypted data path, key custody and recovery permissions |
| Telemetry, activity and support logs | Endpoint locations, least-privilege readers, retention and expiration evidence, redacted test sample |
| Backups and restores | Independent target and key custodian, site and replica proof, archive expiry, restore isolation and replay of independent offboarding records |
| Remote support | Approved access origins, short-lived scoped identities, MFA where supported, approval and revocation evidence, privileged session audit |

## Operating procedures to exercise

1. Run the regional export as the tenant administrator before suspension.
   Include authorized directory and file exports as required by the request.
   Record the request, approver, scope, formats, checksums and delivery route.
   Verify a foreign request is denied. [Regional tenant export](README.md#hosted-workplace-placement-and-audit-retention)
2. For offboarding, record the frozen tenant scope and the controller's return,
   deletion and any retention decisions. Revoke access and credentials,
   withdraw workload assignments, verify the worker acknowledgements or
   fence unreachable workers, and track deletion of live data and the
   latest expiry of copies in each backup system. Retain only the evidence
   necessary to prove the actions and comply with applicable obligations.
   Record the decision UUID and completion evidence for each authorized
   Azure Files or managed SMB share deletion. [Hosted file deletion](README.md#hosted-workplace-placement-and-audit-retention)
3. Keep the authoritative deletion ledger independent of the backups it governs.
   Restore into an isolated environment. Verify that regional startup replays
   subsequent suspensions before accepting requests. Verify denied identities,
   service shutdown, deletion of recovered data and the approval to reopen.
4. Exercise the incident route. Record discovery time, affected scope, initial
   containment, tenant notice and follow-up. The processor notifies the
   controller without undue delay after awareness of a personal data breach.
   The controller assesses whether notification to the supervisory authority
   and data subjects is required and records the decision.

[GDPR Articles 15–20](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng#art_15) · [GDPR Articles 32–34](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng#art_32)

Use tenant and resource identifiers from synthetic fixtures in shared evidence.
Exclude credentials, encryption keys, user data and unrelated identifiers.
Record the tested revision, configuration identifiers, profile, dated results,
deployment owner and reviewer. The repository's hosted-workplace lab verifies
activity retention, placement, recovery, offboarding replay and the regional
tenant export. The review also requires
deployment evidence from the actual storage, backup and support infrastructure.
