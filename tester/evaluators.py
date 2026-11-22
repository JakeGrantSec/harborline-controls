"""Evaluates C-01 to C-07 against the pass criteria in controls/controls.yaml.

Each control's pass criteria are split into separate checks. Every check
records the population it tested, the resources left out and why, and the
evidence files it used. Thresholds, tags and approved lists come from the
control library; ages are measured from the collection time in the manifest.

Only verified evidence (tester/integrity.py) and the control library are read.
"""

import csv
import fnmatch
import io
import re
from dataclasses import dataclass, field

from .checks import (FAIL, NOT_TESTED, PASS, Check, age_days, as_list, items_text, parse_time,
                     policy_document, statements)


class Context:
    def __init__(self, evidence, library, manifest):
        self.ev = evidence
        self.library = library
        self.manifest = manifest
        self.collected_at = parse_time(manifest.get("collection_started_at"))
        arn = (manifest.get("caller_identity") or {}).get("Arn") or ""
        parts = arn.split(":")
        self.caller_arn = arn
        self.partition = parts[1] if len(parts) > 5 and parts[1] else "aws"
        self.account_id = parts[4] if len(parts) > 5 else ""
        self.region = manifest.get("aws_region") or ""
        self.scope_tag = library.scope_tag
        self.audit_tag = library.audit_log_tag
        self.thresholds = library.thresholds

    def tag_text(self, tag):
        return f"{tag.key}={tag.value}"

    def threshold(self, name):
        value = self.thresholds.get(name)
        if value is None:
            raise KeyError(f"controls.yaml scope.thresholds has no {name}")
        return value


# --- Inventories (populations selected by tag) ----------------------------------


@dataclass
class Store:
    kind: str
    name: str
    tags: dict = None          # None when the tags could not be read
    note: str = ""             # why the tags are unknown
    region: str = ""
    ident: str = ""
    data: dict = None
    evidence: list = field(default_factory=list)

    @property
    def label(self):
        return f"{self.kind} {self.name}"


def _list_gaps(items, what, operation):
    gaps = []
    if not items:
        gaps.append(f"no {operation} output in the evidence, so the {what} population is unknown")
    for item in items:
        if item.error:
            gaps.append(f"{operation} returned {item.error}, so the {what} list may be incomplete")
    return gaps


def bucket_inventory(ctx, control):
    lists = ctx.ev.find(control, "s3", "ListBuckets")
    gaps = _list_gaps(lists, "bucket", "ListBuckets")
    regions = {}
    for item in lists:
        for bucket in (item.data() or {}).get("Buckets") or [] if not item.error else []:
            regions.setdefault(bucket.get("Name"), bucket.get("BucketRegion") or ctx.region)
    stores = []
    for name, region in regions.items():
        store = Store("bucket", name, region=region)
        tag_items = ctx.ev.find(control, "s3", "GetBucketTagging", Bucket=name)
        store.evidence = tag_items
        if not tag_items:
            store.note = "no GetBucketTagging output"
        elif tag_items[0].error == "NoSuchTagSet":
            store.tags = {}
        elif tag_items[0].error:
            store.note = f"GetBucketTagging returned {tag_items[0].error}"
        else:
            store.tags = {t.get("Key"): t.get("Value") for t in (tag_items[0].data() or {}).get("TagSet") or []}
        stores.append(store)
    return stores, gaps, lists


def table_inventory(ctx, control):
    lists = ctx.ev.find(control, "dynamodb", "ListTables")
    gaps = _list_gaps(lists, "table", "ListTables")
    names = []
    for item in lists:
        if not item.error:
            names.extend((item.data() or {}).get("TableNames") or [])
    stores = []
    for name in dict.fromkeys(names):
        store = Store("table", name)
        described = ctx.ev.find(control, "dynamodb", "DescribeTable", TableName=name)
        store.evidence = list(described)
        if not described or described[0].error:
            store.note = f"DescribeTable returned {described[0].error}" if described else "no DescribeTable output"
            stores.append(store)
            continue
        store.data = (described[0].data() or {}).get("Table") or {}
        arn = store.data.get("TableArn")
        tag_items = ctx.ev.find(control, "dynamodb", "ListTagsOfResource", ResourceArn=arn)
        store.evidence.extend(tag_items)
        if not tag_items:
            store.note = "no ListTagsOfResource output"
        elif any(i.error for i in tag_items):
            store.note = f"ListTagsOfResource returned {next(i.error for i in tag_items if i.error)}"
        else:
            store.tags = {}
            for item in tag_items:
                store.tags.update({t.get("Key"): t.get("Value") for t in (item.data() or {}).get("Tags") or []})
        stores.append(store)
    return stores, gaps, lists


def api_inventory(ctx, control):
    lists = ctx.ev.find(control, "apigateway", "GetRestApis")
    gaps = _list_gaps(lists, "REST API", "GetRestApis")
    stores = []
    for item in lists:
        if item.error:
            continue
        for api in (item.data() or {}).get("items") or []:
            stores.append(Store("REST API", f"{api.get('name')} ({api.get('id')})", tags=api.get("tags") or {},
                                ident=api.get("id"), data=api, evidence=[item]))
    return stores, gaps, lists


def in_scope(ctx, check, inventory, exclude_audit=False, audit_reason=""):
    """Record exclusions and gaps on the check; return the in-scope stores."""
    stores, gaps, lists = inventory
    check.use(*lists)
    for gap in gaps:
        check.gap(gap)
    selected = []
    for store in stores:
        if store.tags is None:
            check.exclude(store.label, f"scope unknown: {store.note}", store.evidence)
            check.gap(f"the tags of {store.label} could not be read ({store.note}), so it may be in scope")
        elif not ctx.scope_tag.matches(store.tags):
            check.exclude(store.label, f"not tagged {ctx.tag_text(ctx.scope_tag)}", store.evidence)
        elif exclude_audit and ctx.audit_tag.matches(store.tags):
            check.exclude(store.label, f"tagged {ctx.tag_text(ctx.audit_tag)}: {audit_reason}", store.evidence)
        else:
            check.use(*store.evidence)
            selected.append(store)
    return selected


def api_methods(ctx, control, check, api):
    """[(label, GetMethod item or None)] for every method listed by GetResources."""
    pages = ctx.ev.find(control, "apigateway", "GetResources", restApiId=api.ident)
    check.use(*pages)
    if not pages:
        check.gap(f"no GetResources output for {api.label}, so its methods are unknown")
    methods = []
    for page in pages:
        if page.error:
            check.gap(f"GetResources for {api.label} returned {page.error}; its method list may be incomplete")
            continue
        for resource in (page.data() or {}).get("items") or []:
            for http_method in sorted(resource.get("resourceMethods") or {}):
                found = ctx.ev.find(control, "apigateway", "GetMethod", restApiId=api.ident,
                                    resourceId=resource.get("id"), httpMethod=http_method)
                label = f"{api.name} {http_method} {resource.get('path')}"
                methods.append((label, found[0] if found else None))
    return methods


# --- C-01 Encryption at rest -----------------------------------------------------

KMS_ALGORITHMS = ("aws:kms", "aws:kms:dsse")


def _key_lookup(ctx, control, key_id, region):
    found = ctx.ev.find(control, "kms", "DescribeKey", KeyId=key_id)
    same_region = [i for i in found if i.request.get("region") == region]
    return (same_region or found or [None])[0]


def evaluate_c01(ctx):
    c = "C-01"
    audit_reason = "excluded from C-01 by its scope and governed by C-03"
    c1 = Check("C-01.1", "Every in-scope S3 bucket's default encryption uses an AWS KMS key (SSE-KMS or DSSE-KMS), "
                         "not S3 managed keys.")
    c2 = Check("C-01.2", "Every in-scope DynamoDB table is encrypted with an AWS KMS key, not the default AWS owned key.")
    c3 = Check("C-01.3", "Every KMS key used by an in-scope store was found and is either AWS managed or customer managed.")
    c4 = Check("C-01.4", "Every customer-managed KMS key used by an in-scope store has automatic key rotation enabled.")

    buckets = bucket_inventory(ctx, c)
    tables = table_inventory(ctx, c)
    for check in (c3, c4):
        in_scope(ctx, check, buckets, True, audit_reason)
        in_scope(ctx, check, tables, True, audit_reason)

    keys = {}  # (key id, region) -> [store labels]
    for bucket in in_scope(ctx, c1, buckets, True, audit_reason):
        found = ctx.ev.find(c, "s3", "GetBucketEncryption", Bucket=bucket.name)
        if not found:
            c1.add(bucket.label, NOT_TESTED, "no GetBucketEncryption output")
            continue
        item = found[0]
        if item.error == "ServerSideEncryptionConfigurationNotFoundError":
            c1.add(bucket.label, FAIL, "no default encryption configuration", [item])
            continue
        if item.error:
            c1.add(bucket.label, NOT_TESTED, f"GetBucketEncryption returned {item.error}", [item])
            continue
        rules = ((item.data() or {}).get("ServerSideEncryptionConfiguration") or {}).get("Rules") or []
        defaults = [r.get("ApplyServerSideEncryptionByDefault") or {} for r in rules]
        algorithms = [d.get("SSEAlgorithm") for d in defaults]
        kms = [d for d in defaults if d.get("SSEAlgorithm") in KMS_ALGORITHMS]
        if kms:
            key = kms[0].get("KMSMasterKeyID") or "alias/aws/s3"
            keys.setdefault((key, bucket.region), []).append(bucket.label)
            c1.add(bucket.label, PASS, f"{kms[0]['SSEAlgorithm']} with key {key}", [item])
        else:
            shown = ", ".join(a or "none" for a in algorithms) or "none"
            c1.add(bucket.label, FAIL, f"default encryption is {shown} (AES256 means S3 managed keys), not KMS", [item])

    for table in in_scope(ctx, c2, tables, True, audit_reason):
        sse = (table.data or {}).get("SSEDescription")
        if not sse:
            c2.add(table.label, FAIL, "no SSEDescription, which means the default AWS owned key", table.evidence)
        elif sse.get("SSEType") != "KMS":
            c2.add(table.label, FAIL, f"SSEType is {sse.get('SSEType')}, not KMS", table.evidence)
        elif sse.get("Status") != "ENABLED":
            c2.add(table.label, NOT_TESTED, f"KMS encryption status is {sse.get('Status')}, not ENABLED",
                   table.evidence)
        elif not sse.get("KMSMasterKeyArn"):
            c2.add(table.label, NOT_TESTED, "KMS encryption with no key ARN recorded", table.evidence)
        else:
            key = sse["KMSMasterKeyArn"]
            region = key.split(":")[3] if key.startswith("arn:") and len(key.split(":")) > 3 else ctx.region
            keys.setdefault((key, region), []).append(table.label)
            c2.add(table.label, PASS, f"KMS encryption with key {key}", table.evidence)

    untested = [p["item"] for p in c1.population + c2.population if p["result"] == NOT_TESTED]
    if c1.gaps or c2.gaps or untested:
        for check in (c3, c4):
            check.gap("the key of some in-scope stores is unknown (see C-01.1 and C-01.2)")
    if not keys:
        c3.allow_empty("No in-scope store uses a KMS key, so there is no key to check (see C-01.1 and C-01.2).")
        c4.allow_empty("No in-scope store uses a KMS key, so there is no customer-managed key to check.")
    for (key, region), users in keys.items():
        name = f"key {key} ({region}) used by {', '.join(users)}"
        item = _key_lookup(ctx, c, key, region)
        if item is None:
            c3.add(name, NOT_TESTED, "no DescribeKey output")
            c4.add(name, NOT_TESTED, "no DescribeKey output, so who manages the key is unknown")
            continue
        if item.error:
            c3.add(name, NOT_TESTED, f"DescribeKey returned {item.error}", [item])
            c4.add(name, NOT_TESTED, f"DescribeKey returned {item.error}", [item])
            continue
        meta = (item.data() or {}).get("KeyMetadata") or {}
        manager = meta.get("KeyManager")
        detail = f"KeyManager {manager}, KeyState {meta.get('KeyState')}"
        if manager in ("AWS", "CUSTOMER"):
            c3.add(name, PASS, detail, [item])
        else:
            c3.add(name, FAIL, f"{detail}: not an AWS managed or customer-managed key", [item])
        if manager == "AWS":
            c4.exclude(name, "AWS managed key: AWS rotates it, and its rotation cannot be configured", [item])
            continue
        if manager != "CUSTOMER":
            c4.add(name, NOT_TESTED, detail, [item])
            continue
        rotation = ctx.ev.find(c, "kms", "GetKeyRotationStatus", KeyId=meta.get("KeyId"))
        if not rotation or rotation[0].error:
            reason = f"GetKeyRotationStatus returned {rotation[0].error}" if rotation else "no GetKeyRotationStatus output"
            c4.add(name, NOT_TESTED, reason, [item, *rotation])
        elif (rotation[0].data() or {}).get("KeyRotationEnabled") is True:
            c4.add(name, PASS, "customer managed, rotation enabled", [item, rotation[0]])
        else:
            c4.add(name, FAIL, "customer managed, rotation not enabled", [item, rotation[0]])
    if keys and not c4.population and not c4.gaps:
        c4.allow_empty("Every KMS key used by an in-scope store is AWS managed, so no customer-managed key needs rotation.")
    return [c1, c2, c3, c4]


# --- C-02 Encryption in transit --------------------------------------------------


def _principal_is_everyone(principal):
    if principal == "*":
        return True
    return isinstance(principal, dict) and as_list(principal.get("AWS")) == ["*"] and len(principal) == 1


def _is_false(value):
    values = as_list(value)
    return bool(values) and all(str(v).lower() == "false" for v in values)


def denies_insecure_transport(document, bucket, partition):
    """True if a statement denies every principal every S3 action on the bucket and
    its objects when aws:SecureTransport is false, with no other condition."""
    bucket_arn = f"arn:{partition}:s3:::{bucket}"
    object_arn = f"{bucket_arn}/any-object-key"
    for st in statements(document):
        if st.get("Effect") != "Deny" or "NotPrincipal" in st or "NotAction" in st or "NotResource" in st:
            continue
        if not _principal_is_everyone(st.get("Principal")):
            continue
        if not any(a in ("*", "s3:*") for a in as_list(st.get("Action"))):
            continue
        resources = [r for r in as_list(st.get("Resource")) if isinstance(r, str)]
        if not (any(fnmatch.fnmatchcase(bucket_arn, r) for r in resources)
                and any(fnmatch.fnmatchcase(object_arn, r) for r in resources)):
            continue
        condition = st.get("Condition") or {}
        if len(condition) != 1:
            continue
        operator, keys = next(iter(condition.items()))
        if operator not in ("Bool", "BoolIfExists") or not isinstance(keys, dict) or len(keys) != 1:
            continue
        key, value = next(iter(keys.items()))
        if key.lower() == "aws:securetransport" and _is_false(value):
            return True
    return False


def tls_minimum(policy):
    """Minimum TLS version (major, minor) of an API Gateway security policy, or None if unknown."""
    if not isinstance(policy, str):
        return None
    match = re.fullmatch(r"TLS_(\d)_(\d)", policy)
    if match:
        return int(match.group(1)), int(match.group(2))
    match = re.match(r"SecurityPolicy_TLS1[23]_(\d)_(\d)_", policy)
    if match:
        return int(match.group(1)), int(match.group(2))
    if re.match(r"SecurityPolicy_TLS12_", policy):
        return 1, 2
    return None


def _version(text):
    major, minor = str(text).split(".")[:2]
    return int(major), int(minor)


def evaluate_c02(ctx):
    c = "C-02"
    minimum = ctx.threshold("min_tls_version")
    c1 = Check("C-02.1", "Every in-scope S3 bucket's policy denies all requests made without TLS "
                         "(aws:SecureTransport is false).")
    c2 = Check("C-02.2", f"Every in-scope customer API endpoint and custom domain has a security policy "
                         f"with a minimum of TLS {minimum}.")
    c3 = Check("C-02.3", "The customer API exposes no plain HTTP listener and no method integrates with a plain "
                         "HTTP (http://) backend.")

    for bucket in in_scope(ctx, c1, bucket_inventory(ctx, c)):
        found = ctx.ev.find(c, "s3", "GetBucketPolicy", Bucket=bucket.name)
        if not found:
            c1.add(bucket.label, NOT_TESTED, "no GetBucketPolicy output")
        elif found[0].error == "NoSuchBucketPolicy":
            c1.add(bucket.label, FAIL, "the bucket has no policy, so there is no deny statement", found)
        elif found[0].error:
            c1.add(bucket.label, NOT_TESTED, f"GetBucketPolicy returned {found[0].error}", found)
        else:
            document = policy_document((found[0].data() or {}).get("Policy"))
            if document is None:
                c1.add(bucket.label, NOT_TESTED, "the saved policy could not be parsed", found)
            elif denies_insecure_transport(document, bucket.name, ctx.partition):
                c1.add(bucket.label, PASS, "policy denies requests when aws:SecureTransport is false", found)
            else:
                c1.add(bucket.label, FAIL, "policy has no statement denying requests when aws:SecureTransport "
                                           "is false", found)

    apis = api_inventory(ctx, c)
    required = _version(minimum)
    for api in in_scope(ctx, c2, apis):
        found = ctx.ev.find(c, "apigateway", "GetRestApi", restApiId=api.ident)
        if not found or found[0].error:
            c2.add(api.label, NOT_TESTED, f"GetRestApi returned {found[0].error}" if found else "no GetRestApi output",
                   found)
            continue
        policy = (found[0].data() or {}).get("securityPolicy")
        version = tls_minimum(policy)
        if policy is None:
            c2.add(api.label, NOT_TESTED, "no securityPolicy recorded for the API endpoint", found)
        elif version is None:
            c2.add(api.label, NOT_TESTED, f"security policy {policy} is not one the evaluator can read", found)
        elif version >= required:
            c2.add(api.label, PASS, f"security policy {policy} (minimum TLS {version[0]}.{version[1]})", found)
        else:
            c2.add(api.label, FAIL, f"security policy {policy} allows TLS {version[0]}.{version[1]}", found)

    domain_pages = ctx.ev.find(c, "apigateway", "GetDomainNames")
    c2.use(*domain_pages)
    for gap in _list_gaps(domain_pages, "custom domain", "GetDomainNames"):
        c2.gap(gap)
    for page in domain_pages:
        for domain in (page.data() or {}).get("items") or [] if not page.error else []:
            label = f"custom domain {domain.get('domainName')}"
            if not ctx.scope_tag.matches(domain.get("tags") or {}):
                c2.exclude(label, f"not tagged {ctx.tag_text(ctx.scope_tag)}")
                continue
            policy = domain.get("securityPolicy")
            version = tls_minimum(policy)
            if version is None:
                c2.add(label, NOT_TESTED, f"security policy {policy} is not one the evaluator can read")
            elif version >= required:
                c2.add(label, PASS, f"security policy {policy} (minimum TLS {version[0]}.{version[1]})")
            else:
                c2.add(label, FAIL, f"security policy {policy} allows TLS {version[0]}.{version[1]}")

    for api in in_scope(ctx, c3, apis):
        rest_api = ctx.ev.find(c, "apigateway", "GetRestApi", restApiId=api.ident)
        if not rest_api or rest_api[0].error:
            c3.add(api.label, NOT_TESTED, "no GetRestApi output, so the endpoint type is unknown", rest_api)
        else:
            types = ((rest_api[0].data() or {}).get("endpointConfiguration") or {}).get("types") or []
            c3.add(api.label, PASS, f"API Gateway REST API ({', '.join(types) or 'endpoint type not recorded'}); "
                                    "REST API endpoints accept HTTPS only and have no HTTP listener", rest_api)
        for label, method in api_methods(ctx, c, c3, api):
            if method is None:
                c3.add(label, NOT_TESTED, "no GetMethod output")
                continue
            if method.error:
                c3.add(label, NOT_TESTED, f"GetMethod returned {method.error}", [method])
                continue
            integration = (method.data() or {}).get("methodIntegration")
            if not integration:
                c3.add(label, NOT_TESTED, "no integration recorded for the method", [method])
                continue
            kind, uri = integration.get("type"), integration.get("uri") or ""
            if kind in ("HTTP", "HTTP_PROXY") and uri.lower().startswith("http://"):
                c3.add(label, FAIL, f"{kind} integration to plain HTTP backend {uri}", [method])
            else:
                c3.add(label, PASS, f"{kind} integration, no plain HTTP backend", [method])
    return [c1, c2, c3]


# --- C-03 Audit logging ----------------------------------------------------------


def _selector_coverage(selectors, bucket, partition):
    """(reads, writes, unclear) data-event coverage of one bucket's objects."""
    reads = writes = False
    unclear = []
    object_arn = f"arn:{partition}:s3:::{bucket}/"
    for selector in selectors.get("EventSelectors") or []:
        for resource in selector.get("DataResources") or []:
            if resource.get("Type") != "AWS::S3::Object":
                continue
            values = resource.get("Values") or []
            if any(object_arn.startswith(v) for v in values if isinstance(v, str)):
                kind = selector.get("ReadWriteType", "All")
                reads = reads or kind in ("All", "ReadOnly")
                writes = writes or kind in ("All", "WriteOnly")
    for selector in selectors.get("AdvancedEventSelectors") or []:
        fields = {f.get("Field"): f for f in selector.get("FieldSelectors") or []}
        category = fields.get("eventCategory") or {}
        rtype = fields.get("resources.type") or {}
        if "Data" not in (category.get("Equals") or []) or "AWS::S3::Object" not in (rtype.get("Equals") or []):
            continue
        name = selector.get("Name") or "unnamed advanced selector"
        other = set(fields) - {"eventCategory", "resources.type", "resources.ARN", "readOnly"}
        arn = fields.get("resources.ARN")
        if other:
            unclear.append(f"{name} also filters on {', '.join(sorted(other))}")
            continue
        if arn:
            if set(arn) - {"Field", "StartsWith", "Equals"}:
                unclear.append(f"{name} uses a resources.ARN filter the evaluator cannot read")
                continue
            covered = any(object_arn.startswith(p) for p in arn.get("StartsWith") or [])
            if not covered:
                continue
        read_only = (fields.get("readOnly") or {}).get("Equals")
        if read_only and set(fields["readOnly"]) - {"Field", "Equals"}:
            unclear.append(f"{name} uses a readOnly filter the evaluator cannot read")
            continue
        reads = reads or not read_only or "true" in read_only
        writes = writes or not read_only or "false" in read_only
    return reads, writes, unclear


def _rule_applies(rule, log_root):
    prefix = rule.get("Prefix")
    flt = rule.get("Filter") or {}
    if "Prefix" in flt:
        prefix = flt["Prefix"]
    elif "And" in flt and "Prefix" in (flt.get("And") or {}):
        prefix = flt["And"]["Prefix"]
    prefix = prefix or ""
    return log_root.startswith(prefix) or prefix.startswith(log_root)


def evaluate_c03(ctx):
    c = "C-03"
    retention = ctx.threshold("log_retention_min_days")
    c1 = Check("C-03.1", "A multi-region CloudTrail trail exists for the account.")
    c2 = Check("C-03.2", "Log file validation is enabled on the multi-region trail.")
    c3 = Check("C-03.3", "The multi-region trail is logging.")
    c4 = Check("C-03.4", "The multi-region trail records S3 data events (reads and writes) for every in-scope bucket.")
    c5 = Check("C-03.5", "Public access is blocked on the audit log bucket (all four Block Public Access settings).")
    c6 = Check("C-03.6", f"The audit log bucket has an enabled lifecycle rule and no rule deletes logs in fewer "
                         f"than {retention} days.")
    trail_checks = (c2, c3, c4)

    described = ctx.ev.find(c, "cloudtrail", "DescribeTrails")
    for check in (c1, *trail_checks):
        check.use(*described)
    if not described or described[0].error:
        reason = f"DescribeTrails returned {described[0].error}" if described else "no DescribeTrails output"
        for check in (c1, *trail_checks, c5, c6):
            check.gap(reason)
        trails = []
    else:
        trails = list({t.get("TrailARN"): t for t in (described[0].data() or {}).get("trailList") or []}.values())

    covering = []
    for trail in trails:
        name = f"trail {trail.get('Name')} ({trail.get('TrailARN')})"
        if trail.get("IsMultiRegionTrail") is True:
            covering.append((name, trail))
        else:
            for check in (c1, *trail_checks):
                check.exclude(name, "not a multi-region trail")
    if covering:
        for name, _ in covering:
            c1.add(name, PASS, "IsMultiRegionTrail is true")
    elif not c1.gaps:
        c1.decide(FAIL, "No multi-region trail is listed in DescribeTrails.")

    stores = bucket_inventory(ctx, c)
    data_buckets = in_scope(ctx, c4, stores, True, "the audit log bucket itself (accepted known gap in C-03)")

    log_buckets = {}
    for name, trail in covering:
        validation = trail.get("LogFileValidationEnabled")
        c2.add(name, PASS if validation is True else FAIL,
               "log file validation enabled" if validation is True else "log file validation is not enabled")

        status = ctx.ev.find(c, "cloudtrail", "GetTrailStatus", Name=trail.get("TrailARN"))
        if not status or status[0].error:
            c3.add(name, NOT_TESTED, f"GetTrailStatus returned {status[0].error}" if status
                   else "no GetTrailStatus output", status)
        else:
            logging = (status[0].data() or {}).get("IsLogging")
            c3.add(name, PASS if logging is True else FAIL,
                   "IsLogging is true" if logging is True else "the trail is not logging", status)

        selectors = ctx.ev.find(c, "cloudtrail", "GetEventSelectors", TrailName=trail.get("TrailARN"))
        if not selectors or selectors[0].error:
            c4.add(name, NOT_TESTED, f"GetEventSelectors returned {selectors[0].error}" if selectors
                   else "no GetEventSelectors output", selectors)
        elif not data_buckets:
            c4.use(*selectors)
        else:
            data = selectors[0].data() or {}
            for bucket in data_buckets:
                label = f"{name}: data events for {bucket.label}"
                reads, writes, unclear = _selector_coverage(data, bucket.name, ctx.partition)
                if reads and writes:
                    c4.add(label, PASS, "read and write data events recorded", selectors)
                elif unclear:
                    c4.add(label, NOT_TESTED, "; ".join(unclear), selectors)
                else:
                    missing = " and ".join(k for k, ok in (("read", reads), ("write", writes)) if not ok)
                    c4.add(label, FAIL, f"{missing} data events are not recorded", selectors)

        if trail.get("S3BucketName"):
            prefix = trail.get("S3KeyPrefix")
            root = f"{prefix.rstrip('/')}/AWSLogs/" if prefix else "AWSLogs/"
            log_buckets.setdefault(trail["S3BucketName"], (f"log bucket of {name}", root))

    for store in stores[0]:
        if store.tags is not None and ctx.scope_tag.matches(store.tags) and ctx.audit_tag.matches(store.tags):
            log_buckets.setdefault(store.name, (f"tagged {ctx.tag_text(ctx.audit_tag)}", "AWSLogs/"))

    if not log_buckets and not covering:
        for check in (c5, c6):
            check.gap("no multi-region trail and no audit log bucket found, so there is no log bucket to test")
    for bucket, (why, log_root) in sorted(log_buckets.items()):
        label = f"bucket {bucket} ({why})"
        block = ctx.ev.find(c, "s3", "GetPublicAccessBlock", Bucket=bucket)
        if not block:
            c5.add(label, NOT_TESTED, "no GetPublicAccessBlock output")
        elif block[0].error == "NoSuchPublicAccessBlockConfiguration":
            c5.add(label, FAIL, "no Block Public Access configuration on the bucket", block)
        elif block[0].error:
            c5.add(label, NOT_TESTED, f"GetPublicAccessBlock returned {block[0].error}", block)
        else:
            c5.add(label, *_public_access_result(block[0]), block)

        lifecycle = ctx.ev.find(c, "s3", "GetBucketLifecycleConfiguration", Bucket=bucket)
        if not lifecycle:
            c6.add(label, NOT_TESTED, "no GetBucketLifecycleConfiguration output")
            continue
        if lifecycle[0].error == "NoSuchLifecycleConfiguration":
            c6.add(label, FAIL, "no lifecycle rule", lifecycle)
            continue
        if lifecycle[0].error:
            c6.add(label, NOT_TESTED, f"GetBucketLifecycleConfiguration returned {lifecycle[0].error}", lifecycle)
            continue
        c6.add(label, *_retention_result(lifecycle[0].data() or {}, log_root, retention), lifecycle)
    return [c1, c2, c3, c4, c5, c6]


PUBLIC_ACCESS_SETTINGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


def _public_access_result(item):
    config = (item.data() or {}).get("PublicAccessBlockConfiguration") or {}
    off = [s for s in PUBLIC_ACCESS_SETTINGS if config.get(s) is not True]
    if off:
        return FAIL, f"not blocked: {', '.join(off)}"
    return PASS, "all four Block Public Access settings are on"


def _retention_result(config, log_root, minimum):
    rules = [r for r in config.get("Rules") or [] if r.get("Status") == "Enabled"]
    if not rules:
        return FAIL, "no enabled lifecycle rule"
    short, unclear, kept = [], [], []
    for rule in rules:
        rid = rule.get("ID") or "unnamed rule"
        if not _rule_applies(rule, log_root):
            continue
        expiration = rule.get("Expiration") or {}
        noncurrent = rule.get("NoncurrentVersionExpiration") or {}
        if "Date" in expiration:
            unclear.append(f"{rid} expires objects on a fixed date")
        if "Days" in expiration:
            if expiration["Days"] < minimum:
                short.append(f"{rid} deletes logs after {expiration['Days']} days")
            else:
                kept.append(f"{rid} keeps logs {expiration['Days']} days")
        if "NoncurrentDays" in noncurrent and noncurrent["NoncurrentDays"] < minimum:
            short.append(f"{rid} deletes previous log versions after {noncurrent['NoncurrentDays']} days")
    if short:
        return FAIL, "; ".join(short)
    if unclear:
        return NOT_TESTED, "; ".join(unclear)
    return PASS, "; ".join(kept) or f"enabled lifecycle rules delete no logs before {minimum} days"


# --- C-04 Secrets storage --------------------------------------------------------


def evaluate_c04(ctx):
    c = "C-04"
    max_age = ctx.threshold("secret_max_age_days")
    c1 = Check("C-04.1", f"The current version (AWSCURRENT) of every secret in Secrets Manager is no more than "
                         f"{max_age} days old at collection time.")
    c2 = Check("C-04.2", "No environment variable of any in-scope Lambda function (every version) matches a "
                         "credential pattern.")
    c3 = Check("C-04.3", "The secret scanner (gitleaks) scanned the full history of the repository and reported "
                         "zero findings.")

    pages = ctx.ev.find(c, "secretsmanager", "ListSecrets")
    c1.use(*pages)
    for gap in _list_gaps(pages, "secret", "ListSecrets"):
        c1.gap(gap)
    secrets = [s for p in pages if not p.error for s in (p.data() or {}).get("SecretList") or []]
    if pages and not any(p.error for p in pages):
        c1.allow_empty("ListSecrets returned no secrets, so no secret is older than the limit.")
    for secret in secrets:
        label = f"secret {secret.get('Name')}"
        versions = ctx.ev.find(c, "secretsmanager", "ListSecretVersionIds", SecretId=secret.get("ARN"))
        if not versions or any(v.error for v in versions):
            code = next((v.error for v in versions if v.error), None)
            c1.add(label, NOT_TESTED, f"ListSecretVersionIds returned {code}" if code
                   else "no ListSecretVersionIds output", versions)
            continue
        current = [v for page in versions for v in (page.data() or {}).get("Versions") or []
                   if "AWSCURRENT" in (v.get("VersionStages") or [])]
        created = parse_time(current[0].get("CreatedDate")) if current else None
        if created is None:
            c1.add(label, NOT_TESTED, "no AWSCURRENT version with a creation date", versions)
            continue
        age = age_days(created, ctx.collected_at)
        detail = f"current version created {created.isoformat()}, {age:.1f} days before collection"
        c1.add(label, PASS if age <= max_age else FAIL, detail, versions)

    function_pages = ctx.ev.find(c, "lambda", "ListFunctions")
    c2.use(*function_pages)
    for gap in _list_gaps(function_pages, "Lambda function", "ListFunctions"):
        c2.gap(gap)
    by_name = {}
    for page in function_pages:
        for function in (page.data() or {}).get("Functions") or [] if not page.error else []:
            by_name.setdefault(function.get("FunctionName"), []).append(function)
    for name, versions in by_name.items():
        latest = next((f for f in versions if f.get("Version") == "$LATEST"), versions[0])
        arn = (latest.get("FunctionArn") or "").removesuffix(":$LATEST")
        tags = ctx.ev.find(c, "lambda", "ListTags", Resource=arn)
        matched = []
        unreadable = []
        for function in versions:
            env = function.get("Environment") or {}
            if "Variables" in env:
                unreadable.append(f"version {function.get('Version')} has unredacted values (not read)")
                continue
            matched.extend(f"{v.get('Name')} (version {function.get('Version')})"
                           for v in env.get("VariableNames") or [] if v.get("MatchesCredentialPattern") is True)
        label = f"Lambda function {name} ({len(versions)} version{'s' if len(versions) != 1 else ''})"
        if not tags or tags[0].error:
            reason = f"ListTags returned {tags[0].error}" if tags else "no ListTags output"
            c2.exclude(label, f"scope unknown: {reason}" + (f"; note: {', '.join(matched)} match a credential "
                                                             f"pattern" if matched else ""), tags)
            c2.gap(f"the tags of Lambda function {name} could not be read ({reason}), so it may be in scope")
            continue
        if not ctx.scope_tag.matches((tags[0].data() or {}).get("Tags") or {}):
            c2.exclude(label, f"not tagged {ctx.tag_text(ctx.scope_tag)}" +
                       (f"; note: {', '.join(matched)} match a credential pattern" if matched else ""), tags)
            continue
        c2.use(*tags)
        if matched:
            c2.add(label, FAIL, f"matches a credential pattern: {', '.join(matched)}")
        elif unreadable:
            c2.add(label, NOT_TESTED, "; ".join(unreadable))
        else:
            count = sum(len((f.get("Environment") or {}).get("VariableNames") or []) for f in versions)
            c2.add(label, PASS, f"{count} variable name(s) checked across versions, none matches a credential pattern")

    runs = [i for i in ctx.ev.find(c) if (i.request or {}).get("command") == "gitleaks git"]
    reports = [i for i in runs if i.path.endswith("gitleaks_report.json")]
    infos = [i for i in runs if i not in reports]
    c3.use(*runs)
    if not infos:
        c3.gap("no gitleaks run record in the evidence")
    elif infos[0].error:
        c3.add("repository history", NOT_TESTED, f"the gitleaks run failed ({infos[0].error})")
    elif not reports:
        c3.add("repository history", NOT_TESTED, "no gitleaks report in the evidence")
    else:
        info = infos[0].data() or {}
        findings = reports[0].data()
        full_history = any("--all" in str(a) and "--full-history" in str(a) for a in info.get("command") or [])
        if not isinstance(findings, list):
            c3.add("repository history", NOT_TESTED, "the gitleaks report could not be read")
        elif findings:
            c3.add("repository history", FAIL, f"{len(findings)} finding(s): " + items_text(
                f"{f.get('RuleID')} in {f.get('File')} at commit {str(f.get('Commit'))[:12]}" for f in findings))
        elif not full_history:
            c3.add("repository history", NOT_TESTED, "zero findings, but the scan did not cover the full history")
        else:
            c3.add("repository history", PASS, f"zero findings ({info.get('gitleaks_version') or 'version not recorded'},"
                                               " all branches, full history)")
    return [c1, c2, c3]


# --- C-05 Authentication ---------------------------------------------------------

ROOT_USER = "<root_account>"


def evaluate_c05(ctx):
    c = "C-05"
    max_age = ctx.threshold("access_key_max_age_days")
    c1 = Check("C-05.1", "Every IAM user with a console password has MFA active.")
    c2 = Check("C-05.2", f"Every active access key is no more than {max_age} days old at collection time.")
    c3 = Check("C-05.3", "The root account has MFA enabled.")
    c4 = Check("C-05.4", "The root account has no access keys.")
    c5 = Check("C-05.5", "Every method of every in-scope customer API requires authorization (type is not NONE).")

    report = ctx.ev.find(c, "iam", "GetCredentialReport")
    rows = None
    if not report or report[0].error:
        reason = f"GetCredentialReport returned {report[0].error}" if report else "no credential report"
        for check in (c1, c2):
            check.gap(reason, report)
    else:
        content = (report[0].data() or {}).get("Content")
        if isinstance(content, str):
            rows = list(csv.DictReader(io.StringIO(content)))
        else:
            for check in (c1, c2):
                check.gap("the credential report has no readable content", report)
    if rows is not None:
        generated = (report[0].data() or {}).get("GeneratedTime")
        for check in (c1, c2):
            check.use(*report)
        c1.allow_empty("The credential report lists no IAM user with a console password.")
        c2.allow_empty(f"The credential report (generated {generated}) lists no active access key.")
        for row in rows:
            user = row.get("user")
            if user == ROOT_USER:
                c1.exclude("root account", "root has no IAM console password setting; root MFA is C-05.3")
            elif row.get("password_enabled") != "true":
                c1.exclude(f"user {user}", "no console password")
            elif row.get("mfa_active") == "true":
                c1.add(f"user {user}", PASS, "console password with MFA active")
            else:
                c1.add(f"user {user}", FAIL, "console password with no MFA device")
            for n in ("1", "2"):
                label = f"{'root account' if user == ROOT_USER else 'user ' + user} access key {n}"
                if row.get(f"access_key_{n}_active") != "true":
                    continue
                rotated = parse_time(row.get(f"access_key_{n}_last_rotated"))
                if rotated is None:
                    c2.add(label, NOT_TESTED, "active key with no creation date in the report")
                    continue
                age = age_days(rotated, ctx.collected_at)
                c2.add(label, PASS if age <= max_age else FAIL,
                       f"created {rotated.isoformat()}, {age:.1f} days before collection")

    summary = ctx.ev.find(c, "iam", "GetAccountSummary")
    if not summary or summary[0].error:
        reason = f"GetAccountSummary returned {summary[0].error}" if summary else "no GetAccountSummary output"
        c3.add("root account", NOT_TESTED, reason, summary)
        c4.add("root account", NOT_TESTED, reason, summary)
    else:
        values = (summary[0].data() or {}).get("SummaryMap") or {}
        mfa, keys = values.get("AccountMFAEnabled"), values.get("AccountAccessKeysPresent")
        if mfa is None:
            c3.add("root account", NOT_TESTED, "AccountMFAEnabled not in the account summary", summary)
        else:
            c3.add("root account", PASS if mfa == 1 else FAIL, f"AccountMFAEnabled is {mfa}", summary)
        root_rows = [r for r in rows or [] if r.get("user") == ROOT_USER]
        root_key_active = any(r.get(f"access_key_{n}_active") == "true" for r in root_rows for n in ("1", "2"))
        if keys is None:
            c4.add("root account", NOT_TESTED, "AccountAccessKeysPresent not in the account summary", summary)
        elif keys != 0 or root_key_active:
            c4.add("root account", FAIL, f"AccountAccessKeysPresent is {keys}"
                   + ("; the credential report shows an active root key" if root_key_active else ""), summary + report)
        else:
            c4.add("root account", PASS, "AccountAccessKeysPresent is 0", summary)

    for api in in_scope(ctx, c5, api_inventory(ctx, c)):
        for label, method in api_methods(ctx, c, c5, api):
            if method is None:
                c5.add(label, NOT_TESTED, "no GetMethod output")
            elif method.error:
                c5.add(label, NOT_TESTED, f"GetMethod returned {method.error}", [method])
            else:
                kind = (method.data() or {}).get("authorizationType")
                if not kind:
                    c5.add(label, NOT_TESTED, "no authorizationType recorded", [method])
                else:
                    c5.add(label, FAIL if kind == "NONE" else PASS, f"authorizationType {kind}", [method])
    return [c1, c2, c3, c4, c5]


# --- C-06 Authorization ----------------------------------------------------------

# How the evaluator decides an IAM action is read-only, by the verb that starts
# the action name. Anything not recognised is reported as unproven, not passed.
READ_PREFIXES = ("get", "list", "describe", "batchget", "lookup")
# Not read-only even though they start with a read verb: they issue credentials.
WRITE_DESPITE_PREFIX = frozenset({
    "sts:getsessiontoken", "sts:getfederationtoken", "sso:getrolecredentials",
    "cognito-identity:getid", "cognito-identity:getcredentialsforidentity",
    "cognito-identity:getopenidtoken", "cognito-identity:getopenidtokenfordeveloperidentity",
    "redshift:getclustercredentials", "redshift:getclustercredentialswithiam",
    "redshift-serverless:getcredentials", "kms:getparametersforimport",
})
# Read-only although the verb is not a read verb.
READ_DESPITE_PREFIX = frozenset({"iam:generatecredentialreport"})
WRITE_PREFIXES = (
    "put", "create", "delete", "update", "modify", "attach", "detach", "set", "add", "remove", "tag", "untag",
    "start", "stop", "run", "invoke", "terminate", "enable", "disable", "associate", "disassociate", "restore",
    "reboot", "import", "upload", "copy", "replicate", "rotate", "cancel", "register", "deregister", "send",
    "publish", "execute", "pass", "assume", "revoke", "authorize", "reset", "change", "apply", "write",
    "schedule", "accept", "reject", "promote", "release", "allocate", "purge", "replace", "encrypt", "decrypt",
    "generate", "sign", "restore", "abort", "complete", "batchwrite", "batchdelete", "batchput", "insert",
)

READ, WRITE, UNKNOWN = "read", "write", "unknown"


def classify_action(action):
    if not isinstance(action, str) or action == "*":
        return WRITE
    if ":" not in action:
        return UNKNOWN
    service, name = action.lower().split(":", 1)
    full = f"{service}:{name}"
    if name in ("", "*"):
        return WRITE
    if full in READ_DESPITE_PREFIX:
        return READ
    if "*" in name or "?" in name:
        prefix = name.rstrip("*")
        if "*" in prefix or "?" in prefix:
            return UNKNOWN
        if any(fnmatch.fnmatchcase(w, full) for w in WRITE_DESPITE_PREFIX):
            return WRITE
        if any(prefix.startswith(p) for p in READ_PREFIXES):
            return READ
        if any(prefix.startswith(p) or p.startswith(prefix) for p in WRITE_PREFIXES):
            return WRITE
        return UNKNOWN
    if full in WRITE_DESPITE_PREFIX:
        return WRITE
    if any(name.startswith(p) for p in READ_PREFIXES):
        return READ
    if any(name.startswith(p) for p in WRITE_PREFIXES):
        return WRITE
    return UNKNOWN


def allowed_actions(document):
    """{classification: [actions]} for the Allow statements of one policy."""
    found = {READ: [], WRITE: [], UNKNOWN: []}
    for st in statements(document):
        if st.get("Effect") != "Allow":
            continue
        if "NotAction" in st:
            found[WRITE].append("NotAction: everything except " + ", ".join(map(str, as_list(st["NotAction"]))))
            continue
        for action in as_list(st.get("Action")):
            found[classify_action(action)].append(str(action))
    return found


def denies_secret_retrieval(document, partition, region, account):
    """True if an unconditional Deny covers secretsmanager:GetSecretValue on every secret."""
    action = "secretsmanager:getsecretvalue"
    secret_arn = f"arn:{partition}:secretsmanager:{region or 'any-region'}:{account or 'any-account'}:secret:any-AbCdEf"
    for st in statements(document):
        if st.get("Effect") != "Deny" or st.get("Condition") or "NotResource" in st:
            continue
        if "NotAction" in st:
            covered = not any(fnmatch.fnmatchcase(action, str(a).lower()) for a in as_list(st["NotAction"]))
        else:
            covered = any(fnmatch.fnmatchcase(action, str(a).lower()) for a in as_list(st.get("Action")))
        if covered and any(fnmatch.fnmatchcase(secret_arn, str(r)) for r in as_list(st.get("Resource"))):
            return True
    return False


def allows_everything(document):
    for st in statements(document):
        if st.get("Effect") != "Allow" or "NotAction" in st or "NotResource" in st:
            continue
        if any(a in ("*", "*:*") for a in as_list(st.get("Action"))) and "*" in as_list(st.get("Resource")):
            return True
    return False


def _managed_policy(ctx, c, arn):
    """(document or None, reason, evidence items) for a managed policy's default version."""
    policy = ctx.ev.find(c, "iam", "GetPolicy", PolicyArn=arn)
    if not policy or policy[0].error:
        return None, f"GetPolicy returned {policy[0].error}" if policy else "no GetPolicy output", policy
    version = ((policy[0].data() or {}).get("Policy") or {}).get("DefaultVersionId")
    found = ctx.ev.find(c, "iam", "GetPolicyVersion", PolicyArn=arn, VersionId=version)
    if not found or found[0].error:
        reason = f"GetPolicyVersion returned {found[0].error}" if found else "no GetPolicyVersion output"
        return None, reason, policy + found
    document = policy_document(((found[0].data() or {}).get("PolicyVersion") or {}).get("Document"))
    return document, "" if document else "the policy document could not be read", policy + found


def evaluate_c06(ctx):
    c = "C-06"
    approved = ctx.library.approved_lists.get("approved_administrators") or []
    c1 = Check("C-06.1", "No customer-managed IAM policy allows all actions (*) on all resources (*).")
    c2 = Check("C-06.2", "Every identity holding the AdministratorAccess policy matches an entry in "
                         "approved_administrators (controls/approved-lists.yaml), including * patterns.")
    c3 = Check("C-06.3", "S3 Block Public Access is on at the account level (all four settings).")
    c4 = Check("C-06.4", "S3 Block Public Access is on for every in-scope bucket (all four settings).")
    c5 = Check("C-06.5", "No active IAM Access Analyzer finding reports access from outside the account.")
    c6 = Check("C-06.6", "The tester role's policies grant no write actions (it is read-only).")
    c7 = Check("C-06.7", "The tester role's policies explicitly deny retrieving secret values "
                         "(secretsmanager:GetSecretValue on all secrets).")

    # C-06.1 wildcard customer-managed policies.
    pages = ctx.ev.find(c, "iam", "ListPolicies")
    c1.use(*pages)
    for gap in _list_gaps(pages, "customer-managed policy", "ListPolicies"):
        c1.gap(gap)
    if pages and not any(p.error for p in pages):
        c1.allow_empty("ListPolicies (Scope=Local) returned no customer-managed policies.")
    for page in pages:
        for policy in (page.data() or {}).get("Policies") or [] if not page.error else []:
            label = f"policy {policy.get('PolicyName')}"
            attached = policy.get("AttachmentCount")
            found = ctx.ev.find(c, "iam", "GetPolicyVersion", PolicyArn=policy.get("Arn"),
                                VersionId=policy.get("DefaultVersionId"))
            if not found or found[0].error:
                c1.add(label, NOT_TESTED, f"GetPolicyVersion returned {found[0].error}" if found
                       else "no GetPolicyVersion output for the default version", found)
                continue
            document = policy_document(((found[0].data() or {}).get("PolicyVersion") or {}).get("Document"))
            if document is None:
                c1.add(label, NOT_TESTED, "the policy document could not be read", found)
            elif allows_everything(document):
                c1.add(label, FAIL, f"allows Action * on Resource * (attached to {attached} identities)", found)
            else:
                c1.add(label, PASS, "no statement allows all actions on all resources", found)
    c1.exclude("inline policies of users, groups and roles", "not listed by the test procedure "
               "(customer-managed policies only); the tester role's inline policies are checked in C-06.6")

    # C-06.2 administrators against the approved list.
    pages = ctx.ev.find(c, "iam", "ListEntitiesForPolicy")
    pages = [p for p in pages if str(p.params.get("PolicyArn", "")).endswith(":iam::aws:policy/AdministratorAccess")]
    lists = [i for i in ctx.ev.find(c) if (i.request or {}).get("file") == "controls/approved-lists.yaml"]
    c2.use(*pages)
    for gap in _list_gaps(pages, "administrator", "ListEntitiesForPolicy"):
        c2.gap(gap)
    if pages and not any(p.error for p in pages):
        c2.allow_empty("No identity holds the AdministratorAccess policy.")
    if lists and (lists[0].data() or {}).get("sha256") != ctx.library.approved_lists_sha256:
        c2.exclude("approved list saved at collection", "differs from controls/approved-lists.yaml now; "
                   "the current file is used", lists)
    patterns = [str(entry.get("name")) for entry in approved if isinstance(entry, dict) and entry.get("name")]
    for page in pages:
        data = page.data() or {} if not page.error else {}
        identities = ([("group", g.get("GroupName")) for g in data.get("PolicyGroups") or []]
                      + [("user", u.get("UserName")) for u in data.get("PolicyUsers") or []]
                      + [("role", r.get("RoleName")) for r in data.get("PolicyRoles") or []])
        for kind, name in identities:
            match = next((p for p in patterns if fnmatch.fnmatchcase(str(name), p)), None)
            if match:
                c2.add(f"{kind} {name}", PASS, f"matches approved entry {match}")
            else:
                c2.add(f"{kind} {name}", FAIL, "not on approved_administrators")

    # C-06.3 and C-06.4 public access.
    account = ctx.ev.find(c, "s3control", "GetPublicAccessBlock")
    if not account:
        c3.add("account", NOT_TESTED, "no account-level GetPublicAccessBlock output")
    elif account[0].error == "NoSuchPublicAccessBlockConfiguration":
        c3.add("account", FAIL, "no account-level Block Public Access configuration", account)
    elif account[0].error:
        c3.add("account", NOT_TESTED, f"GetPublicAccessBlock returned {account[0].error}", account)
    else:
        c3.add("account", *_public_access_result(account[0]), account)
    for bucket in in_scope(ctx, c4, bucket_inventory(ctx, c)):
        found = ctx.ev.find(c, "s3", "GetPublicAccessBlock", Bucket=bucket.name)
        if not found:
            c4.add(bucket.label, NOT_TESTED, "no GetPublicAccessBlock output")
        elif found[0].error == "NoSuchPublicAccessBlockConfiguration":
            c4.add(bucket.label, FAIL, "no bucket-level Block Public Access configuration", found)
        elif found[0].error:
            c4.add(bucket.label, NOT_TESTED, f"GetPublicAccessBlock returned {found[0].error}", found)
        else:
            c4.add(bucket.label, *_public_access_result(found[0]), found)

    # C-06.5 external access findings.
    pages = ctx.ev.find(c, "accessanalyzer", "ListAnalyzers")
    c5.use(*pages)
    for gap in _list_gaps(pages, "analyzer", "ListAnalyzers"):
        c5.gap(gap)
    external = 0
    for page in pages:
        for analyzer in (page.data() or {}).get("analyzers") or [] if not page.error else []:
            label = f"analyzer {analyzer.get('name')}"
            if analyzer.get("type") not in ("ACCOUNT", "ORGANIZATION"):
                c5.exclude(label, f"type {analyzer.get('type')} does not report external access")
                continue
            if analyzer.get("status") != "ACTIVE":
                c5.add(label, NOT_TESTED, f"analyzer status is {analyzer.get('status')}")
                continue
            external += 1
            rules = ctx.ev.find(c, "accessanalyzer", "ListArchiveRules", analyzerName=analyzer.get("name"))
            findings = ctx.ev.find(c, "accessanalyzer", "ListFindingsV2", analyzerArn=analyzer.get("arn"))
            c5.use(*rules)
            if not findings or any(f.error for f in findings):
                code = next((f.error for f in findings if f.error), None)
                c5.add(label, NOT_TESTED, f"ListFindingsV2 returned {code}" if code else "no ListFindingsV2 output",
                       findings)
                continue
            active = [f for page_ in findings for f in (page_.data() or {}).get("findings") or []
                      if f.get("status") == "ACTIVE" and f.get("findingType", "ExternalAccess") == "ExternalAccess"]
            rule_count = sum(len((r.data() or {}).get("archiveRules") or []) for r in rules if not r.error)
            if active:
                c5.add(label, FAIL, f"{len(active)} active external access finding(s): " + items_text(
                    f"{f.get('resourceType')} {f.get('resource')}" for f in active), findings)
            else:
                c5.add(label, PASS, f"no active external access findings ({rule_count} archive rule(s) recorded)",
                       findings)
    if pages and not external and not c5.gaps and not c5.population:
        c5.decide(NOT_TESTED, "No active external access analyzer (type ACCOUNT or ORGANIZATION) was found, so "
                              "external access findings cannot be checked.")

    _evaluate_tester_role(ctx, c, c6, c7)
    return [c1, c2, c3, c4, c5, c6, c7]


def _evaluate_tester_role(ctx, c, c6, c7):
    roles = ctx.ev.find(c, "iam", "GetRole")
    if not roles or roles[0].error:
        reason = f"GetRole returned {roles[0].error}" if roles else "no GetRole output for the tester role"
        for check in (c6, c7):
            check.gap(reason, roles)
        return
    role = (roles[0].data() or {}).get("Role") or {}
    role_name = roles[0].params.get("RoleName")
    caller_role = ctx.caller_arn.split(":assumed-role/")[-1].split("/")[0] if ":assumed-role/" in ctx.caller_arn else ""
    for check in (c6, c7):
        check.use(*roles)
        if caller_role != role_name:
            check.gap(f"the evidence describes role {role_name}, but the collector ran as {caller_role or 'unknown'}")

    identity, boundary = [], None  # (label, document)
    incomplete = []
    attached_pages = ctx.ev.find(c, "iam", "ListAttachedRolePolicies", RoleName=role_name)
    inline_pages = ctx.ev.find(c, "iam", "ListRolePolicies", RoleName=role_name)
    for pages, operation in ((attached_pages, "ListAttachedRolePolicies"), (inline_pages, "ListRolePolicies")):
        for gap in _list_gaps(pages, "tester role policy", operation):
            incomplete.append(gap)
    evidence = list(attached_pages) + list(inline_pages)
    for page in attached_pages:
        for attached in (page.data() or {}).get("AttachedPolicies") or [] if not page.error else []:
            document, reason, items = _managed_policy(ctx, c, attached.get("PolicyArn"))
            evidence.extend(items)
            label = f"attached policy {attached.get('PolicyName')}"
            if document is None:
                incomplete.append(f"{label}: {reason}")
            else:
                identity.append((label, document))
    for page in inline_pages:
        for name in (page.data() or {}).get("PolicyNames") or [] if not page.error else []:
            found = ctx.ev.find(c, "iam", "GetRolePolicy", RoleName=role_name, PolicyName=name)
            evidence.extend(found)
            document = policy_document((found[0].data() or {}).get("PolicyDocument")) if found and not found[0].error else None
            if document is None:
                incomplete.append(f"inline policy {name}: not readable from the evidence")
            else:
                identity.append((f"inline policy {name}", document))
    boundary_arn = (role.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn")
    if boundary_arn:
        document, reason, items = _managed_policy(ctx, c, boundary_arn)
        evidence.extend(items)
        if document is None:
            incomplete.append(f"permissions boundary {boundary_arn}: {reason}")
        else:
            boundary = (f"permissions boundary {boundary_arn.rsplit('/', 1)[-1]}", document)
    for check in (c6, c7):
        check.use(*evidence)

    # C-06.6: effective permissions are within both the identity policies and the
    # boundary, so the role is read-only if either set allows only read actions.
    def summary(document):
        found = allowed_actions(document)
        return found, (WRITE if found[WRITE] else UNKNOWN if found[UNKNOWN] else READ)

    identity_results = [(label, *summary(doc)) for label, doc in identity]
    boundary_result = (boundary[0], *summary(boundary[1])) if boundary else None
    limited = boundary_result is not None and boundary_result[2] == READ

    for label, found, verdict in identity_results:
        if verdict == READ:
            c6.add(label, PASS, f"allows only read actions ({len(found[READ])} action pattern(s))")
        elif limited:
            c6.add(label, PASS, f"allows {items_text(found[WRITE] + found[UNKNOWN])}, but the read-only "
                                "permissions boundary removes them")
        elif verdict == WRITE:
            c6.add(label, FAIL, f"allows write actions: {items_text(found[WRITE])}")
        else:
            c6.add(label, NOT_TESTED, f"allows actions the evaluator cannot classify: {items_text(found[UNKNOWN])}")
    if boundary_result:
        label, found, verdict = boundary_result
        if verdict == READ:
            c6.add(label, PASS, "allows only read actions, so the role is read-only whatever its identity "
                                "policies allow")
        else:
            c6.exclude(label, f"allows {items_text(found[WRITE] + found[UNKNOWN])}; a boundary grants nothing by "
                              "itself, so the identity policies decide")
    for gap in incomplete:
        if not limited:  # A read-only boundary caps every identity policy, readable or not.
            c6.gap(gap)
    if not identity and not incomplete and not boundary:
        c6.allow_empty("The tester role has no policies, so it can perform no actions.")

    # C-06.7: an unconditional deny of GetSecretValue in any of its policies.
    denying = [label for label, doc in identity + ([boundary] if boundary else [])
               if denies_secret_retrieval(doc, ctx.partition, ctx.region, ctx.account_id)]
    label = f"role {role_name}"
    if denying:
        c7.add(label, PASS, f"secretsmanager:GetSecretValue is denied by {', '.join(denying)}")
    elif incomplete:
        c7.add(label, NOT_TESTED, "no readable policy denies it, and not every policy could be read: "
               + "; ".join(incomplete))
    else:
        checked = ", ".join(l for l, _ in identity + ([boundary] if boundary else [])) or "no policies"
        c7.add(label, FAIL, f"no policy explicitly denies secretsmanager:GetSecretValue on all secrets "
                            f"(checked: {checked})")


# --- C-07 Change management ------------------------------------------------------

DEFAULT_BRANCH = "main"


def _github_pages(ctx, c, pattern):
    regex = re.compile(pattern)
    return ctx.ev.github(c, lambda i: regex.fullmatch(i.url_path) is not None)


def evaluate_c07(ctx):
    c = "C-07"
    lists = ctx.library.approved_lists
    approvers = {str(a.get("github_user")) for a in lists.get("approved_change_approvers") or [] if isinstance(a, dict)}
    authors = {str(a.get("github_user")) for a in lists.get("change_authors") or [] if isinstance(a, dict)}
    exceptions = ctx.library.controls["C-07"].get("known_exceptions") or []
    first_commit_exception = next((e for e in exceptions if "initial" in str(e).lower()), None)

    c1 = Check("C-07.1", "An active ruleset on main requires a pull request with at least one approval.")
    c2 = Check("C-07.2", "The ruleset dismisses approvals when new commits are pushed.")
    c3 = Check("C-07.3", "Every ruleset that applies to main has an empty bypass list.")
    c4 = Check("C-07.4", "Every commit on main belongs to a pull request merged into main, except the repository's "
                         "first commit (documented known exception).")
    c5 = Check("C-07.5", "Every pull request merged into main has an approving review from a person on "
                         "approved_change_approvers.")
    c6 = Check("C-07.6", "That approver is not the pull request's author and is not a change author "
                         "(change_authors).")
    c7 = Check("C-07.7", "That approval was submitted before the pull request was merged and was still in effect "
                         "at the merge.")

    # Ruleset (C-07.1 to C-07.3).
    branch_rules = _github_pages(ctx, c, rf"/repos/[^/]+/[^/]+/rules/branches/{DEFAULT_BRANCH}")
    rulesets = {}
    for item in _github_pages(ctx, c, r"/repos/[^/]+/[^/]+/rulesets/\d+"):
        rulesets[int(item.url_path.rsplit("/", 1)[-1])] = item
    for check in (c1, c2, c3):
        check.use(*branch_rules)
    if not branch_rules or branch_rules[0].error:
        reason = (f"the branch rules request returned {branch_rules[0].error}" if branch_rules
                  else "no branch rules for main in the evidence")
        for check in (c1, c2, c3):
            check.gap(reason)
        rules = []
    else:
        rules = branch_rules[0].data() or []
    pr_rules = [r for r in rules if isinstance(r, dict) and r.get("type") == "pull_request"]
    applying = sorted({r.get("ruleset_id") for r in rules if isinstance(r, dict) and r.get("ruleset_id") is not None})
    for rule in pr_rules:
        params = rule.get("parameters") or {}
        label = f"pull_request rule of ruleset {rule.get('ruleset_id')}"
        detail_item = rulesets.get(rule.get("ruleset_id"))
        count = params.get("required_approving_review_count")
        enforcement = (detail_item.data() or {}).get("enforcement") if detail_item and not detail_item.error else None
        if not isinstance(count, int) or count < 1:
            c1.add(label, FAIL, f"requires {count} approvals", [detail_item])
        elif enforcement is None:
            c1.add(label, NOT_TESTED, f"requires {count} approval(s), but the ruleset's enforcement is not in the "
                                      "evidence", [detail_item])
        elif enforcement != "active":
            c1.add(label, FAIL, f"requires {count} approval(s), but enforcement is {enforcement}", [detail_item])
        else:
            c1.add(label, PASS, f"requires {count} approval(s); enforcement active", [detail_item])
        dismiss = params.get("dismiss_stale_reviews_on_push")
        c2.add(label, PASS if dismiss is True else FAIL,
               "dismiss_stale_reviews_on_push is true" if dismiss is True else "approvals are not dismissed on push")
    if rules is not None and not pr_rules and not c1.gaps:
        c1.decide(FAIL, "No pull_request rule applies to main.")
        c2.decide(FAIL, "No pull_request rule applies to main, so no approvals are dismissed on push.")
    for ruleset_id in applying:
        item = rulesets.get(ruleset_id)
        label = f"ruleset {ruleset_id}"
        if item is None or item.error:
            c3.add(label, NOT_TESTED, f"ruleset request returned {item.error}" if item else "no ruleset detail",
                   [item])
            continue
        data = item.data() or {}
        label = f"ruleset {ruleset_id} ({data.get('name')})"
        if "bypass_actors" not in data:
            c3.add(label, NOT_TESTED, "the bypass list is not in the evidence (the token may not be allowed to see "
                                      "it)", [item])
        elif data["bypass_actors"]:
            c3.add(label, FAIL, f"bypass list has {len(data['bypass_actors'])} actor(s): " + items_text(
                f"{a.get('actor_type')} {a.get('actor_id')} ({a.get('bypass_mode')})" for a in data["bypass_actors"]),
                [item])
        else:
            c3.add(label, PASS, "bypass list is empty", [item])

    # Commits and pull requests (C-07.4 to C-07.7).
    commit_pages = [i for i in _github_pages(ctx, c, r"/repos/[^/]+/[^/]+/commits")
                    if i.url_query.get("sha") == DEFAULT_BRANCH]
    c4.use(*commit_pages)
    for gap in _list_gaps(commit_pages, "commit", "the commit list for main"):
        c4.gap(gap)
    commits = [cm for p in commit_pages if not p.error for cm in (p.data() or []) if isinstance(cm, dict)]

    pulls = {}
    for item in _github_pages(ctx, c, r"/repos/[^/]+/[^/]+/pulls/\d+"):
        pulls[int(item.url_path.rsplit("/", 1)[-1])] = item
    merged = {}
    for number, item in pulls.items():
        data = item.data() or {} if not item.error else {}
        if data.get("merged_at") and (data.get("base") or {}).get("ref") == DEFAULT_BRANCH:
            merged[number] = data
    by_merge_commit = {d.get("merge_commit_sha"): n for n, d in merged.items() if d.get("merge_commit_sha")}

    roots = [cm for cm in commits if not cm.get("parents")]
    root_sha = roots[0].get("sha") if len(roots) == 1 and roots[0] is commits[-1] else None
    carrying = {}
    for commit in commits:
        sha = commit.get("sha") or ""
        message = ((commit.get("commit") or {}).get("message") or "").splitlines()[0:1]
        label = f"commit {sha[:12]} ({message[0] if message else 'no message'})"
        if sha == root_sha and first_commit_exception:
            c4.exclude(label, f"the repository's first commit; known exception in controls.yaml: "
                              f"{first_commit_exception}")
            continue
        assoc = _github_pages(ctx, c, rf"/repos/[^/]+/[^/]+/commits/{re.escape(sha)}/pulls")
        numbers = {by_merge_commit[sha]} if sha in by_merge_commit else set()
        unreadable = [a for a in assoc if a.error]
        for page in assoc:
            if not page.error:
                numbers.update(p.get("number") for p in page.data() or [] if isinstance(p, dict))
        in_main = sorted(n for n in numbers if n in merged)
        evidence = assoc + [pulls[n] for n in in_main]
        if in_main:
            for n in in_main:
                carrying.setdefault(n, []).append(sha)
            c4.add(label, PASS, f"part of merged pull request {', '.join(f'#{n}' for n in in_main)}", evidence)
        elif not assoc or unreadable:
            c4.add(label, NOT_TESTED, "the pull requests for this commit are not in the evidence", evidence)
        elif any(n not in pulls or pulls[n].error for n in numbers):
            c4.add(label, NOT_TESTED, "an associated pull request is not in the evidence", evidence)
        else:
            c4.add(label, FAIL, "not part of any pull request merged into main (direct change)", evidence)

    for number in sorted(carrying):
        data = merged[number]
        label = f"pull request #{number} ({data.get('title')})"
        author = (data.get("user") or {}).get("login")
        merged_at = parse_time(data.get("merged_at"))
        review_pages = _github_pages(ctx, c, rf"/repos/[^/]+/[^/]+/pulls/{number}/reviews")
        evidence = [pulls[number], *review_pages]
        if not review_pages or any(p.error for p in review_pages):
            for check in (c5, c6, c7):
                check.add(label, NOT_TESTED, "the reviews of this pull request are not in the evidence", evidence)
            continue
        reviews = [r for p in review_pages for r in (p.data() or []) if isinstance(r, dict)]
        approvals = [r for r in reviews if r.get("state") == "APPROVED"]
        listed = [r for r in approvals if (r.get("user") or {}).get("login") in approvers]
        independent = [r for r in listed if (r.get("user") or {}).get("login") not in ({author} | authors)]
        if listed:
            c5.add(label, PASS, f"approved by {', '.join(sorted({r['user']['login'] for r in listed}))}", evidence)
        else:
            who = ", ".join(sorted({(r.get("user") or {}).get("login") for r in approvals})) or "nobody"
            c5.add(label, FAIL, f"no approval from an approved approver (approved by: {who})", evidence)
        if independent:
            c6.add(label, PASS, f"author {author}; approver(s) {', '.join(sorted({r['user']['login'] for r in independent}))}",
                   evidence)
        elif listed:
            c6.add(label, FAIL, f"the only approved approver is the author or a change author ({author})", evidence)
        else:
            c6.add(label, FAIL, "no approval from an approved approver, so no independent approval", evidence)
        in_effect = _approved_at_merge(reviews, independent, merged_at)
        if in_effect:
            c7.add(label, PASS, f"approved {in_effect}, merged {merged_at.isoformat()}", evidence)
        elif independent and merged_at is None:
            c7.add(label, NOT_TESTED, "the merge time is not in the evidence", evidence)
        else:
            c7.add(label, FAIL, "no independent approval from an approved approver was in effect when it merged"
                   if independent else "no independent approval from an approved approver", evidence)
    if not carrying and commits and not c4.gaps:
        for check in (c5, c6, c7):
            check.allow_empty("No pull request carried a commit to main in the evidence.")
    return [c1, c2, c3, c4, c5, c6, c7]


def _approved_at_merge(reviews, candidates, merged_at):
    """Submission time of a candidate approval that was the approver's latest
    decision before the merge, or None."""
    if merged_at is None:
        return None
    for review in sorted(candidates, key=lambda r: r.get("submitted_at") or ""):
        login = (review.get("user") or {}).get("login")
        submitted = parse_time(review.get("submitted_at"))
        if submitted is None or submitted >= merged_at:
            continue
        later = [r for r in reviews if (r.get("user") or {}).get("login") == login
                 and r.get("state") in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED")
                 and (parse_time(r.get("submitted_at")) or merged_at) < merged_at
                 and (parse_time(r.get("submitted_at")) or submitted) > submitted]
        if not later or later[-1].get("state") == "APPROVED":
            return submitted.isoformat()
    return None


EVALUATORS = {
    "C-01": evaluate_c01,
    "C-02": evaluate_c02,
    "C-03": evaluate_c03,
    "C-04": evaluate_c04,
    "C-05": evaluate_c05,
    "C-06": evaluate_c06,
    "C-07": evaluate_c07,
}
