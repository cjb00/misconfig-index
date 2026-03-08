# We Scanned 92 Open Source IaC Repos. Here's What We Found.

*Terraform, Kubernetes, and CloudFormation — 1,762 findings across 92 public repos. We expected Kubernetes and Terraform to score similarly. They didn't.*

---

## TL;DR

- **92 repos scanned** across Terraform, Kubernetes, CloudFormation, and Dockerfile
- **1,762 total findings** — but the distribution is heavily bimodal
- **CloudFormation is nearly perfect**: 9/9 repos scored A (100/100), only 1 finding total
- **Kubernetes has the most risk**: average score 82.4, responsible for 68% of all findings despite being 27% of the dataset
- **#1 issue by volume**: missing resource limits — found in 27% of all repos
- **6 of the top 10 misconfigs are Kubernetes-specific**

---

## Why We Did This

We built [Misconfig Index](https://misconfig.dev) to give any public GitHub repo an IaC security score — the kind of quick signal that CI/CD pipelines and security reviews need. Before we started telling people their repos had problems, we wanted to understand the baseline: what does the broader IaC ecosystem actually look like?

We selected 92 public repos representing a realistic cross-section — official cloud provider modules, popular community modules, real-world applications, GitOps tooling, and Helm chart repositories. Then we ran every one of them through the scanner locally, with no rate limits and no cherry-picking.

---

## Methodology

All repos were scanned using the Misconfig Index local scanner (git clone + static analysis, no network calls). The scanner detects misconfigurations across Terraform HCL, Kubernetes YAML, CloudFormation JSON/YAML, and Dockerfiles. Variable blocks and auto-generated wrapper modules are excluded to avoid false positives on module input declarations. Provider SDK repos (`terraform-provider-*`) and the Kubernetes monorepo were excluded since they contain test fixtures rather than deployed infrastructure. Six educational repos (Udemy courses, O'Reilly book companion code, official tutorial examples) are [reported separately](#the-education-gap) — they intentionally demonstrate misconfigured patterns for teaching purposes.

**Scores run 0–100. Grades map A (90–100) → F (0–39).**

---

## The Distribution Is Bimodal — and That's the Story

The average score across all 92 repos is **87.9/100**. The median is **98/100**.

Those two numbers tell you everything: most repos are clean, but a handful are dragging the average down hard.

| Grade | Repos | Pct |
|-------|-------|-----|
| **A** (90–100) | 63 | 68% |
| **B** (80–89)  | 11 | 12% |
| **C** (70–79)  |  9 | 10% |
| **D** (40–69)  |  6 |  7% |
| **F** (0–39)   |  3 |  3% |

The 68% getting an A aren't squeaking by — most score 95–100. The repos in the D–F range have deep, systemic issues: hundreds of findings concentrated in a small number of rule categories. This isn't a bell curve. It's two clusters with a gap in between.

---

## Finding #1: CloudFormation Is Surprisingly Clean

We expected CloudFormation to perform roughly in line with Terraform — same declarative config, same kind of AWS-specific rules. It didn't come close.

| IaC Type | Repos | Avg Score | Total Findings | F Grades |
|----------|-------|-----------|----------------|----------|
| **CloudFormation** | 9 | **100.0** | **1** | 0 |
| Mixed (TF+K8s+Docker) | 5 | 97.4 | 33 | 0 |
| Dockerfile | 9 | 93.0 | 107 | 0 |
| **Terraform** | 44 | 86.3 | 414 | 2 |
| **Kubernetes** | 25 | 82.4 | 1,207 | 1 |

Every single CloudFormation repo scored 100/100. The nine repos generated exactly one finding between them — a single resource in `awslabs/aws-cloudformation-templates`. (Nine repos is a thin sample — we'd want 30+ before drawing strong conclusions about CFN as a format; treat this as a signal worth investigating, not a verdict.)

Our hypothesis: CloudFormation's declarative JSON/YAML format, combined with AWS's conservative defaults and extensive schema validation at deploy time, pushes misconfiguration issues to the surface earlier than Terraform or Kubernetes. The friction of writing JSON keeps configs simple. Whether that's a feature or a limitation is a separate debate.

---

## Finding #2: Kubernetes Has a Security Problem

Kubernetes repos represent 27% of our dataset but account for **68% of all findings** (1,207 out of 1,762). The average Kubernetes repo score is 82.4 — seven points lower than Terraform, fifteen points lower than Dockerfile repos.

The finding distribution is concentrated: a small number of Helm chart repositories (particularly `helm/charts`, the officially deprecated archive with 287 findings, and `bitnami/charts` with 201) drove the majority of the volume. But even excluding those, Kubernetes repos consistently had more findings per repo than any other type.

What's driving it? The Kubernetes runtime security model — resource limits, security contexts, privileged mode, host namespaces, read-only filesystems — offers a lot of knobs. Most repos aren't turning them.

---

## The Top 10 Misconfigurations

These are the rules that fired most often across all 92 repos, by total hit count and percentage of repos affected.

| # | Misconfiguration | Hits | Repos Affected |
|---|------------------|------|----------------|
| 1 | No CPU/memory resource limits | 476 | **27%** |
| 2 | Container image uses `:latest` tag | 375 | **26%** |
| 3 | Container runs as root (UID 0) | 178 | 9% |
| 4 | Security group open to `0.0.0.0/0` | 162 | 18% |
| 5 | IAM wildcard resource (`*`) | 119 | 10% |
| 6 | Writable root filesystem | 110 | 11% |
| 7 | Privileged container mode | 109 | 14% |
| 8 | `hostNetwork` or `hostPID` enabled | 107 | 13% |
| 9 | Security group allows all traffic (`-1`) | 63 | 13% |
| 10 | IAM wildcard resource (HCL policy) | 28 | 4% |

**Six of the top 10 are Kubernetes-specific.** The two Terraform networking issues (#4 and #9) are the most commonly flagged non-Kubernetes problems.

### The top two aren't exotic

Rules 1 and 2 — missing resource limits and `:latest` image tags — are the unglamorous basics. They're not zero-days. They won't get your name on a CVE. But missing resource limits means one noisy neighbour can starve your entire node, and `:latest` means your deployments are non-reproducible and your container could silently change under you.

Combined, these two rules account for **851 findings** — nearly half the total — across a quarter of all repos.

### The networking gap

`0.0.0.0/0` in a security group, or a group that allows all traffic with protocol `-1`, is the Terraform equivalent of `chmod 777`. It showed up in 18% of repos, almost entirely in Terraform. The specific patterns we saw: egress rules that open all outbound traffic (the default "it works, ship it" pattern) and ingress rules left open from debugging that never got locked down.

### IAM wildcards — a real finding in official code

`resources = ["*"]` in an IAM policy definition appeared in 10% of repos. Some of these are legitimate — certain AWS actions (like `cloudwatch:PutMetricData`) genuinely have no resource-level restriction. But several were broad admin-style policies attached to service roles. The `terraform-aws-modules/terraform-aws-iam` module scored F (5/100) specifically because it ships pre-built policies with wildcard resources — a known design trade-off that users should be aware of when adopting those modules.

---

## Finding #3: The Security Category That Consistently Fails

Looking at how repos score by finding category:

| Category | Avg Score | Repos with Findings |
|----------|-----------|---------------------|
| **Networking** | **76.7** | 20 repos |
| Identity/IAM | 80.9 | 13 repos |
| Workload | 83.2 | 32 repos |
| Storage | 85.2 | 4 repos |
| Image | **96.1** | 26 repos |

Networking is the weakest category — 20 repos had networking findings, and their average networking score was 76.7. Image security (base image hygiene) is the strongest, averaging 96.1.

The gap between image hygiene and networking security is striking. Teams are being deliberate about base images but sloppy about ingress/egress rules.

---

## The Education Gap

Six repos in our dataset are explicitly educational — Udemy courses, O'Reilly book companion code, and official tutorial collections. We analyzed them but kept them out of the trend numbers since they intentionally demonstrate broken patterns for teaching purposes.

| Score | Repo | Type |
|-------|------|------|
| **F/0** (123 findings) | `wardviaene/terraform-course` | Udemy course |
| D/45 (97 findings) | `kubernetes/examples` | Official K8s tutorial |
| D/57 (30 findings) | `futurice/terraform-examples` | Example patterns |
| D/58 (63 findings) | `ContainerSolutions/kubernetes-examples` | K8s tutorial |
| D/59 (39 findings) | `brikis98/terraform-up-and-running-code` | *Terraform: Up & Running* code |
| C/66 (48 findings) | `wardviaene/kubernetes-course` | Udemy course |

The course repos score low because they walk through progressively building out infrastructure — including intentionally insecure configs that get fixed by the end of the chapter. The takeaway isn't that the courses are bad. It's that if you're copying config from a tutorial into production without audit, that's the risk vector.

---

## What This Means for Your Repo

Based on the data, the highest-value checks to run on any IaC codebase:

1. **Set resource limits on every container.** CPU and memory limits should be mandatory in any production Kubernetes config. They're absent in 27% of repos in our dataset.

2. **Pin your image tags.** Replace `:latest` with a specific digest or semver tag. This is table stakes for reproducible deployments.

3. **Audit your security groups for `0.0.0.0/0`.** Every open ingress rule should have a documented reason. Egress is lower risk but `0.0.0.0/0` all-traffic egress (`-1`) rules should also be reviewed.

4. **Scope your IAM policies.** `Resource: "*"` on an action that supports resource-level permissions is unnecessary and a privilege escalation vector.

5. **Check your security contexts.** `runAsRoot`, `privileged: true`, `hostNetwork: true` — each one is a potential container escape. If you don't need it, remove it.

---

## Try It on Your Own Repo

Every score in this post was generated by the same scanner available at [misconfig.dev](https://misconfig.dev). Paste your public GitHub repo URL and get a score in under a minute.

The CLI is also available for CI integration:

```bash
pip install misconfig-index
misconfig scan --path ./infra
```

If you want to run the same bulk analysis we ran here, the scanner, repo list, and analysis scripts are all in the [misconfig-index GitHub repo](https://github.com/cjb00/misconfig-index).

---

*Scanned March 2026. 92 repos, 1,762 findings, one very clean CloudFormation dataset.*
