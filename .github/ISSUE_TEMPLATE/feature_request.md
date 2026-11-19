---
name: Feature request
about: Suggest an improvement to Sentinel
title: "[Feature] "
labels: enhancement
---

**The problem**
What is hard, missing, or easy to get wrong today?

**Proposed change**
What should Sentinel do differently?

**Why it helps**
Who benefits, and how often?

**Scope note**
Sentinel is fail-open and reversible by design: every enforcement action is
reversible, every action posts evidence to the mod-log, and no message
content is stored. A lone report from one server never triggers a
network-wide flag — a domain needs reports from 2+ servers to score
network-wide. Requests that would weaken any of those rules are out of
scope.
