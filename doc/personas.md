# Personas

These personas are the potential users of the security-profiles-operator.
The intent of the operator is to address the needs of these personas, and so,
user stories and feature enhancements shall be targeted at helping them.

## Infrastructure SRE  (infra/host)

**_Kirsti_**

Responsible for Day 1 and Day 2 operations for the infrastructure:

* This includes security operations

* Has a more technical dashboard view of the state of security

* Wants compartmentalization verification

  - Namespaces, Seccomp, and SELinux technical reports

## Application SRE  (tenant/workload)

**_Rajesh_**

Responsible for:

* Application deployment, maintenance, and monitoring.

Interacts with:

* Application developer for...

* Infra SRE for... 

Desires:

* No security events/breaches related to managed applications.

* Easy way to ensure the applications they are responsible for are configured securely.

## Application Developer

**_Ming_**

Responsible for:

* Development of new container-native applications.

* Modernizing legacy applications to be moved from bare-metal or virtualized environments to container platforms.

* Developing applications that meet the security requirement.

Interacts with:

* Application SRE to support application deployment, maintenance, and development of new functionality.

* PM, Compliance Officer, or someone else to understand security requirements imposed on their application(s) for the target deployment environment(s).

Desires:

* Easily meet security requirements that are built into the development process without requiring expertise in security components.

* Development environments that mimic production from a security perspective to avoid surprises when applications are deployed into production.
