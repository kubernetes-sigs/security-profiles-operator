# Personas

> [!NOTE]
> This document is historical, it described the target users when the
> Security Profiles Operator was proposed. For current usage and
> configuration, refer to the [installation](../installation.md) and
> [profiles](../profiles.md) documentation.

These personas are the potential users of the Security Profiles Operator. The
intent of the operator is to address the needs of these personas, and so, user
stories and feature enhancements shall be targeted at helping them, see the
[user stories](user-stories.md).

## Infrastructure SRE (infra/host)

Kirsti is responsible for Day 1 and Day 2 operations for the infrastructure:

- This includes security operations.
- Has a more technical dashboard view of the state of security.
- Wants compartmentalization verification:
  - Namespaces, seccomp and SELinux technical reports.

## Application SRE (tenant/workload)

Rajesh is responsible for:

- Application deployment, maintenance and monitoring.

Interacts with:

- The application developer, to deploy and run new versions of the
  application.
- The infrastructure SRE, to get the security profiles and the cluster
  configuration the application needs.

Desires:

- No security events or breaches related to managed applications.
- An easy way to ensure the applications they are responsible for are
  configured securely.

## Application developer

Ming is responsible for:

- Development of new container-native applications.
- Modernizing legacy applications to be moved from bare-metal or virtualized
  environments to container platforms.
- Developing applications that meet the security requirements.

Interacts with:

- The application SRE to support application deployment, maintenance and
  development of new functionality.
- The PM, compliance officer or someone else to understand the security
  requirements imposed on their applications for the target deployment
  environments.

Desires:

- Easily meet security requirements that are built into the development
  process without requiring expertise in security components.
- Development environments that mimic production from a security perspective
  to avoid surprises when applications are deployed into production.
