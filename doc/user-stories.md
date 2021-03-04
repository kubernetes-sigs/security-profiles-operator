# User Stories

These user stories are the scenarios that the security-profiles-operator enables
to cover the needs of [target personas](personas.md).

The intent of this document is to present the features the operator should enable
in a humanized manner that shows how this software helps people do their jobs.

### As an application SRE, Rajesh would like to deploy a Seccomp profile and an SELinux or AppArmor profiles to secure their application.

Details:

* This would also apply to Ming, as an application developer would be deploying to a development environment.

### As an application developer, Ming would like to be able to debug and develop their security profiles using similar tools as would be used to deploy the app in production.

Details:

* Ming needs to be able to try out different profiles and get appropriate error
  messages if the profile is badly formatted. Where possible, invalid profiles
  should be rejected with user-friendly validation error messages and not applied
  to the system.

### As an application developer, Ming would like to be able to debug syntax errors in a given profile.

Details:

* The operator should be able to clearly point out syntax errors that might appear
in a certain profile. E.g. for SELinux a missing parenthesis or something of the
sort… This is considered for SELinux in
[an issue](https://github.com/kubernetes-sigs/security-profiles-operator/issues/223)

### As an application developer, Ming would like to be able to automatically generate initial security profiles that are specific to the application.

Details:

* For improved profiles, users could define a process to be triggered during the profiling process (i.e. execution of E2E tests).
* Avoid potential knowledge short falls by priming essential requirements 
(e.g. blocked essential syscalls may cause 
[issues](https://github.com/kubernetes/kubernetes/issues/85191) in seccomp)
* The initial profile will need to be "manually" refined over time.

### As an application SRE, Rajesh needs to be able to see the state of the installed profile(s) and verify that it has indeed been installed on the system.

### As an application SRE, Rajesh needs to be able to do long runs of a security profile in “complain-mode” to easily identify the impact of a profile being enforced without impacting the application.

Details:

* In Seccomp, profiles can be affected by the underlying system and therefore
  a profile that worked in an environment may break on another. Having the
  ability to securely use a profile in a secure “complain-mode” may decrease
  the risk of breaking production workloads.

* The same complain mode can be used for AppArmor.

### As an application SRE, Rajesh needs to easily be able to link a security profile to a pod or set of pods.

Details:

* Automatically link and apply profiles to Public workloads (kubernetes dashboard,
  nginx, etc) based on target image

### As an infrastructure SRE, Kirsti wants to make sure that no security profiles are in an errored state

Open questions:

* Should we start issuing metrics on errored policies?

### As an application SRE, Rajesh needs to make sure that when rolling out a new version of the app, a new version of the security profile is taken into use by the app (and not the old one).

Details:

* Conversely, for rollbacks, we need to make sure that the old profile is taken
  into use again

Open questions:

* Does this actually work? We should have a test

### As an infrastructure SRE, Kirsti wants to make sure that common profiles are available to all users, so folks can deploy applications securely.

Details:

* Web-servers are a very common type of application, so we should enable folks to
  use profiles specialized for this so that all pods using web server images can
  make use of the common policy

### As an infrastructure SRE, Kirsti wants to make sure that pods are running with the profiles that were set to them.

Details:

* In SELinux, is the pod using the type from the policy, or is it using `spc_t`?

Open questions:

* Same policy in terms of name or content?

* What if the target node does not support the profile type (apparmor, selinux)?

### As an infrastructure SRE, Kirsti wants to make sure that only pods on a certain namespace, can use certain less restrictive profiles.

Details:

* E.g. there is an SELinux policy that gives the pod access to the nodes' logs, and
  so it should only be usable in an approved namespace where a log
  forwarding application is deployed.

Open Questions:

* What’s the overlap with PodSecurityPolicy’s?

* Integration with OPA/Gatekeeper?

* Does this only impact Profiles created through SPO (i.e. can a user just use `runtime/default`)?

Terminology
===========

**Security profile**: A Seccomp profile, SELinux profile, or AppArmor profile.
