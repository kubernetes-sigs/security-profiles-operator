# Summary

[summary]: #summary

The main target is to simplify the usage of seccomp profiles in Kubernetes by
still providing high security standards and enough flexibility for further
additions.

# Motivation

[motivation]: #motivation

The seccomp feature of Kubernetes will [graduate to General Availability (GA)][0] in
one of the upcoming releases. Non-goals of this Kubernetes Enhancement Proposal
(KEP) are those functional enhancements:

[0]: https://github.com/kubernetes/enhancements/pull/1148

- Changing the default seccomp profile from unconfined
- Defining any standard "Kubernetes branded" seccomp profiles
- Formally specifying the seccomp profile format in Kubernetes
- Providing mechanisms for loading profiles from outside the
  static seccomp node directory
- Changing the semantics around seccomp support

Target of this RFC is to fill the gap between the current and future usage of
seccomp in Kubernetes to provide on one hand a better user experience and on
the other hand a more secure Kubernetes installation.

## Explanation

[explanation]: #explanation

The overall enhancement can be split-up into multiple features:

1. **Provide a way to define seccomp profiles as cluster-wide custom resources
   in Kubernetes:**
   Seccomp profiles are usually written in JSON, which is hard to write and
   understand from a user perspective. A custom resource with strong defaults
   should make it easier for users to manually write their own profiles. This
   goes beyond than just managing seccomp profiles as Kubernetes config maps and
   provides the further possibility to validate the profile on the fly.

2. **Provide an operator which synchronizes seccomp profiles to every node:**
   The distribution of seccomp profiles is usually done by the node
   administrators. With the operator we will be able to distribute the custom
   resources as JSON files to each node, whereas the reconciliation loop ensures
   that the profiles are all up-to-date.

3. **Provide a streamlined way to add seccomp profiles to workloads:**
   Right now an annotation is used to add seccomp profiles to single workloads,
   whereas a new API field will be introduced with the graduation to GA.

   To link the custom resource with the workload, we hook into (watch for) the
   existing annotations
   `seccomp.security.alpha.kubernetes.io/pod` and
   `container.seccomp.security.alpha.kubernetes.io/<CONTAINER_NAME>` to
   reconcile the state with the usage of the operator. This way the operator
   can be deployed in clusters which already use custom seccomp profiles.

### Future enhancements

4. **Provide pre-defined seccomp profiles:**
   We could provide pre-defined profiles for application groups like
   _webservers_ to work the box with commonly used applications. The profiles
   can be shipped directly with the operator as pre-defined custom resources.

5. **Provide the possibility to enforce a profile per namespace:**
   A mutating webhook could be used to allow administrators to enforce a
   certain profile per namespace for security hardening purposes. If we
   implement this via an annotation on namespace level or via a new resource
   (-binding) is currently open.

6. **Provide the possibility to record seccomp profiles in Kubernetes:**
   It is possible to record seccomp profiles via an OCI hook or probably with a
   sidecar container. This means we can put workloads from a security
   perspective into three possible modes:

   - _Disabled_: This refers to the unconfined behavior wchich means that seccomp
     is disabled at all.
   - _Recording_: Seccomp is still in _disabled_ mode, but we now record the
     profile during the run of the application.
   - _Applying_: Seccomp is enabled and enforcing a profile.

   This also means that we would be able to audit the cluster from a security
   perspective and report workloads which are currently in _disabled_ mode.

# Drawbacks

[drawbacks]: #drawbacks

This will add additional maintenance overhead to the cluster operator and
enforces users to understand what the usage of seccomp implies for their
business. It will increase the complexity if the user has not used seccomp
before.

# Alternatives

[alternatives]: #alternatives

We could alternatively stick to the classic approach in providing seccomp
profiles for containers via RPM packaging. This would still mean that users have
to select the right profile in their Kubernetes workloads.

## Related projects and enhancements to Kubernetes

There is an [open KEP][10] about using config maps which should be passed down
the CRI to be applied directly by containers runtimes like CRI-O. This would
avoid static file handling at all but would not propose a Custom Resource
Definition on top.

Since the KEP has not merged yet we will follow the initial file-based approach
and contribute to the KEP. The operator can be changed later on to manage
config-maps instead of files which would not affect the overall CRD
implementation. If the KEP promotes to Beta or GA we consider moving the CRD
implementation over to the official Kubernetes repository.

In any case the operator would still persist and we're keeping in mind to
integrate later on with the official Kubernetes implementation.

[10]: https://github.com/kubernetes/enhancements/pull/1269
