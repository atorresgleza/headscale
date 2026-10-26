# Registration methods

Headscale supports multiple ways to register a node. The preferred registration method depends on the identity of a node
and your use case.

## Identity model

Tailscale's identity model distinguishes between personal and tagged nodes:

- A personal node (or user-owned node) is owned by a human and typically refers to end-user devices such as laptops,
  workstations or mobile phones. End-user devices are managed by a single user.
- A tagged node (or service-based node or non-human node) provides services to the network. Common examples include web-
  and database servers. Those nodes are typically managed by a team of users. Some additional restrictions apply for
  tagged nodes, e.g. a tagged node is not allowed to [Tailscale SSH](https://tailscale.com/docs/features/tailscale-ssh)
  into a personal node.

Headscale implements Tailscale's identity model and distinguishes between personal and tagged nodes where a personal
node is owned by a Headscale user and a tagged node is owned by a tag. Tagged devices are grouped under the special user
`tagged-devices`.

## Registration methods

There are two main ways to register new nodes, [web authentication](#web-authentication) and [registration with a pre
authenticated key](#pre-authenticated-key). Both methods can be used to register personal and tagged nodes.

### Web authentication

Web authentication is the default method to register a new node. It's interactive, where the client initiates the
registration and the Headscale administrator needs to approve the new node before it is allowed to join the network. A
node can be approved with:

- Headscale CLI (described in this documentation)
- [Headscale API](api.md)
- Or delegated to an identity provider via [OpenID Connect](oidc.md)

Web authentication relies on the presence of a Headscale user. Use the `headscale users` command to create a new
user[^1]:

```console
headscale users create <USER>
```

=== "Personal devices"

    Run `tailscale up` to login your personal device:

    ```console
    tailscale up --login-server <YOUR_HEADSCALE_URL>
    ```

    Usually, a browser window with further instructions is opened. This page explains how to complete the registration
    on your Headscale server and it also prints the Auth ID required to approve the node:

    ```console
    headscale auth register --user <USER> --auth-id <AUTH_ID>
    ```

    Congrations, the registration of your personal node is complete and it should be listed as "online" in the output of
    `headscale nodes list`. The "User" column displays `<USER>` as the owner of the node.

=== "Tagged devices"

    Your Headscale user needs to be authorized to register tagged devices. This authorization is specified in the
    [`tagOwners`](https://tailscale.com/docs/reference/syntax/policy-file#tag-owners) section of the
    [policy](policy.md). A simple example looks like this:

    ```json title="The user alice can register nodes tagged with tag:server"
    {
      "tagOwners": {
        "tag:server": ["alice@"]
      },
      // more rules
    }
    ```

    Run `tailscale up` and provide at least one tag to login a tagged device:

    ```console
    tailscale up --login-server <YOUR_HEADSCALE_URL> --advertise-tags tag:<TAG>
    ```

    Usually, a browser window with further instructions is opened. This page explains how to complete the registration
    on your Headscale server and it also prints the Auth ID required to approve the node:

    ```console
    headscale auth register --user <USER> --auth-id <AUTH_ID>
    ```

    Headscale checks that `<USER>` is allowed to register a node with the specified tag(s) and then transfers ownership
    of the new node to the special user `tagged-devices`. The registration of a tagged node is complete and it should be
    listed as "online" in the output of `headscale nodes list`. The "User" column displays `tagged-devices` as the owner
    of the node. See the "Tags" column for the list of assigned tags.

### Local password invitation (fork development only)

This fork has an administrator-only CLI command for an **existing** local user. It does not create a user, change an email address, send email, or register a device. An opt-in HTTPS-proxy-gated enrollment page and POST can now set or renew a password for an existing local user. **Do not send invitation links or deploy this intermediate build yet**: browser, proxy, authorization and end-to-end security verification remain pending, as does a separate production decision. The command issues a new one-time secret; issuing another invitation replaces the prior outstanding link. It can also be used to renew a password after enrollment is available.

```console
headscale users invite --identifier <USER_ID> --origin https://<HEADSCALE_HOST> --lifetime 24h
# The same operation is available as: headscale users renew-password
```

`--origin` may be omitted only if the configured `server_url` is a plain HTTPS origin with an ICANN-registrable DNS hostname; IP literals, non-ICANN/private suffixes, `.onion` and infrastructure `.arpa` names are refused. The CLI does not resolve DNS or verify TLS, so the operator must verify public reachability and the certificate before deployment. The maximum lifetime is `168h`; `--lifetime` requires whole seconds. The CLI displays the link once on stdout (or in `--output json`, `json-line`, or `yaml`), and it must be delivered manually through a trusted channel. Its secret is in the URL fragment, not the HTTP path or query. Treat saved terminal output and structured output as credentials; do not paste them into logs. The page removes the URL fragment in a first-party script; its POST requires matching Origin and one host-bound Secure CSRF cookie/form token, caps the body, applies shared IP/secret attempt limits, and atomically consumes the invitation with password storage. Rejected, expired and replayed links receive the same generic error. The opt-in device registration page verifies a local password, displays the device identity and requested tags for review, then requires a separate explicit confirmation POST before the pending device is registered under the authenticated user. Approval state expires after ten minutes and can be used once; a request for tags the authenticated user cannot claim is rejected rather than assigning those tags. **Do not deliver invitation links or deploy** until the real browser, public HTTPS proxy and isolated end-to-end checks pass and a separate production decision is made. End-to-end browser, HTTPS proxy/logging and security verification remain pending. Disabled-mode CLI registration and OIDC remain unchanged.

### Pre authenticated key

Registration with a pre authenticated key (or auth key) is a non-interactive way to register a new node. The Headscale
administrator creates a preauthkey upfront and this preauthkey can then be used to register a node non-interactively.
Its best suited for automation.

=== "Personal devices"

    A personal node is always assigned to a Headscale user. Use the `headscale users` command to create a new user[^1]:

    ```console
    headscale users create <USER>
    ```

    Use the `headscale user list` command to learn its `<USER_ID>` and create a new pre authenticated key for your user:

    ```console
    headscale preauthkeys create --user <USER_ID>
    ```

    The above prints a pre authenticated key with the default settings (can be used once and is valid for one hour). Use
    this auth key to register a node non-interactively:

    ```console
    tailscale up --login-server <YOUR_HEADSCALE_URL> --authkey <YOUR_AUTH_KEY>
    ```

    Congrations, the registration of your personal node is complete and it should be listed as "online" in the output of
    `headscale nodes list`. The "User" column displays `<USER>` as the owner of the node.

=== "Tagged devices"

    Create a new pre authenticated key and provide at least one tag:

    ```console
    headscale preauthkeys create --tags tag:<TAG>
    ```

    The above prints a pre authenticated key with the default settings (can be used once and is valid for one hour). Use
    this auth key to register a node non-interactively. You don't need to provide the `--advertise-tags` parameter as
    the tags are automatically read from the pre authenticated key:

    ```console
    tailscale up --login-server <YOUR_HEADSCALE_URL> --authkey <YOUR_AUTH_KEY>
    ```

    The registration of a tagged node is complete and it should be listed as "online" in the output of
    `headscale nodes list`. The "User" column displays `tagged-devices` as the owner of the node. See the "Tags" column for the list of
    assigned tags.

[^1]: [Ensure that the Headscale username does not end with `@`.](oidc.md#reference-a-user-in-the-policy)
