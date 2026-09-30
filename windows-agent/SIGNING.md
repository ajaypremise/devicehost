# WindowsProtect signing

The test workflow produces an **unsigned** build unless `WINDOWS_SIGNING_ENABLED=true`.
A product icon, administrator manifest and version information do not establish a verified publisher.

The workflow supports Azure Artifact Signing with OIDC, following the official action:
https://github.com/Azure/artifact-signing-action

After the owner has an eligible, identity-verified signing account and a **Public Trust** certificate profile:

1. Configure a federated Azure identity for `ajaypremise/devicehost` on `main`, with the certificate-profile signing role. Do not grant subscription-wide permissions.
2. Add repository secrets `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`.
3. Set repository variables `WINDOWS_SIGNING_ENDPOINT`, `WINDOWS_SIGNING_ACCOUNT`, `WINDOWS_SIGNING_PROFILE` and `WINDOWS_SIGNING_ENABLED=true`.
4. Run the WindowsProtect workflow. It signs the service before embedding, then signs the finished installer, verifies all signatures, and hashes the final files. Any configured signing failure stops the build.

Azure eligibility varies by jurisdiction. Check current availability before purchasing or creating resources. A CA-issued signing identity through another supported cloud/HSM provider is another route and needs that provider's CI integration.

Trusted signing does **not** guarantee immediate SmartScreen reputation. Never disable Defender, SmartScreen or UAC to hide installer prompts. The normal administrator consent prompt is expected because setup installs a system service.

Microsoft documentation:
- https://learn.microsoft.com/windows/apps/package-and-deploy/smartscreen-reputation
- https://learn.microsoft.com/windows/apps/package-and-deploy/code-signing-options
