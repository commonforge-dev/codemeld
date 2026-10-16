// Pre-request credential failure a provider.Client raises when the selected provider has no usable credential.
package provider

// CredentialUnavailableError is returned by a provider.Client when the selected
// provider has no usable credential for the turn and the turn must fail without
// falling back to another provider. It is a pre-request failure — no HTTP request
// reached the network — so it is distinct from *HTTPError and *HTTPBodyError and is
// never routed through the transport classifier. Surface is a safe, provider-named,
// credential-free remediation message the turn layer renders verbatim as the failure
// notice. No provider_request_failed event is emitted for it: the reason set
// has no auth phase and there is no transport outcome to record (the OpenAI ChatGPT
// wiring raises it for a missing/invalid/expired session or a failed token refresh).
type CredentialUnavailableError struct {
	Surface string
}

func (e *CredentialUnavailableError) Error() string { return e.Surface }
