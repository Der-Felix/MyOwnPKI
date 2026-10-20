package httpapi

import "net/http"

// table is the route table: operation ID, method and path as in
// api/openapi.yaml. The contract tests read the spec and check every row.
func (a *API) table() []Route {
	return []Route{
		{OperationID: "getSystemStatus", Method: http.MethodGet, Path: "/system/status", access: signedIn, passive: true, handle: a.systemStatus},
		{OperationID: "unseal", Method: http.MethodPost, Path: "/system/unseal", access: signedIn, body: true, handle: a.unseal},
		{OperationID: "seal", Method: http.MethodPost, Path: "/system/seal", access: signedIn, handle: a.seal},

		{OperationID: "login", Method: http.MethodPost, Path: "/auth/login", access: public, body: true, handle: a.login},
		{OperationID: "verifyTOTP", Method: http.MethodPost, Path: "/auth/totp", access: public, body: true, handle: a.secondFactor},
		{OperationID: "stepUp", Method: http.MethodPost, Path: "/auth/step-up", access: signedIn, body: true, handle: a.stepUp},
		{OperationID: "getSession", Method: http.MethodGet, Path: "/auth/session", access: signedIn, passive: true, handle: a.getSession},
		{OperationID: "beginWebAuthnLogin", Method: http.MethodPost, Path: "/auth/webauthn/begin", access: public, handle: a.passkeyBegin},
		{OperationID: "finishWebAuthnLogin", Method: http.MethodPost, Path: "/auth/webauthn/finish", access: public, body: true, handle: a.passkeyFinish},
		{OperationID: "logout", Method: http.MethodPost, Path: "/auth/logout", access: signedIn, handle: a.logout},

		{OperationID: "listWebAuthnCredentials", Method: http.MethodGet, Path: "/users/me/webauthn", access: signedIn, handle: a.listPasskeys},
		{OperationID: "beginWebAuthnRegistration", Method: http.MethodPost, Path: "/users/me/webauthn/begin", access: signedIn, body: true, handle: a.passkeyRegisterBegin},
		{OperationID: "finishWebAuthnRegistration", Method: http.MethodPost, Path: "/users/me/webauthn/finish", access: signedIn, body: true, handle: a.passkeyRegisterFinish},
		{OperationID: "deleteWebAuthnCredential", Method: http.MethodDelete, Path: "/users/me/webauthn/{passkeyId}", access: signedIn, body: true, handle: a.deletePasskey},

		{OperationID: "listPresets", Method: http.MethodGet, Path: "/presets", access: signedIn, handle: a.listPresets},
		{OperationID: "getPreset", Method: http.MethodGet, Path: "/presets/{presetName}", access: signedIn, handle: a.getPreset},

		{OperationID: "listCAs", Method: http.MethodGet, Path: "/cas", access: signedIn, handle: a.listCAs},
		{OperationID: "getCA", Method: http.MethodGet, Path: "/cas/{caId}", access: signedIn, handle: a.getCA},
		{OperationID: "downloadCACertificate", Method: http.MethodGet, Path: "/cas/{caId}/certificate", access: signedIn, handle: a.downloadCACertificate},

		{OperationID: "listCertificates", Method: http.MethodGet, Path: "/certificates", access: signedIn, handle: a.listCertificates},
		{OperationID: "issueCertificate", Method: http.MethodPost, Path: "/certificates", access: signedIn, body: true, handle: a.issueCertificate},
		{OperationID: "getCertificate", Method: http.MethodGet, Path: "/certificates/{certificateId}", access: signedIn, handle: a.getCertificate},
		{OperationID: "downloadCertificate", Method: http.MethodGet, Path: "/certificates/{certificateId}/download/{format}", access: signedIn, handle: a.downloadCertificate},
		{OperationID: "exportCertificateWithKey", Method: http.MethodPost, Path: "/certificates/{certificateId}/export", access: signedIn, body: true, handle: a.exportKey},
	}
}
