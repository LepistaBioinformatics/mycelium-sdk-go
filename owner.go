package mycelium

import (
	"strings"

	"github.com/google/uuid"
)

// Owner is a principal (or secondary) identity attached to a Profile.
type Owner struct {
	ID          uuid.UUID `json:"id"`
	Email       string    `json:"email"`
	FirstName   *string   `json:"firstName,omitempty"`
	LastName    *string   `json:"lastName,omitempty"`
	Username    *string   `json:"username,omitempty"`
	IsPrincipal bool      `json:"isPrincipal"`
}

// RedactedEmail returns the owner email with its local part masked.
func (o Owner) RedactedEmail() string {
	return redactEmail(o.Email)
}

// redactEmail masks the local part of an email, keeping the first character and
// the domain. Mirrors the mycelium-sdk-js redactEmail helper.
func redactEmail(email string) string {
	local, domain, found := strings.Cut(email, "@")
	if !found || local == "" || domain == "" {
		return email
	}
	stars := len(local) - 1
	if stars < 1 {
		stars = 1
	}
	return local[:1] + strings.Repeat("*", stars) + "@" + domain
}
