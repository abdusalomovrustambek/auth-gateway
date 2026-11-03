package account

import (
	"strings"
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	hash, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Errorf("hash %q is not a PHC argon2id string", hash)
	}

	tests := []struct {
		name     string
		password string
		want     bool
	}{
		{"right password", "correct horse battery", true},
		{"wrong password", "correct horse batterz", false},
		{"empty password", "", false},
		{"prefix of the password", "correct horse", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := VerifyPassword(tt.password, hash)
			if err != nil {
				t.Fatalf("VerifyPassword: %v", err)
			}
			if got != tt.want {
				t.Errorf("VerifyPassword = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHashesDiffer(t *testing.T) {
	a, err := HashPassword("same password here")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	b, err := HashPassword("same password here")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if a == b {
		t.Error("two hashes of the same password are equal: the salt is not random")
	}
}

func TestVerifyMalformedHash(t *testing.T) {
	tests := []struct {
		name    string
		encoded string
	}{
		{"empty", ""},
		{"plain text", "hunter2"},
		{"wrong algorithm", "$argon2i$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaA"},
		{"too few parts", "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA"},
		{"bad version", "$argon2id$v=x$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaA"},
		{"bad params", "$argon2id$v=19$m=x,t=2,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaA"},
		{"zero threads", "$argon2id$v=19$m=19456,t=2,p=0$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaA"},
		{"huge memory", "$argon2id$v=19$m=4000000,t=2,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaA"},
		{"bad salt", "$argon2id$v=19$m=19456,t=2,p=1$!!!$aGFzaGhhc2hoYXNoaGFzaA"},
		{"bad hash", "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$!!!"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, err := VerifyPassword("anything", tt.encoded)
			if err == nil {
				t.Error("want an error for a malformed hash")
			}
			if ok {
				t.Error("a malformed hash verified")
			}
		})
	}
}
