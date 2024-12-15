package common

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	usernamePattern = `?()/\+=\s\n`
	passwordPattern = `^<>;.*&|£\n\s`
	usernameRegex   = `(?im)(?:user|usr)\S{0,40}?[:=\s]{1,3}[ '"=]{0,1}([^:?()/\+=\s\n]{4,40})\b`
	passwordRegex   = `(?im)(?:pass|password)\S{0,40}?[:=\s]{1,3}[ '"=]{0,1}([^:^<>;.*&|£\n\s]{4,40})`
)

func TestEmailRegexCheck(t *testing.T) {
	testEmails := `
		// positive cases
		standard email     = john.doe@example.com
		subdomain email    = jane_doe123@sub.domain.co.us
		organization email = alice.smith@test.org
		test email         = bob@test.name
		with tag email     = user.name+tag@domain.com
		hyphen domain      = info@my-site.net
		service email      = contact@web-service.io
		underscore email   = example_user@domain.info
		department email   = first.last@department.company.edu
		alphanumeric email = user1234@domain.co
		local server email = admin@local-server.local
		dot email          = test.email@my-email-service.xyz
		special char email = special@characters.com
		support email      = support@customer-service.org

		// negative cases
		not an email       = abc.123@z
		looks like email   = test@user <- no domain
		email but not      = user12@service.COM <- capital letters not supported for domain
		random text        = here's some information about local-user@edu user
	`

	expectedStr := []string{
		"john.doe@example.com", "jane_doe123@sub.domain.co.us",
		"alice.smith@test.org", "bob@test.name", "user.name+tag@domain.com",
		"info@my-site.net", "contact@web-service.io", "example_user@domain.info",
		"first.last@department.company.edu", "user1234@domain.co", "admin@local-server.local",
		"test.email@my-email-service.xyz", "special@characters.com", "support@customer-service.org",
	}

	emailRegex := regexp.MustCompile(EmailPattern)

	emailMatches := emailRegex.FindAllString(testEmails, -1)

	assert.Exactly(t, emailMatches, expectedStr)

}

func TestUsernameRegexCheck(t *testing.T) {
	usernameRegexPat := UsernameRegexCheck(usernamePattern)

	expectedRegexPattern := regexp.MustCompile(usernameRegex)

	if usernameRegexPat.compiledRegex.String() != expectedRegexPattern.String() {
		t.Errorf("\n got %v \n want %v", usernameRegexPat.compiledRegex, expectedRegexPattern)
	}

	testString := `username = "johnsmith123"
                   username='johnsmith123'
				   username:="johnsmith123"
                   username = johnsmith123
                   username=johnsmith123`

	expectedStr := []string{"johnsmith123", "johnsmith123", "johnsmith123", "johnsmith123", "johnsmith123"}

	usernameRegexMatches := usernameRegexPat.Matches([]byte(testString))

	assert.Exactly(t, usernameRegexMatches, expectedStr)

}

func TestPasswordRegexCheck(t *testing.T) {
	passwordRegexPat := PasswordRegexCheck(passwordPattern)

	expectedRegexPattern := regexp.MustCompile(passwordRegex)
	assert.Equal(t, passwordRegexPat.compiledRegex, expectedRegexPattern)

	testString := `password = "johnsmith123$!"
                   password='johnsmith123$!'
				   password:="johnsmith123$!"
                   password = johnsmith123$!
                   password=johnsmith123$!
				   PasswordAuthenticator(username, "johnsmith123$!")`

	expectedStr := []string{"johnsmith123$!", "johnsmith123$!", "johnsmith123$!", "johnsmith123$!", "johnsmith123$!",
		"johnsmith123$!"}

	passwordRegexMatches := passwordRegexPat.Matches([]byte(testString))

	assert.Exactly(t, passwordRegexMatches, expectedStr)

}

func TestLowerChars(t *testing.T) {
	result := LowerChars()
	assert.Equal(t, "abcdefghijklmnopqrstuvwxyz", result)
	assert.Len(t, result, 26)
}

func TestUpperChars(t *testing.T) {
	result := UpperChars()
	assert.Equal(t, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", result)
	assert.Len(t, result, 26)
}

func TestNumericChars(t *testing.T) {
	result := NumericChars()
	assert.Equal(t, "0123456789", result)
	assert.Len(t, result, 10)
}

func TestAlphaNumericChars(t *testing.T) {
	result := AlphaNumericChars()
	// Test length.
	assert.Len(t, result, 62) // 26 lowercase + 26 uppercase + 10 digits

	assert.Contains(t, result, "a")
	assert.Contains(t, result, "z")
	assert.Contains(t, result, "A")
	assert.Contains(t, result, "Z")
	assert.Contains(t, result, "0")
	assert.Contains(t, result, "9")
}

func TestHexChars(t *testing.T) {
	result := HexChars()
	assert.Equal(t, "abcdef0123456789", result)
	assert.Len(t, result, 16)
}

func TestUnionChars(t *testing.T) {
	tests := []struct {
		name     string
		inputs   []string
		expected int // length of expected result
	}{
		{
			name:     "empty input",
			inputs:   []string{},
			expected: 0,
		},
		{
			name:     "single input",
			inputs:   []string{"abc"},
			expected: 3,
		},
		{
			name:     "duplicate chars",
			inputs:   []string{"aaa", "aaa"},
			expected: 1,
		},
		{
			name:     "mixed case no overlap",
			inputs:   []string{"abc", "ABC"},
			expected: 6,
		},
		{
			name:     "with numbers",
			inputs:   []string{"123", "abc"},
			expected: 6,
		},
		{
			name:     "all char types",
			inputs:   []string{LowerChars(), UpperChars(), NumericChars()},
			expected: 62,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := UnionChars(tt.inputs...)
			assert.Len(t, result, tt.expected)

			// Verify no duplicates.
			seen := make(map[rune]bool)
			for _, r := range result {
				assert.False(t, seen[r], "found duplicate character: %c", r)
				seen[r] = true
			}
		})
	}
}
