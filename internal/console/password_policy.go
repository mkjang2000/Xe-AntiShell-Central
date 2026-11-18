package console

import (
	"errors"
	"unicode/utf8"
)

// PasswordPolicyMessage is safe to show without including the supplied value.
const PasswordPolicyMessage = "비밀번호는 8자 이상이며 영문 소문자·숫자·특수문자(예: !@#$%, 공백 제외)를 모두 포함해야 합니다. 8~9자는 영문 대문자도 필요합니다. 최대 1,024 UTF-8 바이트입니다."

var ErrPasswordPolicy = errors.New(PasswordPolicyMessage)

// ValidateNewPassword applies only to a newly selected password. Existing
// credential verification must remain independent of current creation rules.
func ValidateNewPassword(password string) error {
	if len(password) > 1024 || !utf8.ValidString(password) {
		return ErrPasswordPolicy
	}
	count := utf8.RuneCountInString(password)
	if count < 8 {
		return ErrPasswordPolicy
	}
	var lower, upper, digit, punctuation bool
	for _, r := range password {
		switch {
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= '0' && r <= '9':
			digit = true
		case r >= '!' && r <= '/' || r >= ':' && r <= '@' || r >= '[' && r <= '`' || r >= '{' && r <= '~':
			punctuation = true
		}
	}
	if !lower || !digit || !punctuation || count < 10 && !upper {
		return ErrPasswordPolicy
	}
	return nil
}
