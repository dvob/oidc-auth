package testissuer

// UserClaimFunc returns extra claims for a particular user.
type UserClaimFunc func(user string) map[string]any

func StaticUserClaims(userMap map[string]map[string]any) UserClaimFunc {
	return func(user string) map[string]any {
		claims := userMap[user]
		return claims
	}
}

func DefaultUserClaims() UserClaimFunc {
	return func(user string) map[string]any {
		return map[string]any{
			"email": user + "@localhost.local",
			"groups": []string{
				"group1",
				"group2",
			},
		}
	}
}
