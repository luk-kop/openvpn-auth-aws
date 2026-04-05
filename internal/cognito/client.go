package cognito

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"

	"openvpn-auth-aws/internal/auth"
)

type Checker struct {
	client     *cognitoidentityprovider.Client
	userPoolID string
}

func NewChecker(cfg aws.Config, userPoolID string) *Checker {
	return &Checker{
		client:     cognitoidentityprovider.NewFromConfig(cfg),
		userPoolID: userPoolID,
	}
}

func (c *Checker) CheckUser(ctx context.Context, username, requiredGroup string, checkGroups bool) (auth.IdentityResult, error) {
	result := auth.IdentityResult{CheckedAt: time.Now().UTC()}

	resp, err := c.client.AdminGetUser(ctx, &cognitoidentityprovider.AdminGetUserInput{
		UserPoolId: aws.String(c.userPoolID),
		Username:   aws.String(username),
	})
	if err != nil {
		var notFound *types.UserNotFoundException
		if errors.As(err, &notFound) {
			result.Exists = false
			return result, nil
		}
		result.FailureCause = fmt.Sprintf("cognito error: %v", err)
		return result, err
	}

	result.Exists = true
	result.Enabled = resp.Enabled && (resp.UserStatus == types.UserStatusTypeConfirmed || resp.UserStatus == types.UserStatusTypeExternalProvider)

	if checkGroups && requiredGroup != "" {
		paginator := cognitoidentityprovider.NewAdminListGroupsForUserPaginator(c.client, &cognitoidentityprovider.AdminListGroupsForUserInput{
			UserPoolId: aws.String(c.userPoolID),
			Username:   aws.String(username),
		})

		for paginator.HasMorePages() {
			groups, err := paginator.NextPage(ctx)
			if err != nil {
				result.FailureCause = fmt.Sprintf("list groups error: %v", err)
				return result, err
			}
			for _, g := range groups.Groups {
				if g.GroupName != nil && *g.GroupName == requiredGroup {
					result.InGroup = true
					break
				}
			}
			if result.InGroup {
				break
			}
		}
	} else {
		result.InGroup = true
	}

	return result, nil
}

// StaticChecker for testing
type StaticChecker struct {
	checkGroups bool
}

func NewStaticChecker(checkGroups bool) *StaticChecker {
	return &StaticChecker{checkGroups: checkGroups}
}

func (c *StaticChecker) CheckUser(_ context.Context, _ string, requiredGroup string, checkGroups bool) (auth.IdentityResult, error) {
	return auth.IdentityResult{
		Exists:    true,
		Enabled:   true,
		InGroup:   !checkGroups || requiredGroup == "" || c.checkGroups,
		CheckedAt: time.Now().UTC(),
	}, nil
}
