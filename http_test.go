package escalation

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/api/cloudresourcemanager/v1"
)

type policyManagerMock struct {
	getPolicyFunc func(ctx context.Context, crmService *cloudresourcemanager.Service, projectID string) (*cloudresourcemanager.Policy, error)
	setPolicyFunc func(ctx context.Context, crmService *cloudresourcemanager.Service, projectID string, policy *cloudresourcemanager.Policy, member, role string) ([]*cloudresourcemanager.Binding, error)
}

func (pmm *policyManagerMock) getPolicy(ctx context.Context, crmService *cloudresourcemanager.Service, projectID string) (*cloudresourcemanager.Policy, error) {
	return pmm.getPolicyFunc(ctx, crmService, projectID)
}

func (pmm *policyManagerMock) setPolicy(ctx context.Context, crmService *cloudresourcemanager.Service, projectID string, policy *cloudresourcemanager.Policy, member, role string) ([]*cloudresourcemanager.Binding, error) {
	return pmm.setPolicyFunc(ctx, crmService, projectID, policy, member, role)
}

func Test_AddMember(t *testing.T) {

	member := "joe.random@yourorg.com"
	roleName := "roles/product.rolename"

	tests := []struct {
		name                     string
		policyManager            *policyManagerMock
		expectedNumberOfBindings int
	}{
		{
			name: "no bindings - create new binding",
			policyManager: &policyManagerMock{
				getPolicyFunc: func(ctx context.Context, crmService *cloudresourcemanager.Service, projectID string) (*cloudresourcemanager.Policy, error) {
					return &cloudresourcemanager.Policy{}, nil
				},
				setPolicyFunc: func(ctx context.Context, crmService *cloudresourcemanager.Service, projectID string, policy *cloudresourcemanager.Policy, member, role string) ([]*cloudresourcemanager.Binding, error) {
					return policy.Bindings, nil
				},
			},
			expectedNumberOfBindings: 1,
		},
		{
			name: "no binding for role - create new binding",
			policyManager: &policyManagerMock{
				getPolicyFunc: func(ctx context.Context, crmService *cloudresourcemanager.Service, projectID string) (*cloudresourcemanager.Policy, error) {
					return &cloudresourcemanager.Policy{
						Bindings: []*cloudresourcemanager.Binding{},
					}, nil
				},
				setPolicyFunc: func(ctx context.Context, crmService *cloudresourcemanager.Service, projectID string, policy *cloudresourcemanager.Policy, member, role string) ([]*cloudresourcemanager.Binding, error) {
					return policy.Bindings, nil
				},
			},
			expectedNumberOfBindings: 1,
		},
		{
			name: "existing binding for role with same condition title - override exisiting binding",
			policyManager: &policyManagerMock{
				getPolicyFunc: func(ctx context.Context, crmService *cloudresourcemanager.Service, projectID string) (*cloudresourcemanager.Policy, error) {
					return &cloudresourcemanager.Policy{
						Bindings: []*cloudresourcemanager.Binding{
							{
								Role: roleName,
								Condition: &cloudresourcemanager.Expr{
									Title: generateTitle(member),
								},
							},
						},
					}, nil
				},
				setPolicyFunc: func(ctx context.Context, crmService *cloudresourcemanager.Service, projectID string, policy *cloudresourcemanager.Policy, member, role string) ([]*cloudresourcemanager.Binding, error) {
					return policy.Bindings, nil
				},
			},
			expectedNumberOfBindings: 1,
		},
		{
			name: "existing binding for role with no condition - create new binding and dont touch existing one",
			policyManager: &policyManagerMock{
				getPolicyFunc: func(ctx context.Context, crmService *cloudresourcemanager.Service, projectID string) (*cloudresourcemanager.Policy, error) {
					return &cloudresourcemanager.Policy{
						Bindings: []*cloudresourcemanager.Binding{
							{
								Role: roleName,
							},
						},
					}, nil
				},
				setPolicyFunc: func(ctx context.Context, crmService *cloudresourcemanager.Service, projectID string, policy *cloudresourcemanager.Policy, member, role string) ([]*cloudresourcemanager.Binding, error) {
					return policy.Bindings, nil
				},
			},
			expectedNumberOfBindings: 2,
		},
		{
			name: "existing binding for role with existing unrecognised condition - create new binding and dont touch existing one",
			policyManager: &policyManagerMock{
				getPolicyFunc: func(ctx context.Context, crmService *cloudresourcemanager.Service, projectID string) (*cloudresourcemanager.Policy, error) {
					return &cloudresourcemanager.Policy{
						Bindings: []*cloudresourcemanager.Binding{
							{
								Role: roleName,
								Condition: &cloudresourcemanager.Expr{
									Title: "unregonised condition",
								},
							},
						},
					}, nil
				},
				setPolicyFunc: func(ctx context.Context, crmService *cloudresourcemanager.Service, projectID string, policy *cloudresourcemanager.Policy, member, role string) ([]*cloudresourcemanager.Binding, error) {
					return policy.Bindings, nil
				},
			},
			expectedNumberOfBindings: 2,
		},
	}
	for _, test := range tests {
		tc := test
		t.Run(tc.name, func(t *testing.T) {
			bindings, err := addMember(context.Background(), tc.policyManager, nil, "random-project-id", member, roleName, time.Now())
			require.NoError(t, err)
			require.Len(t, bindings, tc.expectedNumberOfBindings)
		})
	}
}

func Test_GetMemberFromJWT(t *testing.T) {
	sampleJWT := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJpYXQiOjE2MDIxOTU1NDcsImV4cCI6MTYzMzczMTU0NywiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsImhkIjoieW91cm9yZy5jb20iLCJlbWFpbCI6InJhbmRvbS5ndXlAeW91cm9yZy5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZX0.NK9DPyqIdMpFgoc1Qm1BJvhibcbOXjeZek4j0pDMwDg`
	email, err := getEmailFromJWT(sampleJWT)
	require.NoError(t, err)
	require.Equal(t, "random.guy@yourorg.com", *email)
}
