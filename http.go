package escalation

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"google.golang.org/api/cloudresourcemanager/v1"

	"github.com/blendle/zapdriver"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type TokenClaims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	HD            string `json:"hd"`
	jwt.StandardClaims
}

var logger *zap.Logger = newLogger(zapcore.InfoLevel)

type policyManager struct{}

type policyManagerService interface {
	getPolicy(ctx context.Context, crmService *cloudresourcemanager.Service, projectID string) (*cloudresourcemanager.Policy, error)
	setPolicy(ctx context.Context, crmService *cloudresourcemanager.Service, projectID string, policy *cloudresourcemanager.Policy, member, role string) ([]*cloudresourcemanager.Binding, error)
}

// EscalatePermissions temporarily escalates the IAM permissions for the caller
func EscalatePermissions(w http.ResponseWriter, r *http.Request) {

	var pm policyManagerService = &policyManager{}

	role := os.Getenv("IAM_ROLE")
	projectID := os.Getenv("PROJECT_ID")

	if projectID == "" {
		logger.Error("env variable 'PROJECT_ID' not set")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if role == "" {
		logger.Error("env variable 'IAM_ROLE' not set")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// only allow custom roles to be used for escalations
	if !strings.HasPrefix(role, fmt.Sprintf("projects/%s/roles/yourorg.", projectID)) {
		logger.Error("role must be a custom yourorg role")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	expirationMinutes, err := strconv.Atoi(os.Getenv("EXPIRATION_MINUTES"))
	if err != nil {
		logger.Error("env variable'EXPIRATION_MINUTES' is invalid", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	expiration := time.Now().UTC().Add(time.Duration(expirationMinutes) * time.Minute)
	authorizationParts := strings.Split(r.Header.Get("Authorization"), "bearer ")
	if len(authorizationParts) != 2 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	email, err := getEmailFromJWT(authorizationParts[1])
	if err != nil {
		logger.Error("could not extract user from token", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	member := "user:" + *email

	crmService, err := cloudresourcemanager.NewService(r.Context())
	if err != nil {
		logger.Error("could not create cloudresourcemanager", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	_, err = addMember(r.Context(), pm, crmService, projectID, member, role, expiration)
	if err != nil {
		logger.Error("could not add member", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// addMember adds the member to the project's IAM policy for a limited period of time
func addMember(ctx context.Context, pm policyManagerService, crmService *cloudresourcemanager.Service, projectID, member, role string, expiration time.Time) ([]*cloudresourcemanager.Binding, error) {

	// expressions are at the same level as members in bindings so we use title to scope the expression to a user
	expression := &cloudresourcemanager.Expr{
		Title:       generateTitle(member),
		Description: "time limited permission escalation",
		Expression:  fmt.Sprintf("request.time < timestamp('%s')", expiration.Format(time.RFC3339)),
	}

	policy, err := pm.getPolicy(ctx, crmService, projectID)
	if err != nil {
		return nil, err
	}

	var binding *cloudresourcemanager.Binding
	for _, b := range policy.Bindings {
		if b.Role == role && b.Condition != nil && b.Condition.Title == expression.Title {
			// binding exists - ok to modify existing binding
			binding = b
			break
		}
	}

	if binding != nil {
		// If the binding exists, adds the member to the binding
		binding.Members = append(binding.Members, member)
		binding.Condition = expression
	} else {
		// If the binding does not exist, add a new binding to the policy
		binding = &cloudresourcemanager.Binding{
			Condition: expression,
			Role:      role,
			Members:   []string{member},
		}
		policy.Bindings = append(policy.Bindings, binding)
	}

	policy.Version = 3 // must update version when using condition

	bindings, err := pm.setPolicy(ctx, crmService, projectID, policy, member, role)
	if err != nil {
		return nil, err
	}
	logger.Info("CF escalate permissions for user", zap.String("member", member), zap.String("role", role), zap.Time("expiration", expiration))
	return bindings, nil
}

// getPolicy gets the project's IAM policy
func (pm *policyManager) getPolicy(ctx context.Context, crmService *cloudresourcemanager.Service, projectID string) (*cloudresourcemanager.Policy, error) {

	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	request := new(cloudresourcemanager.GetIamPolicyRequest)
	request.Options = &cloudresourcemanager.GetPolicyOptions{
		RequestedPolicyVersion: 3,
	}
	policy, err := crmService.Projects.GetIamPolicy(projectID, request).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("Projects.GetIamPolicy: %w", err)
	}

	return policy, nil
}

// setPolicy sets the project's IAM policy
func (pm *policyManager) setPolicy(ctx context.Context, crmService *cloudresourcemanager.Service, projectID string, policy *cloudresourcemanager.Policy, member, role string) ([]*cloudresourcemanager.Binding, error) {

	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	request := new(cloudresourcemanager.SetIamPolicyRequest)

	request.Policy = policy
	policy, err := crmService.Projects.SetIamPolicy(projectID, request).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("Projects.SetIamPolicy: %w", err)
	}
	return policy.Bindings, nil
}

func generateTitle(member string) string {
	return "incident escalation - " + member
}

func getEmailFromJWT(tokenString string) (*string, error) {
	// GCP verifies token before invoking the CF so no need to verify again
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, &TokenClaims{})
	if err != nil {
		return nil, fmt.Errorf("token not parsable: %w", err)
	}

	// validate some custom claims and get the member's email
	if claims, ok := token.Claims.(*TokenClaims); ok {
		if claims.Issuer != "https://accounts.google.com" && claims.Issuer != "accounts.google.com" {
			return nil, errors.New("token issuer invalid")
		}
		if claims.HD != "yourorg.com" {
			return nil, errors.New("token from non G-Suite domain member")
		}
		if !claims.EmailVerified {
			return nil, errors.New("token email not verified")
		}
		return &claims.Email, nil
	}
	return nil, errors.New("invalid token")
}

// newLogger create a zap Logger with configurations set appropriate for
// production and is compliant with the GCP/Stackdriver format.
func newLogger(level zapcore.Level) *zap.Logger {
	atom := zap.NewAtomicLevel()
	atom.SetLevel(level)

	logger := zap.New(zapcore.NewSamplerWithOptions(zapcore.NewCore(
		zapcore.NewJSONEncoder(zapdriver.NewProductionEncoderConfig()),
		zapcore.Lock(os.Stdout),
		atom,
	), time.Second, 100, 10),
		zap.ErrorOutput(zapcore.Lock(os.Stderr)), zap.AddCaller(),
	)
	return logger
}
