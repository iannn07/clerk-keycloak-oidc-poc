package id.gaussian.keycloak.clerk;

import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;

/** Registers the Clerk password form. Reads CLERK_BRIDGE_URL and CLERK_BRIDGE_TOKEN from the environment. */
public class ClerkPasswordFormFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "clerk-username-password-form";

    private ClerkBridgeClient bridge;

    @Override
    public void init(Config.Scope config) {
        bridge = new ClerkBridgeClient(requireEnv("CLERK_BRIDGE_URL"), requireEnv("CLERK_BRIDGE_TOKEN"));
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new ClerkPasswordForm(session, bridge);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Clerk Username Password Form";
    }

    @Override
    public String getHelpText() {
        return "Username/password form whose passwords are checked by Clerk. Imports Clerk users after their first successful login.";
    }

    @Override
    public String getReferenceCategory() {
        return PasswordCredentialModel.TYPE;
    }

    @Override
    public Requirement[] getRequirementChoices() {
        return new Requirement[] {Requirement.REQUIRED};
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    private static String requireEnv(String key) {
        String value = System.getenv(key);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(key + " must be set for " + PROVIDER_ID);
        }
        return value;
    }
}
