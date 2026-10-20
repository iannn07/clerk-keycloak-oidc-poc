package id.gaussian.keycloak.clerk;

import id.gaussian.keycloak.clerk.ClerkBridgeClient.ClerkUser;
import jakarta.ws.rs.core.MultivaluedMap;
import java.util.Optional;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.events.Details;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.services.managers.AuthenticationManager;

/**
 * Keycloak's username/password form, with Clerk as the password checker:
 * <ul>
 *   <li>user in the realm and linked to Clerk: Clerk checks the password;</li>
 *   <li>user not in the realm: found in Clerk, password checked by Clerk, then imported;</li>
 *   <li>anything else (plain Keycloak users, wrong passwords): Keycloak's own handling.</li>
 * </ul>
 * Users are imported only after Clerk confirms the password, so failed attempts leave nothing behind.
 */
public class ClerkPasswordForm extends UsernamePasswordForm {

    static final String CLERK_ID_ATTRIBUTE = "clerk_user_id";
    private static final Logger LOG = Logger.getLogger(ClerkPasswordForm.class);

    private final ClerkBridgeClient bridge;

    ClerkPasswordForm(KeycloakSession session, ClerkBridgeClient bridge) {
        super(session);
        this.bridge = bridge;
    }

    @Override
    protected boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> form) {
        String identifier = Optional.ofNullable(form.getFirst(AuthenticationManager.FORM_USERNAME)).orElse("").trim();
        String password = form.getFirst(CredentialRepresentation.PASSWORD);
        if (identifier.isEmpty() || password == null || password.isEmpty()) {
            return super.validateForm(context, form);
        }

        UserModel local = KeycloakModelUtils.findUserByNameOrEmail(context.getSession(), context.getRealm(), identifier);
        if (local != null && local.getFirstAttribute(CLERK_ID_ATTRIBUTE) == null) {
            return super.validateForm(context, form);
        }

        Optional<UserModel> user;
        try {
            user = local != null ? verifyLinked(local, password) : importIfVerified(context, identifier, password);
        } catch (ClerkBridgeClient.BridgeException e) {
            LOG.errorf(e, "Clerk bridge failed for '%s'; refusing login", identifier);
            user = Optional.empty();
        }

        // Falling back to Keycloak's own check produces the standard "invalid username or password"
        // response and brute-force bookkeeping; a Clerk-linked user has no local password, so it fails.
        if (user.isEmpty()) {
            return super.validateForm(context, form);
        }
        if (!enabledUser(context, user.get())) {
            return false;
        }
        context.getEvent().user(user.get()).detail(Details.USERNAME, identifier);
        context.setUser(user.get());
        return true;
    }

    private Optional<UserModel> verifyLinked(UserModel local, String password) {
        String clerkId = local.getFirstAttribute(CLERK_ID_ATTRIBUTE);
        if (bridge.get(clerkId).isEmpty()) {
            LOG.warnf("User '%s' is linked to Clerk user %s, which no longer exists", local.getUsername(), clerkId);
            return Optional.empty();
        }
        return bridge.verifyPassword(clerkId, password) ? Optional.of(local) : Optional.empty();
    }

    private Optional<UserModel> importIfVerified(AuthenticationFlowContext context, String identifier, String password) {
        Optional<ClerkUser> found = bridge.lookup(identifier);
        if (found.isEmpty() || !bridge.verifyPassword(found.get().id(), password)) {
            return Optional.empty();
        }
        ClerkUser clerk = found.get();
        String username = clerk.username() != null && !clerk.username().isBlank() ? clerk.username() : clerk.email();
        try {
            UserModel user = context.getSession().users().addUser(context.getRealm(), username);
            user.setEnabled(true);
            user.setEmail(clerk.email());
            user.setEmailVerified(clerk.emailVerified());
            user.setFirstName(clerk.firstName());
            user.setLastName(clerk.lastName());
            user.setSingleAttribute(CLERK_ID_ATTRIBUTE, clerk.id());
            LOG.infof("Imported Clerk user %s as '%s'", clerk.id(), username);
            return Optional.of(user);
        } catch (ModelDuplicateException e) {
            LOG.warnf("Cannot import Clerk user %s: '%s' or its email already exists in the realm", clerk.id(), username);
            return Optional.empty();
        }
    }
}
