package de.lugawe.dropwizard.auth.jwt;

import java.util.Collections;
import java.util.Objects;
import java.util.Set;

public class BasicJwtPrincipal implements JwtPrincipal {

    private final String name;
    private final Set<String> roles;

    public BasicJwtPrincipal(String name, Set<String> roles) {
        this.name = Objects.requireNonNull(name, "name");
        this.roles = Objects.requireNonNull(roles, "roles");
    }

    public BasicJwtPrincipal(String name) {
        this(name, Collections.emptySet());
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public Set<String> getRoles() {
        return Collections.unmodifiableSet(roles);
    }

    @Override
    public String toString() {
        return String.format("BasicJwtPrincipal{name=%s, roles=%s}", name, roles);
    }
}
