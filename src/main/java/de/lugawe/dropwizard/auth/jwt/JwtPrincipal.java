package de.lugawe.dropwizard.auth.jwt;

import java.security.Principal;
import java.util.Set;

public interface JwtPrincipal extends Principal {

    Set<String> getRoles();
}
