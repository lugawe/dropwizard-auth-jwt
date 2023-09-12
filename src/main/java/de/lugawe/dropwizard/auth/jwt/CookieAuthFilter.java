package de.lugawe.dropwizard.auth.jwt;

import io.dropwizard.auth.AuthFilter;
import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.SecurityContext;
import java.security.Principal;
import java.util.Map;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Priority(Priorities.AUTHENTICATION)
public class CookieAuthFilter<P extends Principal> extends AuthFilter<String, P> {

    private static final Logger log = LoggerFactory.getLogger(CookieAuthFilter.class);

    protected final String cookieName;

    protected CookieAuthFilter(String cookieName) {
        this.cookieName = Objects.requireNonNull(cookieName, "cookieName");
    }

    @Override
    public void filter(ContainerRequestContext requestContext) {

        Map<String, Cookie> cookies = requestContext.getCookies();
        if (cookies == null || cookies.isEmpty() || !cookies.containsKey(cookieName)) {
            log.debug("no valid cookie found: {}", cookieName);
            throw unauthorizedHandler.buildException(prefix, realm);
        }

        if (!authenticate(requestContext, cookies.get(cookieName).getValue(), SecurityContext.BASIC_AUTH)) {
            throw unauthorizedHandler.buildException(prefix, realm);
        }
    }

    public static class Builder<P extends Principal> extends AuthFilterBuilder<String, P, CookieAuthFilter<P>> {

        private String cookieName;

        public Builder() {}

        public Builder<P> setCookieName(String cookieName) {
            this.cookieName = cookieName;
            return this;
        }

        @Override
        protected CookieAuthFilter<P> newInstance() {
            return new CookieAuthFilter<>(cookieName);
        }
    }
}
