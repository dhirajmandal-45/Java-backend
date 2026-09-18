package ecommerce.back.security;

import java.io.IOException;
import java.util.List;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    public JwtAuthFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    // ============================================================
    // SKIP JWT FILTER FOR LOGIN AND SIGNUP
    // ============================================================
    // Users don't have a JWT token when they are signing up
    // or logging in.
    //
    // Therefore, JWT checking is not required for these endpoints.
    // ============================================================

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {

        String path = request.getServletPath();

        return path.equals("/freshers/signup")
                || path.equals("/freshers/login");
    }

    // ============================================================
    // JWT FILTER
    // ============================================================
    // This method runs for requests that pass through
    // the JWT authentication filter.
    //
    // Example:
    //
    // GET /users/profile
    // GET /admin/products
    //
    // Frontend sends:
    //
    // Authorization: Bearer <JWT>
    // ============================================================

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws ServletException, IOException {

        // ========================================================
        // 1. GET AUTHORIZATION HEADER
        // ========================================================
        // The frontend sends the JWT inside this header.
        //
        // Example:
        //
        // Authorization: Bearer eyJhbGciOiJIUzI1...
        // ========================================================

        String authHeader = request.getHeader("Authorization");

        // ========================================================
        // 2. CHECK WHETHER JWT EXISTS
        // ========================================================
        // If there is no Authorization header,
        // continue the request.
        //
        // Spring Security will decide later whether
        // authentication is required for this endpoint.
        // ========================================================

        if (authHeader == null ||
                !authHeader.startsWith("Bearer ")) {

            filterChain.doFilter(request, response);
            return;
        }

        // ========================================================
        // 3. REMOVE "Bearer "
        // ========================================================
        // Example:
        //
        // "Bearer abc123"
        //
        // becomes:
        //
        // "abc123"
        // ========================================================

        String token = authHeader.substring(7);

        try {

            // ====================================================
            // 4. EXTRACT EMAIL FROM JWT
            // ====================================================
            // JwtService stores the user's email
            // as the JWT subject.
            // ====================================================

            String email = jwtService.extractUsername(token);

            // ====================================================
            // 5. EXTRACT ROLE FROM JWT
            // ====================================================
            // Example:
            //
            // ADMIN
            // USER
            //
            // This role will be used by Spring Security
            // to protect admin routes.
            // ====================================================

            String role = jwtService.extractRole(token);

            // ====================================================
            // 6. VALIDATE JWT
            // ====================================================
            // Check that:
            //
            // - JWT signature is valid
            // - JWT is not expired
            // - JWT is a valid token
            // ====================================================

            if (email != null &&
                    jwtService.isTokenValid(token)) {

                // =================================================
                // 7. CREATE SPRING SECURITY AUTHORITY
                // =================================================
                // Spring Security's:
                //
                // hasRole("ADMIN")
                //
                // internally expects:
                //
                // ROLE_ADMIN
                //
                // Therefore:
                //
                // ADMIN → ROLE_ADMIN
                // USER → ROLE_USER
                // =================================================

                SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_" + role);

                // =================================================
                // 8. CREATE AUTHENTICATION OBJECT
                // =================================================
                // This tells Spring Security:
                //
                // "This request belongs to this user."
                //
                // We also provide the user's role/authority.
                // =================================================

                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        email,
                        null,
                        List.of(authority));

                // =================================================
                // 9. SAVE AUTHENTICATION
                // =================================================
                // Store the authenticated user in Spring's
                // SecurityContext.
                //
                // Now Spring knows:
                //
                // User → email
                // Role → ROLE_USER / ROLE_ADMIN
                // =================================================

                SecurityContextHolder
                        .getContext()
                        .setAuthentication(authentication);
            }

        } catch (Exception e) {

            // ====================================================
            // INVALID JWT
            // ====================================================
            // If the token is:
            //
            // - expired
            // - corrupted
            // - incorrectly signed
            // - invalid
            //
            // the user will not be authenticated.
            // ====================================================

            System.out.println(
                    "Invalid JWT: " + e.getMessage());
        }

        // ========================================================
        // 10. CONTINUE REQUEST
        // ========================================================
        // Pass the request to the next filter/controller.
        // ========================================================

        filterChain.doFilter(request, response);
    }
}