package br.danielwilson.todolist.Filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.danielwilson.todolist.user.IUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

    @Autowired
    private IUserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        var serveletPath = request.getServletPath();

        if (serveletPath.startsWith("/tasks/")) {

            var authorization = request.getHeader("Authorization");

            var authDecode = authorization.substring("Basic".length()).trim();

            var decoded = Base64.getDecoder().decode(authDecode);

            var auth = new String(decoded);

            String[] credentials = auth.split(":");

            var username = credentials[0];
            var password = credentials[1];

            var user = this.userRepository.findByUsername(username);

            if (user == null || !BCrypt.verifyer().verify(password.toCharArray(), user.getPassword()).verified) {

                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }

            request.setAttribute("idUser", user.getId());

            filterChain.doFilter(request, response);
        }
        filterChain.doFilter(request, response);
    }

}
