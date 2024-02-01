package med.voll.api.infra.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import med.voll.api.domain.usuario.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component //Carrega automaticamente uma classe genérica
public class SecurityFilter extends OncePerRequestFilter {

    @Autowired
    private TokenService tokenService;

    @Autowired
    private UsuarioRepository repository;

    //Garante que o filtro seja executado apenas uma vez
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        var tokenJWT = recuperarToken(request);

       if (tokenJWT != null) {
           var subject = tokenService.getSubject(tokenJWT);
           var usuario = repository.findByLogin(subject);

           var authentication = new UsernamePasswordAuthenticationToken(usuario, null, usuario.getAuthorities());
           SecurityContextHolder.getContext().setAuthentication(authentication);

       }

       filterChain.doFilter(request, response);
    }

    private String recuperarToken(HttpServletRequest request) {
        var authorizationHeader = request.getHeader( "Authorization" );

        if (authorizationHeader != null) {
            //Aqui tinha um espaço em branco no segundo parametro do metodo replace (deve ser uma string vazia mesmo, sem espacos):
            return authorizationHeader.replace("Bearer ", "").trim();
        }
        return null;
    }
}

