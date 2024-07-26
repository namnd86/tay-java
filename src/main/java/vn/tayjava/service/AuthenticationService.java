package vn.tayjava.service;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import vn.tayjava.dto.request.SignInRequest;
import vn.tayjava.dto.response.TokenResponse;
import vn.tayjava.exception.InvalidDataException;
import vn.tayjava.repository.UserRepository;

import java.util.List;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static vn.tayjava.util.TokenType.REFRESH_TOKEN;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JwtService jwtService;

    public TokenResponse authenticate(SignInRequest signInRequest) {
        log.info("---------- authenticate ----------");

        var user = userRepository.findByUsername(signInRequest.getUsername()).orElseThrow(() -> new UsernameNotFoundException("Username or Password is incorrect"));

        List<String> roles = userRepository.findAllRolesByUserId(user.getId());
        List<SimpleGrantedAuthority> authorities = roles.stream().map(SimpleGrantedAuthority::new).toList();

        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(signInRequest.getUsername(), signInRequest.getPassword(), authorities));

        String accessToken = jwtService.generateToken(user);

        String refreshToken = jwtService.generateRefreshToken(user);

        return TokenResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .userId(user.getId())
                .build();
    }

    /**
     * Refresh token
     * @param servletRequest
     * @return
     */
    public TokenResponse refreshToken(HttpServletRequest servletRequest) {
        log.info("---------- authenticate ----------");

        final String refreshToken = servletRequest.getHeader(AUTHORIZATION);
        //log.info("Authorization: {}", authorization);

        if (StringUtils.isBlank(refreshToken)) {
            throw new InvalidDataException("Refresh token invalid");
        }

        final String userName = jwtService.extractUsername(refreshToken, REFRESH_TOKEN);

//        if (StringUtils.isNotEmpty(userName) && SecurityContextHolder.getContext().getAuthentication() == null) {
//            UserDetails userDetails = (UserDetails) userRepository.findByUsername(userName);
//            if (jwtService.isValid(token, ACCESS_TOKEN, userDetails)) {
//                SecurityContext context = SecurityContextHolder.createEmptyContext();
//                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
//                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//                context.setAuthentication(authentication);
//                SecurityContextHolder.setContext(context);
//            }
//        }
//
//        String refreshToken = "";

        return TokenResponse.builder()
                .accessToken("accessToken")
                .refreshToken(refreshToken)
                .userId(1l)
                .build();
    }
}
